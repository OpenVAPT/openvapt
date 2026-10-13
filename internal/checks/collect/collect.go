// Package collect holds read-only helpers shared by many checks: parsing the
// SSH daemon config, reading kernel parameters, listing listening sockets and
// discovering the websites (virtual hosts) this machine serves.
package collect

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/openvapt/openvapt/internal/sys"
)

// ---------- SSH daemon ----------

// SSHD returns the effective sshd settings with lower-case keys.
// It prefers "sshd -T" (the daemon's own view, including defaults and
// Include files) and falls back to parsing the config files directly.
func SSHD(ctx context.Context, s sys.System) (map[string]string, bool) {
	if out, err := s.Run(ctx, "sshd", "-T"); err == nil && strings.Contains(out, "permitrootlogin") {
		return parseKV(out), true
	}
	cfg := map[string]string{}
	files := []string{"/etc/ssh/sshd_config"}
	if more, _ := s.Glob("/etc/ssh/sshd_config.d/*.conf"); len(more) > 0 {
		sort.Strings(more)
		files = append(more, files...) // drop-ins are read first; first value wins
	}
	found := false
	for _, f := range files {
		b, err := s.ReadFile(f)
		if err != nil {
			continue
		}
		found = true
		for k, v := range parseKV(string(b)) {
			if _, set := cfg[k]; !set {
				cfg[k] = v
			}
		}
	}
	return cfg, found
}

func parseKV(text string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "match ") {
			break // settings after Match apply only to some users; ignore them
		}
		f := strings.Fields(strings.Replace(line, "=", " ", 1))
		if len(f) < 2 {
			continue
		}
		k := strings.ToLower(f[0])
		if _, ok := m[k]; !ok {
			m[k] = strings.ToLower(strings.Join(f[1:], " "))
		}
	}
	return m
}

// ---------- Kernel parameters ----------

// Sysctl reads a kernel parameter such as "kernel.randomize_va_space"
// from /proc/sys without running any command.
func Sysctl(s sys.System, key string) (string, error) {
	b, err := s.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ---------- Listening sockets ----------

// Listener is one listening TCP socket or bound UDP socket.
type Listener struct {
	Proto string // tcp, tcp6, udp, udp6
	IP    net.IP
	Port  int
}

// Public reports whether the socket accepts connections from other machines.
func (l Listener) Public() bool { return !l.IP.IsLoopback() }

func (l Listener) String() string {
	return fmt.Sprintf("%s %s", l.Proto, net.JoinHostPort(l.IP.String(), strconv.Itoa(l.Port)))
}

// Listeners parses /proc/net/{tcp,tcp6,udp,udp6}. TCP sockets in state 0A
// (LISTEN) and UDP sockets in state 07 (unconnected, bound) are returned.
func Listeners(s sys.System) ([]Listener, error) {
	var out []Listener
	var lastErr error
	ok := false
	for _, p := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp6", "0A"},
		{"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp6", "07"},
	} {
		b, err := s.ReadFile(p.file)
		if err != nil {
			lastErr = err
			continue
		}
		ok = true
		lines := strings.Split(string(b), "\n")
		for _, line := range lines[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != p.state {
				continue
			}
			ip, port, err := parseProcAddr(f[1])
			if err != nil {
				continue
			}
			out = append(out, Listener{Proto: p.proto, IP: ip, Port: port})
		}
	}
	if !ok {
		return nil, lastErr
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return dedupe(out), nil
}

// parseProcAddr decodes "0100007F:0050" (little-endian hex IP : hex port).
func parseProcAddr(s string) (net.IP, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, fmt.Errorf("bad ip %q", parts[0])
	}
	// The kernel prints each 32-bit word in host (little-endian) order.
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return nil, 0, err
	}
	return ip, int(port), nil
}

func dedupe(in []Listener) []Listener {
	seen := map[string]bool{}
	var out []Listener
	for _, l := range in {
		if k := l.String(); !seen[k] {
			seen[k] = true
			out = append(out, l)
		}
	}
	return out
}

// ListensOn reports whether any socket listens on the given TCP port.
func ListensOn(ls []Listener, port int) bool {
	for _, l := range ls {
		if l.Port == port && strings.HasPrefix(l.Proto, "tcp") {
			return true
		}
	}
	return false
}

// ---------- Websites (virtual hosts) ----------

var vhostPatterns = []string{
	"/etc/apache2/sites-enabled/*", "/etc/httpd/conf.d/*.conf", "/etc/httpd/conf/httpd.conf",
	"/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf", "/etc/nginx/nginx.conf",
	"/usr/local/lsws/conf/vhosts/*/vhconf.conf",
}

var (
	vhostOnce sync.Map // per System, cached for the duration of one scan
)

// VHosts returns the host names configured in Apache, nginx or LiteSpeed on
// this machine. Only these names are ever requested, and always through
// 127.0.0.1, so the scan never leaves the machine.
func VHosts(s sys.System) []string {
	if v, ok := vhostOnce.Load(s); ok {
		return v.([]string)
	}
	set := map[string]bool{}
	for _, pat := range vhostPatterns {
		files, _ := s.Glob(pat)
		for _, f := range files {
			b, err := s.ReadFile(f)
			if err != nil {
				continue
			}
			for _, name := range parseVHostNames(string(b)) {
				set[name] = true
			}
		}
	}
	var out []string
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) > 50 {
		out = out[:50] // keep scans bounded on large shared hosts
	}
	vhostOnce.Store(s, out)
	return out
}

func parseVHostNames(conf string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(f) < 2 {
			continue
		}
		key := strings.ToLower(f[0])
		if key != "servername" && key != "serveralias" && key != "server_name" && key != "vhdomain" {
			continue
		}
		for _, n := range f[1:] {
			n = strings.ToLower(strings.Trim(strings.TrimSuffix(n, ";"), `"',`))
			if i := strings.Index(n, ":"); i > 0 {
				n = n[:i]
			}
			if validHost(n) {
				out = append(out, n)
			}
		}
	}
	return out
}

func validHost(n string) bool {
	if n == "" || n == "_" || n == "localhost" || strings.ContainsAny(n, "*~$^()[]{}\\/ ") {
		return false
	}
	return strings.Contains(n, ".")
}

// ---------- OS ----------

// OSRelease parses /etc/os-release into a map (ID, VERSION_ID, PRETTY_NAME...).
func OSRelease(s sys.System) map[string]string {
	m := map[string]string{}
	b, err := s.ReadFile("/etc/os-release")
	if err != nil {
		b, err = s.ReadFile("/usr/lib/os-release")
		if err != nil {
			return m
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return m
}

// ServiceActive reports whether any of the named systemd units is active.
func ServiceActive(ctx context.Context, s sys.System, units ...string) (string, bool) {
	for _, u := range units {
		out, err := s.Run(ctx, "systemctl", "is-active", u)
		if err == nil && strings.TrimSpace(out) == "active" {
			return u, true
		}
	}
	return "", false
}
