// Package collect holds read-only helpers shared by many checks: parsing the
// SSH daemon config, reading kernel parameters, listing listening sockets and
// discovering the websites (virtual hosts) this machine serves.
package collect

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"regexp"
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
	contexts := []string{"user=root,host=localhost,addr=127.0.0.1", "user=nobody,host=localhost,addr=127.0.0.1", "user=root,host=localhost,addr=192.0.2.1", "user=nobody,host=localhost,addr=192.0.2.1"}
	merged := map[string]string{}
	seen := false
	for _, c := range contexts {
		if out, err := s.Run(ctx, "sshd", "-T", "-C", c); err == nil && strings.Contains(strings.ToLower(out), "permitrootlogin") {
			seen = true
			mergeSSHD(merged, parseKV(out))
		}
	}
	if seen {
		addFileMatch(ctx, s, merged)
		addMatchContexts(ctx, s, merged, contexts)
		return merged, true
	}
	if out, err := s.Run(ctx, "sshd", "-T"); err == nil && strings.Contains(strings.ToLower(out), "permitrootlogin") {
		cfg := parseKV(out)
		addFileMatch(ctx, s, cfg)
		return cfg, true
	}
	cfg := map[string]string{}
	found := parseSSHFile(ctx, s, "/etc/ssh/sshd_config", cfg, map[string]bool{}, 0)
	if found {
		cfg[SSHDSourceKey] = SSHDSourceFile
	}
	return cfg, found
}

// SSHDSourceKey marks where the sshd settings came from. It is only set to
// SSHDSourceFile when sshd -T was unavailable (typically a non-root scan) and
// the config files were parsed instead, in which case defaults sshd would
// apply for unset keywords are not visible.
const (
	SSHDSourceKey  = "_source"
	SSHDSourceFile = "file"
)

var opensshVersionRe = regexp.MustCompile(`^(?:\d+:)?(\d+)\.(\d+)`)

// OpenSSHVersion reports the installed OpenSSH server version (major, minor)
// from the package inventory, for example 9.6 from "1:9.6p1-3ubuntu13".
func OpenSSHVersion(ctx context.Context, s sys.System) (major, minor int, raw string, ok bool) {
	items, _ := HostInventory(ctx, s)
	for _, p := range items {
		if p.Package != "openssh-server" {
			continue
		}
		m := opensshVersionRe.FindStringSubmatch(p.Version)
		if m == nil {
			return 0, 0, p.Version, false
		}
		major, _ = strconv.Atoi(m[1])
		minor, _ = strconv.Atoi(m[2])
		return major, minor, p.Version, true
	}
	return 0, 0, "", false
}

// addFileMatch copies the Match block settings ("match:" and "matchcond:"
// keys) from the config files into an sshd -T result. Match rules naming
// other users or networks are also evaluated by addMatchContexts, within the
// validated context shape the read-only allow-list permits.
func addFileMatch(ctx context.Context, s sys.System, dst map[string]string) {
	files := map[string]string{}
	parseSSHFile(ctx, s, "/etc/ssh/sshd_config", files, map[string]bool{}, 0)
	for k, v := range files {
		if strings.HasPrefix(k, "match:") || strings.HasPrefix(k, "matchcond:") {
			dst[k] = v
		}
	}
}

// maxMatchContexts caps the extra sshd -T -C evaluations built from Match
// lines, so a config with many Match blocks cannot cause many commands.
const maxMatchContexts = 8

// MatchContexts builds extra sshd -T -C connection contexts from the Match
// User, Group and Address lines of the config files. Every value is
// validated (sys.ValidSSHDContext) before use; patterns, negations and
// anything else are skipped. A Group is represented by its first listed
// member in /etc/group, read-only; a group with no listed member is skipped.
// The host is always "localhost". At most maxMatchContexts are returned and
// none of the skip list.
func MatchContexts(ctx context.Context, s sys.System, skip []string) []string {
	var conds []string
	cond := ""
	parseSSHFileM(ctx, s, "/etc/ssh/sshd_config", map[string]string{}, map[string]bool{}, 0, &cond, &conds)
	seen := map[string]bool{}
	for _, c := range skip {
		seen[c] = true
	}
	var groups map[string]string
	var out []string
	for _, c := range conds {
		f := strings.Fields(c)
		user, addr := "", ""
		for i := 0; i+1 < len(f); i += 2 {
			crit, vals := f[i], strings.Split(f[i+1], ",")
			for _, v := range vals {
				if v == "" || strings.ContainsAny(v, "*?!") {
					continue
				}
				switch crit {
				case "user":
					if user == "" && sshName(v) {
						user = v
					}
				case "group":
					if user == "" && sshName(v) {
						if groups == nil {
							groups = groupMembers(ctx, s)
						}
						if m := groups[v]; m != "" {
							user = m
						}
					}
				case "address":
					if addr == "" {
						addr = firstAddr(v)
					}
				}
			}
		}
		if user == "" && addr == "" {
			continue
		}
		if user == "" {
			user = "nobody"
		}
		if addr == "" {
			addr = "192.0.2.1"
		}
		cc := "user=" + user + ",host=localhost,addr=" + addr
		if seen[cc] || !sys.ValidSSHDContext(cc) {
			continue
		}
		seen[cc] = true
		out = append(out, cc)
		if len(out) == maxMatchContexts {
			break
		}
	}
	return out
}

func sshName(v string) bool {
	return sys.ValidSSHDContext("user=" + v + ",host=localhost,addr=127.0.0.1")
}

// firstAddr returns the canonical address of an IP literal, or the first
// (network) address of a CIDR, or "".
func firstAddr(v string) string {
	if strings.Contains(v, "/") {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return ""
		}
		return n.IP.String()
	}
	if ip := net.ParseIP(v); ip != nil {
		return ip.String()
	}
	return ""
}

// groupMembers maps each group in /etc/group to its first valid listed member.
func groupMembers(ctx context.Context, s sys.System) map[string]string {
	m := map[string]string{}
	r, err := s.ReadFile(ctx, "/etc/group")
	if err != nil || !r.Complete {
		return m
	}
	// A group's members are its listed members plus users whose primary
	// group it is (gid in /etc/passwd).
	primary := map[string]string{}
	if pw, err := s.ReadFile(ctx, "/etc/passwd"); err == nil && pw.Complete {
		for _, line := range strings.Split(string(pw.Data), "\n") {
			f := strings.Split(strings.TrimSpace(line), ":")
			if len(f) >= 4 && sshName(f[0]) {
				if _, ok := primary[f[3]]; !ok {
					primary[f[3]] = f[0]
				}
			}
		}
	}
	for _, line := range strings.Split(string(r.Data), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 {
			continue
		}
		for _, u := range strings.Split(f[3], ",") {
			if u = strings.TrimSpace(u); sshName(u) {
				m[f[0]] = u
				break
			}
		}
		if _, ok := m[f[0]]; !ok {
			if u, ok := primary[f[2]]; ok {
				m[f[0]] = u
			}
		}
	}
	return m
}

// addMatchContexts evaluates the extra Match contexts with sshd -T -C and
// records any risky value that the base contexts did not show as a
// conditional "match:" finding, with the context in "matchcond:".
func addMatchContexts(ctx context.Context, s sys.System, dst map[string]string, base []string) {
	for _, c := range MatchContexts(ctx, s, base) {
		out, err := s.Run(ctx, "sshd", "-T", "-C", c)
		if err != nil || !strings.Contains(strings.ToLower(out), "permitrootlogin") {
			continue
		}
		for k, v := range parseKV(out) {
			if !SSHDangerous(k, v) || SSHDangerous(k, dst[k]) {
				continue
			}
			mk := "match:" + k
			if old, ok := dst[mk]; ok && sshDanger(k, old) >= sshDanger(k, v) {
				continue
			}
			dst[mk] = v
			dst["matchcond:"+k] = "context " + c
		}
	}
}

// SSHDangerous reports whether an sshd setting value is the risky one for
// that keyword (for example PermitRootLogin yes, X11Forwarding yes).
func SSHDangerous(k, v string) bool {
	switch k {
	case "maxauthtries", "logingracetime":
		return false
	}
	return sshDanger(k, v) >= 10
}

func mergeSSHD(dst, src map[string]string) {
	for k, v := range src {
		old, ok := dst[k]
		if !ok || sshDanger(k, v) > sshDanger(k, old) {
			dst[k] = v
		}
	}
}

func sshDanger(k, v string) int {
	v = strings.ToLower(v)
	switch k {
	case "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "challengeresponseauthentication", "permitemptypasswords", "x11forwarding", "allowtcpforwarding", "allowagentforwarding", "permittunnel", "gatewayports":
		switch v {
		case "yes", "any", "all", "point-to-point", "ethernet", "clientspecified", "local", "remote":
			return 10
		}
	case "maxauthtries":
		n, _ := strconv.Atoi(v)
		return n
	case "logingracetime":
		n, _ := strconv.Atoi(strings.TrimSuffix(v, "s"))
		return n
	}
	return 0
}

// parseSSHFile applies sshd's first-value-wins rule to one config file and
// its Include files. Keywords may be written "Key value" or "Key=value".
// Settings after the first Match line apply only to some connections, so
// they never override global values; they are recorded under the key
// "match:<keyword>" (most dangerous value wins) for checks that want them,
// with the condition of that Match line under "matchcond:<keyword>".
func parseSSHFile(ctx context.Context, s sys.System, path string, cfg map[string]string, visiting map[string]bool, depth int) bool {
	cond := ""
	return parseSSHFileM(ctx, s, path, cfg, visiting, depth, &cond, nil)
}

func parseSSHFileM(ctx context.Context, s sys.System, path string, cfg map[string]string, visiting map[string]bool, depth int, cond *string, conds *[]string) bool {
	if depth > 16 || visiting[path] {
		return false
	}
	visiting[path] = true
	defer delete(visiting, path)
	r, err := s.ReadFile(ctx, path)
	if err != nil || !r.Complete {
		return false
	}
	complete := true
	for _, raw := range strings.Split(string(r.Data), "\n") {
		k, v, ok := sshKeyword(raw)
		if !ok {
			continue
		}
		switch k {
		case "match":
			if strings.EqualFold(v, "all") {
				*cond = ""
			} else {
				*cond = v
				if conds != nil {
					*conds = append(*conds, v)
				}
			}
			continue
		case "include":
			for _, pat := range strings.Fields(v) {
				if !strings.HasPrefix(pat, "/") {
					// sshd resolves relative Include paths against /etc/ssh.
					pat = "/etc/ssh/" + pat
				}
				files, _ := s.Glob(pat)
				sort.Strings(files)
				for _, inc := range files {
					if !parseSSHFileM(ctx, s, inc, cfg, visiting, depth+1, cond, conds) {
						complete = false
					}
				}
			}
			continue
		}
		if *cond != "" {
			mk := "match:" + k
			if old, seen := cfg[mk]; !seen || sshDanger(k, v) > sshDanger(k, old) {
				cfg[mk] = v
				cfg["matchcond:"+k] = *cond
			}
			continue
		}
		if _, seen := cfg[k]; !seen {
			cfg[k] = v
		}
	}
	return complete
}

// sshKeyword splits one sshd_config line into a lower-case keyword and a
// lower-case value, accepting both whitespace and "=" as the separator.
func sshKeyword(raw string) (string, string, bool) {
	line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
	if line == "" {
		return "", "", false
	}
	i := strings.IndexAny(line, " \t=")
	if i <= 0 {
		return "", "", false
	}
	k := strings.ToLower(line[:i])
	rest := strings.TrimSpace(line[i:])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	if rest == "" {
		return "", "", false
	}
	f := strings.Fields(rest)
	if k == "match" {
		// sshd compares Match user and group names case-sensitively, so only
		// the criterion keywords (User, Group, Address...) are lowercased.
		for i := 0; i < len(f); i += 2 {
			f[i] = strings.ToLower(f[i])
		}
		return k, strings.Join(f, " "), true
	}
	return k, strings.ToLower(strings.Join(f, " ")), true
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
	r, err := s.ReadFile(context.Background(), "/proc/sys/"+strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return "", err
	}
	if !r.Complete {
		return "", fmt.Errorf("sysctl input was truncated")
	}
	return strings.TrimSpace(string(r.Data)), nil
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
	complete := true
	for _, p := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp6", "0A"},
		{"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp6", "07"},
	} {
		r, err := s.ReadFile(context.Background(), p.file)
		if err != nil && strings.HasSuffix(p.file, "6") && errors.Is(err, fs.ErrNotExist) {
			// A kernel built or booted without IPv6 has no tcp6/udp6 file:
			// that means no IPv6 sockets, not an unreadable input.
			continue
		}
		if err != nil {
			lastErr = err
			complete = false
			continue
		}
		ok = true
		if !r.Complete {
			return nil, fmt.Errorf("%s was truncated", p.file)
		}
		lines := strings.Split(string(r.Data), "\n")
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
	if !ok || !complete {
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

type WebTarget struct{ Name, Scheme string }

// VHosts returns the host names configured in Apache, nginx or LiteSpeed on
// this machine. Only these names are ever requested, and always through
// 127.0.0.1, so the scan never leaves the machine.
func VHosts(s sys.System) []string {
	if v, ok := vhostOnce.Load(s); ok {
		return v.([]string)
	}
	set := map[string]bool{}
	for _, target := range WebTargets(s) {
		set[target.Name] = true
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

func WebTargets(s sys.System) []WebTarget {
	var out []WebTarget
	seen := map[string]bool{}
	for _, pat := range vhostPatterns {
		files, _ := s.Glob(pat)
		for _, f := range files {
			collectWebTargets(s, f, &out, seen, map[string]bool{}, 0)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Scheme < out[j].Scheme
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func collectWebTargets(s sys.System, path string, out *[]WebTarget, seen, visiting map[string]bool, depth int) {
	if depth > 16 || visiting[path] || len(*out) >= 50 {
		return
	}
	visiting[path] = true
	defer delete(visiting, path)
	r, err := s.ReadFile(context.Background(), path)
	if err != nil || !r.Complete {
		return
	}
	text := string(r.Data)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		fields := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "include" || key == "includeoptional" {
			for _, p := range fields[1:] {
				if !safeConfigPattern(p) {
					continue
				}
				files, _ := s.Glob(strings.Trim(p, `"'`))
				sort.Strings(files)
				for _, f := range files {
					collectWebTargets(s, f, out, seen, visiting, depth+1)
				}
			}
			continue
		}
	}
	add := func(scheme, name string) {
		key := scheme + "://" + name
		if !seen[key] {
			seen[key] = true
			*out = append(*out, WebTarget{Name: name, Scheme: scheme})
		}
	}
	// Decide the scheme per <VirtualHost> or server {} block, so an http-only
	// name in a file that also holds an https block is not tagged https (a
	// fetch that then fails would hide the site). Names outside any block
	// (LiteSpeed vhdomain, bare includes) use the file-level heuristic.
	blocks, rest := vhostBlocks(text)
	for _, b := range blocks {
		for _, name := range parseVHostNames(b.text) {
			add(b.scheme, name)
		}
	}
	scheme := "http"
	lower := strings.ToLower(text)
	if strings.Contains(lower, "<virtualhost") && strings.Contains(lower, ":443") || strings.Contains(lower, "listen 443") || strings.Contains(lower, "ssl on") || strings.Contains(lower, "ssl_certificate") {
		scheme = "https"
	}
	for _, name := range parseVHostNames(rest) {
		add(scheme, name)
	}
}

type vhostBlock struct {
	scheme string
	text   string
}

// vhostBlocks splits a web server configuration into its Apache
// <VirtualHost> blocks and nginx server {} blocks, each with the scheme its
// own directives imply (a :443 or ssl listener, SSLEngine on, ssl on or an
// ssl_certificate), and returns the text outside every block.
func vhostBlocks(text string) ([]vhostBlock, string) {
	var blocks []vhostBlock
	var rest, cur strings.Builder
	depth := 0 // nginx brace depth inside a server block
	inApache, inNginx := false, false
	https := false
	flush := func() {
		scheme := "http"
		if https {
			scheme = "https"
		}
		blocks = append(blocks, vhostBlock{scheme: scheme, text: cur.String()})
		cur.Reset()
		https = false
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		lower := strings.ToLower(line)
		switch {
		case !inApache && !inNginx && strings.HasPrefix(lower, "<virtualhost"):
			inApache = true
			https = strings.Contains(lower, ":443")
			cur.WriteString(raw + "\n")
			continue
		case inApache:
			cur.WriteString(raw + "\n")
			if strings.HasPrefix(lower, "sslengine") && strings.Contains(lower, "on") {
				https = true
			}
			if strings.HasPrefix(lower, "</virtualhost") {
				inApache = false
				flush()
			}
			continue
		case !inApache && !inNginx && (lower == "server {" || lower == "server{" || strings.HasPrefix(lower, "server ") && strings.HasSuffix(lower, "{")):
			inNginx = true
			depth = 1
			cur.WriteString(raw + "\n")
			continue
		case inNginx:
			cur.WriteString(raw + "\n")
			if strings.HasPrefix(lower, "listen") && (strings.Contains(lower, "443") || strings.Contains(lower, " ssl")) || strings.HasPrefix(lower, "ssl on") || strings.HasPrefix(lower, "ssl_certificate ") {
				https = true
			}
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				inNginx = false
				flush()
			}
			continue
		}
		rest.WriteString(raw + "\n")
	}
	if cur.Len() > 0 { // unterminated block: judge what was seen
		flush()
	}
	return blocks, rest.String()
}

func safeConfigPattern(p string) bool {
	p = strings.Trim(p, `"'`)
	return strings.HasPrefix(p, "/etc/apache2/") || strings.HasPrefix(p, "/etc/httpd/") || strings.HasPrefix(p, "/etc/nginx/") || strings.HasPrefix(p, "/usr/local/lsws/conf/")
}

func parseVHostNames(conf string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
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
	r, err := s.ReadFile(context.Background(), "/etc/os-release")
	if err != nil {
		r, err = s.ReadFile(context.Background(), "/usr/lib/os-release")
		if err != nil {
			return m
		}
	}
	for _, line := range strings.Split(string(r.Data), "\n") {
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
