// Package sys is the only way checks touch the machine.
//
// Checks never call os, exec or net directly. They receive a System, which
// exposes a small, read-only set of operations. This gives three guarantees:
//
//  1. Read-only: there is no write, delete or restart operation to call.
//  2. Local-only: HTTP and TLS go through scope.Dialer (loopback only).
//  3. Auditable: --dry-run swaps in a Recorder that prints every operation
//     instead of performing it, and tests swap in a Fake.
package sys

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/scope"
)

// FileInfo is the subset of file metadata checks need.
type FileInfo struct {
	Path  string
	Mode  fs.FileMode
	UID   int
	GID   int
	Size  int64
	IsDir bool
}

// HTTPResponse is a trimmed HTTP response. Bodies are capped at 64 KiB.
type HTTPResponse struct {
	Status  int
	Header  http.Header
	Body    string
	Cookies []*http.Cookie
}

// TLSInfo describes the result of one TLS handshake.
type TLSInfo struct {
	Version    uint16
	Cipher     uint16
	NotAfter   time.Time
	Subject    string
	DNSNames   []string
	SelfSigned bool
}

// System is the complete set of operations a check may perform.
type System interface {
	ReadFile(path string) ([]byte, error)
	Stat(path string) (FileInfo, error)
	Glob(pattern string) ([]string, error)
	// Walk lists regular files under root, at most maxFiles entries,
	// without following symlinks.
	Walk(root string, maxFiles int) ([]FileInfo, error)
	// Run executes one allow-listed, read-only command.
	Run(ctx context.Context, name string, args ...string) (string, error)
	// HTTP fetches path from a vhost served by this machine, connecting to
	// 127.0.0.1 and sending vhost as the Host header (SNI for https).
	HTTP(ctx context.Context, scheme, vhost, path string) (HTTPResponse, error)
	// TLS performs a handshake with 127.0.0.1:port using serverName as SNI,
	// limited to the given protocol version range.
	TLS(ctx context.Context, port, serverName string, minV, maxV uint16) (TLSInfo, error)
}

// ErrNotAllowed is returned for a command that is not on the allow-list.
var ErrNotAllowed = errors.New("command not on the read-only allow-list")

// allowed lists every external command OpenVAPT may run, with the exact
// argument prefix. All of them only read state.
var allowed = [][]string{
	{"sshd", "-T"},               // print effective sshd config
	{"apt-get", "-s", "upgrade"}, // simulate upgrade, changes nothing
	{"apt-get", "-s", "dist-upgrade"},
	{"dnf", "-q", "updateinfo", "list", "--security"},
	{"yum", "-q", "updateinfo", "list", "security"},
	{"nft", "list", "ruleset"},
	{"iptables", "-S"},
	{"ip6tables", "-S"},
	{"ufw", "status"},
	{"firewall-cmd", "--state"},
	{"systemctl", "is-active"},
	{"systemctl", "is-enabled"},
	{"php", "-r"}, // only used with ini_get() expressions
	{"php", "-v"},
	{"uname", "-r"},
}

// IsAllowed reports whether a command line matches the allow-list.
func IsAllowed(name string, args []string) bool {
	full := append([]string{name}, args...)
	for _, a := range allowed {
		if len(full) < len(a) {
			continue
		}
		match := true
		for i := range a {
			if full[i] != a[i] {
				match = false
				break
			}
		}
		if match {
			if name == "php" && len(args) > 1 && args[0] == "-r" && !safePHP(args[1]) {
				return false
			}
			return true
		}
	}
	return false
}

// safePHP permits only expressions built from echo and ini_get, so the
// php -r entry can never be used to run arbitrary code.
func safePHP(expr string) bool {
	for _, part := range strings.Split(expr, ";") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "echo ini_get('") {
			return false
		}
	}
	return !strings.ContainsAny(expr, "`$")
}

// Live is the real implementation used by "openvapt scan".
type Live struct {
	client *http.Client
}

// NewLive builds a Live system whose network access is confined to loopback.
func NewLive() *Live {
	d := scope.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext:       d.DialContext,
		Proxy:             nil,                                   // never use a proxy: it would leave the machine
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // we inspect, not trust
		DisableKeepAlives: true,
	}
	return &Live{client: &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // report redirects, never follow them
		},
	}}
}

func (l *Live) ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 4<<20))
}

func (l *Live) Stat(path string) (FileInfo, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return FileInfo{}, err
	}
	return toInfo(path, st), nil
}

func (l *Live) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

func (l *Live) Walk(root string, maxFiles int) ([]FileInfo, error) {
	var out []FileInfo
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if d.IsDir() && isPseudoFS(p) {
			return filepath.SkipDir
		}
		if d.Type()&fs.ModeSymlink != 0 || d.IsDir() {
			return nil
		}
		if st, e := d.Info(); e == nil {
			out = append(out, toInfo(p, st))
		}
		if len(out) >= maxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	return out, err
}

func isPseudoFS(p string) bool {
	for _, x := range []string{"/proc", "/sys", "/dev", "/run", "/snap"} {
		if p == x {
			return true
		}
	}
	return false
}

func (l *Live) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !IsAllowed(name, args) {
		return "", ErrNotAllowed
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (l *Live) HTTP(ctx context.Context, scheme, vhost, path string) (HTTPResponse, error) {
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://127.0.0.1:"+port+path, nil)
	if err != nil {
		return HTTPResponse{}, err
	}
	req.Host = vhost
	req.Header.Set("User-Agent", "OpenVAPT local self-assessment")
	tr := l.client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: vhost} //nolint:gosec
	c := *l.client
	c.Transport = tr
	resp, err := c.Do(req)
	if err != nil {
		return HTTPResponse{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return HTTPResponse{Status: resp.StatusCode, Header: resp.Header, Body: string(b), Cookies: resp.Cookies()}, nil
}

func (l *Live) TLS(ctx context.Context, port, serverName string, minV, maxV uint16) (TLSInfo, error) {
	d := scope.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", "127.0.0.1:"+port)
	if err != nil {
		return TLSInfo{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV} //nolint:gosec
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return TLSInfo{}, err
	}
	st := conn.ConnectionState()
	info := TLSInfo{Version: st.Version, Cipher: st.CipherSuite}
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		info.NotAfter = c.NotAfter
		info.Subject = c.Subject.CommonName
		info.DNSNames = c.DNSNames
		info.SelfSigned = c.Issuer.String() == c.Subject.String()
	}
	return info, nil
}
