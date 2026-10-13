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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	Version            uint16
	Cipher             uint16
	NotAfter           time.Time
	Subject            string
	DNSNames           []string
	SelfSigned         bool
	Trusted            bool
	TrustError         string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	SignatureAlgorithm string
}

type ReadResult struct {
	Data     []byte
	Complete bool
}
type WalkResult struct {
	Files    []FileInfo
	Complete bool
}

// System is the complete set of operations a check may perform.
type System interface {
	ReadFile(ctx context.Context, path string) (ReadResult, error)
	Stat(path string) (FileInfo, error)
	Glob(pattern string) ([]string, error)
	// Walk lists regular files under root, at most maxFiles entries,
	// without following symlinks.
	Walk(ctx context.Context, root string, maxFiles int) (WalkResult, error)
	// Run executes one allow-listed, read-only command.
	Run(ctx context.Context, name string, args ...string) (string, error)
	// HTTP fetches path from a vhost served by this machine, connecting to
	// 127.0.0.1 and sending vhost as the Host header (SNI for https).
	HTTP(ctx context.Context, scheme, vhost, path string) (HTTPResponse, error)
	// TLS performs a handshake with 127.0.0.1:port using serverName as SNI,
	// limited to the given protocol version range.
	TLS(ctx context.Context, port, serverName string, minV, maxV uint16) (TLSInfo, error)
	TLSWithCiphers(ctx context.Context, port, serverName string, cipherSuites []uint16) (TLSInfo, error)
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
	{"ufw", "status", "verbose"},
	{"firewall-cmd", "--state"},
	{"firewall-cmd", "--get-active-zones"},
	{"systemctl", "is-active"},
	{"systemctl", "is-enabled"},
	{"php", "-r"}, // only used with ini_get() expressions
	{"php", "-v"},
	{"uname", "-r"},
	{"node", "--version"}, // print the Node.js version only
	{"nodejs", "--version"},
	{"rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"},
}

// IsAllowed reports whether a command line matches the allow-list.
func IsAllowed(name string, args []string) bool {
	full := append([]string{name}, args...)
	if name == "php" && len(args) == 2 && args[0] == "-r" {
		return safePHP(args[1])
	}
	// sshd -T -C evaluates the configuration for a hypothetical connection; no
	// connection is made. 192.0.2.1 is a reserved documentation address
	// (RFC 5737) used only to evaluate Match rules for non-local clients.
	if name == "sshd" && len(args) == 3 && args[0] == "-T" && args[1] == "-C" {
		// The context must be the fixed shape checked by ValidSSHDContext;
		// callers build it only from validated Match values.
		return ValidSSHDContext(args[2])
	}
	if name == "systemctl" && len(args) == 2 && (args[0] == "is-active" || args[0] == "is-enabled") {
		return validUnit(args[1])
	}
	for _, a := range allowed {
		if len(full) != len(a) {
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

var sshdUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidSSHDContext reports whether c is a connection context that sshd -T -C
// may evaluate: exactly "user=<u>,host=localhost,addr=<a>", where u is a
// plain POSIX-style user name and a is an IPv4 or IPv6 literal in canonical
// form (no CIDR, zone or port). The value is passed to sshd as one argument
// with no shell, and sshd only evaluates the configuration; nothing connects.
func ValidSSHDContext(c string) bool {
	parts := strings.Split(c, ",")
	if len(parts) != 3 {
		return false
	}
	u, ok1 := strings.CutPrefix(parts[0], "user=")
	h, ok2 := strings.CutPrefix(parts[1], "host=")
	a, ok3 := strings.CutPrefix(parts[2], "addr=")
	if !ok1 || !ok2 || !ok3 || h != "localhost" || !sshdUserRe.MatchString(u) {
		return false
	}
	ip := net.ParseIP(a)
	return ip != nil && ip.String() == a
}

func validUnit(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsAny(s, "/ \t\r\n") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '@' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// safePHP permits only expressions built from echo and ini_get, so the
// php -r entry can never be used to run arbitrary code.
var safePHPRe = regexp.MustCompile(`^(echo ini_get\('[A-Za-z0-9_.]+'\)(,"\\n")?;)+$`)

func safePHP(expr string) bool { return safePHPRe.MatchString(expr) }

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
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- certificates are inspected and reported, never trusted; loopback only
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

// ErrNotRegular is returned when a path is not a regular file (a FIFO,
// device, socket or directory), or is a symlink where none is allowed.
var ErrNotRegular = errors.New("refused: not a regular file")

const maxRead = 4 << 20

// ReadFile reads a system path. Symlinks are followed, because legitimate
// configuration often lives behind them (for example
// /etc/nginx/sites-enabled), but only a regular file is ever read and the
// open never blocks.
func (l *Live) ReadFile(ctx context.Context, path string) (ReadResult, error) {
	return readRegular(ctx, path, false)
}

// ReadFileNoFollow reads path only if it is a regular file and the final
// component is not a symlink. Use it for files found under web document
// roots, which a web user could replace with a link to /etc/shadow.
func (l *Live) ReadFileNoFollow(ctx context.Context, path string) (ReadResult, error) {
	return readRegular(ctx, path, true)
}

// NoFollowReader is implemented by systems that can refuse symlinks.
type NoFollowReader interface {
	ReadFileNoFollow(ctx context.Context, path string) (ReadResult, error)
}

// ReadFileNoFollow reads path through s without following a final symlink
// when s supports it. Fakes and the dry-run recorder fall back to ReadFile.
func ReadFileNoFollow(ctx context.Context, s System, path string) (ReadResult, error) {
	if n, ok := s.(NoFollowReader); ok {
		return n.ReadFileNoFollow(ctx, path)
	}
	return s.ReadFile(ctx, path)
}

func readRegular(ctx context.Context, path string, noFollow bool) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, err
	}
	f, err := openRead(path, noFollow)
	if err != nil {
		return ReadResult{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ReadResult{}, err
	}
	if !st.Mode().IsRegular() {
		return ReadResult{}, ErrNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRead+1))
	if err != nil {
		return ReadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ReadResult{}, err
	}
	complete := len(b) <= maxRead
	if !complete {
		b = b[:maxRead]
	}
	return ReadResult{Data: b, Complete: complete}, nil
}

func (l *Live) Stat(path string) (FileInfo, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return FileInfo{}, err
	}
	return toInfo(path, st), nil
}

func (l *Live) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

func (l *Live) Walk(ctx context.Context, root string, maxFiles int) (WalkResult, error) {
	var out []FileInfo
	complete := true
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if err != nil {
			complete = false
			return nil
		}
		if d.IsDir() && isPseudoFS(p) {
			return filepath.SkipDir
		}
		if d.Type()&fs.ModeSymlink != 0 || d.IsDir() {
			return nil
		}
		if st, e := d.Info(); e == nil {
			out = append(out, toInfo(p, st))
		} else {
			complete = false
		}
		if len(out) >= maxFiles {
			complete = false
			return filepath.SkipAll
		}
		return nil
	})
	return WalkResult{Files: out, Complete: complete}, err
}

func isPseudoFS(p string) bool {
	for _, x := range []string{"/proc", "/sys", "/dev", "/run", "/snap"} {
		if p == x {
			return true
		}
	}
	return false
}

// commandDirs are the only directories an allow-listed command may be
// started from. exec.Command would otherwise resolve the name through the
// caller's PATH, where a writable directory ahead of /usr/bin could plant a
// fake sshd or iptables (S-01).
var commandDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// ErrNotFound is returned when an allow-listed command is not installed in
// any of the fixed system directories.
var ErrNotFound = errors.New("command not found in /usr/sbin, /usr/bin, /sbin or /bin")

// maxCommandOutput bounds what one command may print into memory (S-03).
const maxCommandOutput = 8 << 20

// resolveCommand returns the absolute path of name inside commandDirs, or
// ErrNotFound. Names with a path separator are refused outright.
func resolveCommand(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return "", ErrNotAllowed
	}
	for _, d := range commandDirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", ErrNotFound
}

// Run executes one allow-listed, read-only command from a fixed system
// directory, with a 60 second limit, a bounded output buffer and a grace
// period after the kill so a grandchild holding the pipe cannot stall the
// scan.
func (l *Live) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !IsAllowed(name, args) {
		return "", ErrNotAllowed
	}
	path, err := resolveCommand(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.WaitDelay = 5 * time.Second
	var out boundedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if out.truncated && err == nil {
		err = errors.New("command output exceeded the 8 MiB limit and was truncated")
	}
	return out.String(), err
}

// boundedBuffer keeps at most maxCommandOutput bytes and drops the rest.
type boundedBuffer struct {
	b         []byte
	truncated bool
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	room := maxCommandOutput - len(w.b)
	if room <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		w.truncated = true
		p = p[:room]
	}
	w.b = append(w.b, p...)
	return len(p), nil
}
func (w *boundedBuffer) String() string { return string(w.b) }

// ErrTooLarge is returned by ReadLocalFile for a file over its limit.
var ErrTooLarge = errors.New("file is larger than the permitted size")

// ReadLocalFile reads a file the operator named on the command line (a
// report to verify, diff or use as a baseline): the open never blocks, only
// a regular file is read, and at most max bytes are accepted (S-02).
func ReadLocalFile(path string, max int64) ([]byte, error) {
	f, err := openRead(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
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
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: vhost} // #nosec G402 -- inspecting the local site, including broken certificates, is the purpose
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
	return l.tls(ctx, port, serverName, minV, maxV, nil)
}

func (l *Live) TLSWithCiphers(ctx context.Context, port, serverName string, cipherSuites []uint16) (TLSInfo, error) {
	return l.tls(ctx, port, serverName, tls.VersionTLS12, tls.VersionTLS12, cipherSuites)
}

func (l *Live) tls(ctx context.Context, port, serverName string, minV, maxV uint16, cipherSuites []uint16) (TLSInfo, error) {
	d := scope.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", "127.0.0.1:"+port)
	if err != nil {
		return TLSInfo{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV, CipherSuites: cipherSuites} // #nosec G402 -- deliberately probes weak or invalid TLS on 127.0.0.1
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
		info.PublicKeyAlgorithm = c.PublicKeyAlgorithm.String()
		info.SignatureAlgorithm = c.SignatureAlgorithm.String()
		switch k := c.PublicKey.(type) {
		case *rsa.PublicKey:
			info.PublicKeyBits = k.N.BitLen()
		case *ecdsa.PublicKey:
			info.PublicKeyBits = k.Curve.Params().BitSize
		}
		info.DNSNames = c.DNSNames
		info.SelfSigned = c.Issuer.String() == c.Subject.String()
		roots, rootErr := x509.SystemCertPool()
		if rootErr == nil {
			intermediates := x509.NewCertPool()
			for _, cert := range st.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, verifyErr := c.Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates})
			info.Trusted = verifyErr == nil
			if verifyErr != nil {
				info.TrustError = verifyErr.Error()
			}
		} else {
			info.TrustError = rootErr.Error()
		}
	}
	return info, nil
}
