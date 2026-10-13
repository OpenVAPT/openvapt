package sys

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
)

// Recorder implements System for --dry-run. It performs nothing and prints
// every operation a scan would perform, so the user can review it first.
type Recorder struct {
	mu   sync.Mutex
	W    io.Writer
	seen map[string]bool
}

func (r *Recorder) log(kind, what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	line := fmt.Sprintf("%-6s %s", kind, what)
	if !r.seen[line] {
		r.seen[line] = true
		fmt.Fprintln(r.W, line)
	}
}

func (r *Recorder) ReadFile(p string) ([]byte, error) { r.log("read", p); return nil, fs.ErrNotExist }
func (r *Recorder) Stat(p string) (FileInfo, error) {
	r.log("stat", p)
	return FileInfo{}, fs.ErrNotExist
}
func (r *Recorder) Glob(p string) ([]string, error) { r.log("glob", p); return nil, nil }
func (r *Recorder) Walk(root string, n int) ([]FileInfo, error) {
	r.log("walk", fmt.Sprintf("%s (max %d files, metadata only)", root, n))
	return nil, nil
}
func (r *Recorder) Run(_ context.Context, name string, args ...string) (string, error) {
	if !IsAllowed(name, args) {
		r.log("DENY", name+" "+strings.Join(args, " "))
		return "", ErrNotAllowed
	}
	r.log("run", name+" "+strings.Join(args, " "))
	return "", fs.ErrNotExist
}
func (r *Recorder) HTTP(_ context.Context, scheme, vhost, path string) (HTTPResponse, error) {
	r.log("http", fmt.Sprintf("GET %s://127.0.0.1%s (Host: %s)", scheme, path, vhost))
	return HTTPResponse{}, fs.ErrNotExist
}
func (r *Recorder) TLS(_ context.Context, port, sni string, minV, maxV uint16) (TLSInfo, error) {
	r.log("tls", fmt.Sprintf("handshake 127.0.0.1:%s (SNI %s, versions %#x-%#x)", port, sni, minV, maxV))
	return TLSInfo{}, fs.ErrNotExist
}
