package sys

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
)

// Fake is an in-memory System used by unit tests. Each check is tested
// against a "vulnerable" fake and a "hardened" fake, proving it both fires
// and stays silent.
type Fake struct {
	Files           map[string]string
	Infos           map[string]FileInfo
	Commands        map[string]string       // "name arg1 arg2" -> output
	HTTPResp        map[string]HTTPResponse // "scheme://vhost/path"
	TLSResp         map[string]TLSInfo      // "port/sni/maxVersion"
	IncompleteFiles map[string]bool
	IncompleteWalks map[string]bool
}

func (f *Fake) ReadFile(ctx context.Context, p string) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, err
	}
	if s, ok := f.Files[p]; ok {
		return ReadResult{Data: []byte(s), Complete: !f.IncompleteFiles[p]}, nil
	}
	return ReadResult{}, fs.ErrNotExist
}
func (f *Fake) Stat(p string) (FileInfo, error) {
	if i, ok := f.Infos[p]; ok {
		return i, nil
	}
	if s, ok := f.Files[p]; ok {
		return FileInfo{Path: p, Mode: 0o644, Size: int64(len(s))}, nil
	}
	return FileInfo{}, fs.ErrNotExist
}
func (f *Fake) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range f.Files {
		if ok, _ := filepath.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, nil
}
func (f *Fake) Walk(ctx context.Context, root string, n int) (WalkResult, error) {
	var out []FileInfo
	for p, i := range f.Infos {
		if err := ctx.Err(); err != nil {
			return WalkResult{}, err
		}
		if strings.HasPrefix(p, root) && !i.IsDir {
			out = append(out, i)
		}
	}
	complete := !f.IncompleteWalks[root]
	if len(out) > n {
		out = out[:n]
		complete = false
	}
	return WalkResult{Files: out, Complete: complete}, nil
}
func (f *Fake) Run(_ context.Context, name string, args ...string) (string, error) {
	if !IsAllowed(name, args) {
		return "", ErrNotAllowed
	}
	if out, ok := f.Commands[strings.Join(append([]string{name}, args...), " ")]; ok {
		return out, nil
	}
	return "", fs.ErrNotExist
}
func (f *Fake) HTTP(_ context.Context, scheme, vhost, path string) (HTTPResponse, error) {
	if r, ok := f.HTTPResp[scheme+"://"+vhost+path]; ok {
		return r, nil
	}
	return HTTPResponse{}, fs.ErrNotExist
}
func (f *Fake) TLS(_ context.Context, port, sni string, minV, maxV uint16) (TLSInfo, error) {
	key := port + "/" + sni + "/" + versionKey(maxV)
	if r, ok := f.TLSResp[key]; ok {
		return r, nil
	}
	return TLSInfo{}, fs.ErrNotExist
}

func versionKey(v uint16) string {
	switch v {
	case 0x0301:
		return "1.0"
	case 0x0302:
		return "1.1"
	case 0x0303:
		return "1.2"
	default:
		return "1.3"
	}
}
