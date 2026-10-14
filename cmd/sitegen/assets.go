package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

var (
	assetMu    sync.Mutex
	assetCache = map[string]string{}
)

// assetVersioned returns "assets/<name>?v=<hash>", where hash is the first
// ten hex digits of the file's SHA-256, so a changed file gets a new URL.
func assetVersioned(name string) string {
	assetMu.Lock()
	defer assetMu.Unlock()
	if v, ok := assetCache[name]; ok {
		return v
	}
	b, err := os.ReadFile(filepath.Join("site", "static", "assets", filepath.Clean(name))) // #nosec G304 -- fixed build-time asset paths from templates
	must(err)
	sum := sha256.Sum256(b)
	v := "assets/" + name + "?v=" + hex.EncodeToString(sum[:])[:10]
	assetCache[name] = v
	return v
}

// vendorVersion hashes every vendored file, so upgrading a library changes
// the query string the loader scripts append to vendor URLs.
func vendorVersion() string {
	assetMu.Lock()
	defer assetMu.Unlock()
	if v, ok := assetCache["\x00vendor"]; ok {
		return v
	}
	root := filepath.Join("site", "static", "assets", "vendor")
	var files []string
	must(filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	}))
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- files found by walking the vendored asset folder
		must(err)
		h.Write([]byte(f))
		h.Write(b)
	}
	v := hex.EncodeToString(h.Sum(nil))[:10]
	assetCache["\x00vendor"] = v
	return v
}
