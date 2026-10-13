package sys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// S-01: commands come only from the fixed system directories.
func TestResolveCommandUsesFixedDirectories(t *testing.T) {
	for _, bad := range []string{"", "./sshd", "/tmp/sshd", "..", "a/b", "no-such-command-openvapt"} {
		if p, err := resolveCommand(bad); err == nil {
			t.Errorf("%q resolved to %s", bad, p)
		}
	}
	// A planted binary earlier in PATH is ignored: resolution never reads PATH.
	dir := t.TempDir()
	fake := filepath.Join(dir, "planted-openvapt-test")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho planted\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := resolveCommand("planted-openvapt-test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("planted binary must not resolve, got %v", err)
	}
	if p, err := resolveCommand("ls"); err != nil || !strings.HasPrefix(p, "/") || strings.Contains(p, dir) {
		t.Errorf("ls should resolve inside a system directory, got %s %v", p, err)
	}
}

// S-03: command output is bounded.
func TestBoundedBuffer(t *testing.T) {
	var b boundedBuffer
	chunk := make([]byte, 1<<20)
	for i := 0; i < 10; i++ {
		if n, err := b.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("write %d: %d %v", i, n, err)
		}
	}
	if len(b.b) != maxCommandOutput || !b.truncated {
		t.Errorf("got %d bytes, truncated %v", len(b.b), b.truncated)
	}
}

// S-02: operator-named files are read bounded and only when regular.
func TestReadLocalFileGuards(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.json")
	if err := os.WriteFile(small, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadLocalFile(small, 1<<20); err != nil || string(b) != `{"a":1}` {
		t.Errorf("small: %q %v", b, err)
	}
	if _, err := ReadLocalFile(small, 3); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize: want ErrTooLarge, got %v", err)
	}
	if _, err := ReadLocalFile(dir, 1<<20); !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory: want ErrNotRegular, got %v", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	if _, err := ReadLocalFile(fifo, 1<<20); !errors.Is(err, ErrNotRegular) {
		t.Errorf("fifo: want ErrNotRegular (and no hang), got %v", err)
	}
}
