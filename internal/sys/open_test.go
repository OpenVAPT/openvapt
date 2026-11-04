//go:build unix

package sys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadRefusesFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo unsupported:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := NewLive().ReadFile(context.Background(), p); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("FIFO must be refused, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}

func TestReadNoFollowRefusesSymlinkButReadFileFollows(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "secret")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "wp-config.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	l := NewLive()
	if _, err := ReadFileNoFollow(context.Background(), l, link); err == nil {
		t.Fatal("no-follow read accepted a symlink")
	}
	if r, err := l.ReadFile(context.Background(), link); err != nil || string(r.Data) != "x" {
		t.Fatalf("system read should follow a symlink to a regular file: %v", err)
	}
	if _, err := l.ReadFile(context.Background(), d); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory must be refused, got %v", err)
	}
	f := &Fake{Files: map[string]string{"/a": "b"}}
	if r, err := ReadFileNoFollow(context.Background(), f, "/a"); err != nil || string(r.Data) != "b" {
		t.Fatal("fake fallback failed")
	}
}
