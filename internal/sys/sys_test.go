package sys

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAllowList(t *testing.T) {
	ok := [][]string{{"sshd", "-T"}, {"apt-get", "-s", "upgrade"}, {"php", "-r", "echo ini_get('expose_php');"}}
	bad := [][]string{
		{"rm", "-rf", "/"}, {"apt-get", "upgrade"}, {"apt-get", "install", "x"},
		{"systemctl", "restart", "sshd"}, {"php", "-r", "system('id');"},
		{"php", "-r", "echo ini_get('x'); system('id');"}, {"sh", "-c", "id"},
		{"php", "-r", "echo ini_get('x').file_get_contents('/etc/shadow');"},
		{"apt-get", "-s", "upgrade", "-o", "APT::Update::Pre-Invoke::=id"}, {"iptables", "-S", "--wait"},
		{"ip6tables", "-S", "--wait"}, {"nft", "list", "ruleset", "extra"},
		{"systemctl", "is-active", "--all"}, {"systemctl", "is-active", "../bad"}, {"sshd", "-T", "-C", "user=root,host=x,addr=203.0.113.1"},
	}
	for _, c := range ok {
		if !IsAllowed(c[0], c[1:]) {
			t.Errorf("%v should be allowed", c)
		}
	}
	for _, c := range bad {
		if IsAllowed(c[0], c[1:]) {
			t.Errorf("%v must NOT be allowed", c)
		}
	}
}

func TestReadAndWalkReportIncomplete(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "large")
	if err := os.WriteFile(p, make([]byte, (4<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLive()
	r, err := l.ReadFile(context.Background(), p)
	if err != nil || r.Complete || len(r.Data) != 4<<20 {
		t.Fatalf("read: len=%d complete=%v err=%v", len(r.Data), r.Complete, err)
	}
	if err := os.WriteFile(filepath.Join(d, "second"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := l.Walk(context.Background(), d, 1)
	if err != nil || w.Complete || len(w.Files) != 1 {
		t.Fatalf("walk: %+v %v", w, err)
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Walk(c, d, 10); err == nil {
		t.Fatal("cancelled walk succeeded")
	}
}
