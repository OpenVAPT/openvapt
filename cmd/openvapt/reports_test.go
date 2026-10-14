package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanReportsDirIsPrivateDatedAndNeverReused(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 10, 14, 7, 46, 0, 0, time.FixedZone("X", 8*3600))
	ad, err := scanReportsDir(home, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ad.finish(nil)
	a := ad.Path
	if want := filepath.Join(home, "openvapt-reports", "20261013T234600Z"); a != want {
		t.Fatalf("folder %s, want %s (UTC timestamp)", a, want)
	}
	bd, err := scanReportsDir(home, now, nil)
	if err != nil || bd.Path != a+"-2" {
		t.Fatalf("second scan in the same second must get its own folder: %v", err)
	}
	defer bd.finish(nil)
	b := bd.Path
	for _, d := range []string{a, b, filepath.Dir(a)} {
		st, err := os.Stat(d)
		if err != nil || st.Mode().Perm() != 0o700 {
			t.Fatalf("%s must be 0700: %v %v", d, st.Mode().Perm(), err)
		}
	}
	if _, err := scanReportsDir("", now, nil); err == nil || !strings.Contains(err.Error(), "--out") {
		t.Fatalf("no home must ask for --out, got %v", err)
	}
	if _, err := scanReportsDir("relative", now, nil); err == nil {
		t.Fatal("a relative home must be refused")
	}
}

func TestScanReportsDirRefusesLinkedBase(t *testing.T) {
	home := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(home, "openvapt-reports")); err != nil {
		t.Skip(err)
	}
	if _, err := scanReportsDir(home, time.Now(), nil); err == nil {
		t.Fatal("a symlinked reports folder must be refused")
	}
}

func TestPrintReportsListsEveryFileAndOpenHint(t *testing.T) {
	var b bytes.Buffer
	printReports(&b, []string{"/r/report.html", "/r/report.json", "/r/report.sarif", "/r/report.md"})
	out := b.String()
	for _, want := range []string{"Reports", "/r/report.html", "/r/report.json", "/r/report.sarif", "/r/report.md", "xdg-open /r/report.html"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	b.Reset()
	printReports(&b, []string{"/r/report.json"})
	if strings.Contains(b.String(), "xdg-open") {
		t.Error("no open hint without an HTML report")
	}
}

func TestOpenReportOnlyInDesktopSessionAndNeverAsRoot(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	files := []string{"/r/report.html"}
	cases := []struct {
		env  map[string]string
		euid int
		want string
	}{
		{map[string]string{}, 1000, "no desktop session"},
		{map[string]string{"DISPLAY": ":0"}, 0, "not starting a web browser as root"},
	}
	for _, c := range cases {
		var b bytes.Buffer
		openReport(&b, files, env(c.env), c.euid)
		if !strings.Contains(b.String(), c.want) {
			t.Errorf("env %v euid %d: got %q, want %q", c.env, c.euid, b.String(), c.want)
		}
	}
	var b bytes.Buffer
	openReport(&b, []string{"/r/report.json"}, env(map[string]string{"DISPLAY": ":0"}), 1000)
	if !strings.Contains(b.String(), "no HTML report") {
		t.Errorf("got %q", b.String())
	}
	if !desktopSession(env(map[string]string{"WAYLAND_DISPLAY": "wayland-0"})) || desktopSession(env(nil)) {
		t.Error("desktopSession must follow DISPLAY or WAYLAND_DISPLAY")
	}
}

func TestOpenFlagIsKeptInSafeCommandLine(t *testing.T) {
	got := safeCommandLine([]string{"openvapt", "scan", "--open", "--out", "/home/x/r"})
	if got != "openvapt scan --open --out <value>" {
		t.Fatalf("got %q", got)
	}
}

func TestSudoOwnerTrustsUserDatabaseNotHome(t *testing.T) {
	old := lookupHome
	t.Cleanup(func() { lookupHome = old })
	lookupHome = func(uid string) (string, error) {
		if uid == "1000" {
			return "/home/alice", nil
		}
		return "", errors.New("no such user")
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	sudo := env(map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1001"})
	if o := sudoOwner(0, sudo, "/home/alice"); o == nil || o.uid != 1000 || o.gid != 1001 {
		t.Fatalf("sudo with the user's own home must hand over to 1000:1001, got %+v", o)
	}
	if o := sudoOwner(0, sudo, "/home/alice/sub"); o == nil {
		t.Fatal("a folder inside the user's home must be handed over")
	}
	for _, c := range []struct {
		euid int
		env  func(string) string
		home string
	}{
		{0, sudo, "/root"},        // sudo reset HOME: root keeps it
		{0, sudo, "/home/alicex"}, // a look-alike prefix is not inside
		{0, sudo, "/home/alice/../bob"},
		{1000, sudo, "/home/alice"}, // not root
		{0, env(map[string]string{}), "/home/alice"},
		{0, env(map[string]string{"SUDO_UID": "0", "SUDO_GID": "0"}), "/home/alice"},
		{0, env(map[string]string{"SUDO_UID": "2000", "SUDO_GID": "2000"}), "/home/alice"}, // unknown user
		{0, env(map[string]string{"SUDO_UID": "x", "SUDO_GID": "1"}), "/home/alice"},
	} {
		if o := sudoOwner(c.euid, c.env, c.home); o != nil {
			t.Errorf("euid %d home %s: must keep the running user's ownership, got %+v", c.euid, c.home, o)
		}
	}
}

func TestReportsDirHandsOverThroughOpenBase(t *testing.T) {
	home := t.TempDir()
	owner := &reportOwner{uid: os.Getuid(), gid: os.Getgid()} // chown to ourselves needs no privilege
	d, err := scanReportsDir(home, time.Now(), owner)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(d.Path, "report.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.finish([]string{f}); err != nil {
		t.Fatalf("hand over: %v", err)
	}
	for _, p := range []string{f, d.Path, filepath.Dir(d.Path)} {
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if uid, ok := fileUID(st); ok && uid != owner.uid {
			t.Errorf("%s owned by %d, want %d", p, uid, owner.uid)
		}
	}
}

func TestScanReportsDirRefusesBaseOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a folder owned by another user")
	}
	home := t.TempDir()
	base := filepath.Join(home, "openvapt-reports")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(base, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := scanReportsDir(home, time.Now(), nil); err == nil {
		t.Fatal("a base folder owned by another user must be refused")
	}
	if d, err := scanReportsDir(home, time.Now(), &reportOwner{uid: 4242, gid: 4242}); err != nil {
		t.Fatalf("the sudo user's own existing folder must be accepted: %v", err)
	} else {
		_ = d.finish(nil)
	}
}
