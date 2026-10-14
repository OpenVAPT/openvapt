package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanReportsDirIsPrivateDatedAndNeverReused(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 10, 14, 7, 46, 0, 0, time.FixedZone("X", 8*3600))
	a, err := scanReportsDir(home, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "openvapt-reports", "20261013T234600Z"); a != want {
		t.Fatalf("folder %s, want %s (UTC timestamp)", a, want)
	}
	b, err := scanReportsDir(home, now)
	if err != nil || b != a+"-2" {
		t.Fatalf("second scan in the same second must get its own folder: %s %v", b, err)
	}
	for _, d := range []string{a, b, filepath.Dir(a)} {
		st, err := os.Stat(d)
		if err != nil || st.Mode().Perm() != 0o700 {
			t.Fatalf("%s must be 0700: %v %v", d, st.Mode().Perm(), err)
		}
	}
	if _, err := scanReportsDir("", now); err == nil || !strings.Contains(err.Error(), "--out") {
		t.Fatalf("no home must ask for --out, got %v", err)
	}
	if _, err := scanReportsDir("relative", now); err == nil {
		t.Fatal("a relative home must be refused")
	}
}

func TestScanReportsDirRefusesLinkedBase(t *testing.T) {
	home := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(home, "openvapt-reports")); err != nil {
		t.Skip(err)
	}
	if _, err := scanReportsDir(home, time.Now()); err == nil {
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
