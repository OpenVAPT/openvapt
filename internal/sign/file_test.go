package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/report"
)

func signedFile(t *testing.T) ([]byte, *report.Report) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := &report.Report{Schema: report.SchemaVersion, Scan: report.Scan{Started: time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)},
		Findings: []report.Finding{{ID: "X-1", Status: "fail", Severity: "high", Results: []check.Result{{Status: check.Fail, Target: "/etc/x", Message: "m <b>&"}}}}}
	r.Summarise()
	if err := Sign(r, priv); err != nil {
		t.Fatal(err)
	}
	b, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return b, r
}

func TestVerifyBytesExactFile(t *testing.T) {
	b, r := signedFile(t)
	if _, err := VerifyBytes(b, r.Integrity.KeyID); err != nil {
		t.Fatalf("fresh file must verify: %v", err)
	}
	if _, err := VerifyBytes(append(append([]byte{}, b...), '\n'), ""); err != nil {
		t.Fatalf("one trailing newline must be tolerated: %v", err)
	}
	if _, err := VerifyBytes(b, "0000000000000000"); err == nil {
		t.Fatal("wrong key id must fail")
	}
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(p, ""); err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
}

func TestVerifyBytesRejectsTampering(t *testing.T) {
	b, _ := signedFile(t)
	s := string(b)
	cases := map[string]string{
		"extra field":       strings.Replace(s, `"schema":`, `"note": "all fine",`+"\n  "+`"schema":`, 1),
		"extra nested":      strings.Replace(s, `"id": "X-1",`, `"id": "X-1", "hidden": true,`, 1),
		"duplicate key":     strings.Replace(s, `"status": "fail",`, `"status": "fail", "status": "pass",`, 1),
		"case variant":      strings.Replace(s, `"findings":`, `"Findings":`, 1),
		"case duplicate":    strings.Replace(s, `"status": "fail",`, `"status": "fail", "Status": "pass",`, 1),
		"whitespace change": strings.Replace(s, "\n  \"tool\"", "\n    \"tool\"", 1),
		"value change":      strings.Replace(s, `"status": "fail"`, `"status": "pass"`, 1),
		"raw html escape":   strings.Replace(s, "\\u003cb\\u003e", "<b>", 1),
		"trailing data":     s + "\n{}",
		"two newlines":      s + "\n\n",
	}
	for name, mod := range cases {
		if mod == s {
			t.Fatalf("%s: tamper did not change the file", name)
		}
		if _, err := VerifyBytes([]byte(mod), ""); err == nil {
			t.Errorf("%s: tampered file verified", name)
		}
	}
}

func TestOlderFormats(t *testing.T) {
	b, _ := signedFile(t)
	old := bytes.Replace(b, []byte(report.SchemaVersion), []byte("openvapt.report/2"), 1)
	_, err := VerifyBytes(old, "")
	if err == nil || !strings.Contains(err.Error(), "older report format") {
		t.Fatalf("schema/2 must say cannot verify older format, got %v", err)
	}
	// A schema/3 report signed by an earlier release (compact digest, no
	// format field) still verifies when the file is in canonical form.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := &report.Report{Schema: report.SchemaVersion, Findings: []report.Finding{{ID: "Y", Status: "pass"}}}
	if err := Sign(r, priv); err != nil {
		t.Fatal(err)
	}
	if err := legacySign(r, priv); err != nil {
		t.Fatal(err)
	}
	lb, _ := r.JSON()
	if _, err := VerifyBytes(lb, ""); err != nil {
		t.Fatalf("legacy signed canonical report should verify: %v", err)
	}
	r.Integrity.Format = "something/9"
	ub, _ := r.JSON()
	if _, err := VerifyBytes(ub, ""); err == nil || !strings.Contains(err.Error(), "unknown signature format") {
		t.Fatalf("unknown format must say so, got %v", err)
	}
}

func legacySign(r *report.Report, priv ed25519.PrivateKey) error {
	r.Integrity = nil
	d, err := digest(r, "")
	if err != nil {
		return err
	}
	if err := Sign(r, priv); err != nil {
		return err
	}
	r.Integrity.Format = ""
	r.Integrity.SHA256 = hexs(d)
	r.Integrity.Signature = b64(ed25519.Sign(priv, d))
	return nil
}

func TestKeyCreationAndChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	base := t.TempDir()
	p := filepath.Join(base, "openvapt", "report-key")
	k1, err := LoadOrCreateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	dst, _ := os.Stat(filepath.Dir(p))
	if st.Mode().Perm() != 0o600 || dst.Mode().Perm() != 0o700 {
		t.Fatalf("modes: key %v dir %v", st.Mode().Perm(), dst.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(p)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("reload failed: %v", err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("group or world readable key accepted")
	}
	_ = os.Chmod(p, 0o600)
	if err := os.Chmod(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("world accessible key folder accepted")
	}
	_ = os.Chmod(filepath.Dir(p), 0o700)

	// A planted symlink in place of the key is refused and its target untouched.
	d2 := filepath.Join(base, "two")
	if err := os.Mkdir(d2, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(d2, "report-key")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(filepath.Join(d2, "report-key")); err == nil {
		t.Fatal("symlinked key accepted")
	}
	dangling := filepath.Join(base, "three")
	_ = os.Mkdir(dangling, 0o700)
	if err := os.Symlink(filepath.Join(base, "nowhere"), filepath.Join(dangling, "report-key")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(filepath.Join(dangling, "report-key")); err == nil {
		t.Fatal("dangling symlink followed on create")
	}
	if _, err := os.Stat(filepath.Join(base, "nowhere")); err == nil {
		t.Fatal("key written through a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("symlink target modified")
	}
	// A symlinked key folder is refused.
	realDir := filepath.Join(base, "realdir")
	_ = os.Mkdir(realDir, 0o700)
	linkDir := filepath.Join(base, "linkdir")
	_ = os.Symlink(realDir, linkDir)
	if _, err := LoadOrCreateKey(filepath.Join(linkDir, "report-key")); err == nil {
		t.Fatal("symlinked key folder accepted")
	}
}

func TestKeyPathNeedsConfigDir(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip()
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := KeyPath(); err == nil {
		t.Fatal("KeyPath must fail without a user configuration folder")
	}
}
