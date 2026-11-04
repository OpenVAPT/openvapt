package channels

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfAndBase(t *testing.T) {
	for v, want := range map[string]Channel{"v0.1.0-alpha.3": Alpha, "v0.1.0-beta.1": Beta, "v1.2.0-rc.2": RC, "v1.2.0": Stable, "v0.1.0-dev": Dev, "main": Dev} {
		if got := Of(v); got != want {
			t.Errorf("Of(%q) = %q, want %q", v, got, want)
		}
	}
	if Base("v1.2.0-rc.2") != "v1.2.0" || Base("x") != "" {
		t.Error("Base")
	}
}

func day(s string) time.Time { t, _ := time.Parse("2006-01-02", s); return t }

func names(cs []Check, passed bool) []string {
	var out []string
	for _, c := range cs {
		if c.Passed == passed {
			out = append(out, c.Name)
		}
	}
	return out
}

// The full life of one version: every gate must block until its evidence
// exists, and every promotion must be recorded.
func TestPromotionLifecycle(t *testing.T) {
	s := &State{Schema: "openvapt.channels/1", Next: "v0.1.0", Current: map[Channel]Release{}}
	legal := LegalReview{Version: "v0.1.0-alpha.1", Reviewed: "2026-10-13", Reviewer: "AI legal reviewer", PublicLaunchApproved: true}
	ev := Evidence{Commit: "aaa", CIGreen: true, LabPass: true, Legal: legal, Now: day("2026-10-13")}

	if ok, cs := Gate(s, Beta, ev); ok {
		t.Fatalf("beta before any alpha must fail: %v", cs)
	}
	ok, cs := Gate(s, Alpha, ev)
	if !ok {
		t.Fatalf("alpha gate: %v", names(cs, false))
	}
	if r := s.Promote(Alpha, ev, cs); r.Version != "v0.1.0-alpha.1" || r.Commit != "aaa" {
		t.Fatalf("alpha release %+v", r)
	}
	if ok, _ := Gate(s, Alpha, ev); ok {
		t.Error("the same commit must not become a second alpha")
	}

	// Beta needs 7 days of soak and the alpha commit's own evidence.
	if ok, cs := Gate(s, Beta, ev); ok || names(cs, false)[0] != "Soak Time" {
		t.Errorf("beta on day 0 must fail only on soak, got %v", names(cs, false))
	}
	ev.Now = day("2026-10-20")
	if ok, cs := Gate(s, Beta, Evidence{Commit: "bbb", CIGreen: true, LabPass: true, Legal: legal, Now: ev.Now}); ok {
		t.Errorf("evidence for another commit must not promote: %v", cs)
	}
	risky := ev
	risky.Legal.OpenHighRisks = 1
	if ok, _ := Gate(s, Beta, risky); ok {
		t.Error("open High legal risks must block beta")
	}
	missing := ev
	missing.LegalErr = errors.New("missing")
	if ok, _ := Gate(s, Beta, missing); ok {
		t.Error("a missing legal record must block beta")
	}
	ok, cs = Gate(s, Beta, ev)
	if !ok {
		t.Fatalf("beta gate: %v", names(cs, false))
	}
	s.Promote(Beta, ev, cs)
	ev.Legal.Version = "v0.1.0-beta.1" // the legal reviewer re-reviews each build before it moves up

	// RC needs installer and signing evidence.
	ev.Now = day("2026-10-27")
	if ok, _ := Gate(s, RC, ev); ok {
		t.Error("rc without installer and signing evidence must fail")
	}
	ev.InstallerE2E, ev.Signed = true, true
	ok, cs = Gate(s, RC, ev)
	if !ok {
		t.Fatalf("rc gate: %v", names(cs, false))
	}
	if r := s.Promote(RC, ev, cs); r.Version != "v0.1.0-rc.1" {
		t.Errorf("rc version %s", r.Version)
	}
	ev.Legal.Version = "v0.1.0-rc.1"

	// Stable needs 14 days and the public release sign-off.
	ev.Now = day("2026-11-05")
	if ok, _ := Gate(s, Stable, ev); ok {
		t.Error("stable after 9 days must fail")
	}
	ev.Now = day("2026-11-10")
	noSign := ev
	noSign.Legal.PublicLaunchApproved = false
	if ok, _ := Gate(s, Stable, noSign); ok {
		t.Error("stable without public sign-off must fail")
	}
	ok, cs = Gate(s, Stable, ev)
	if !ok {
		t.Fatalf("stable gate: %v", names(cs, false))
	}
	if r := s.Promote(Stable, ev, cs); r.Version != "v0.1.0" || r.Commit != "aaa" {
		t.Errorf("stable %+v", r)
	}
	if s.Next != "v0.2.0" || s.Highest() != Stable || len(s.History) != 4 {
		t.Errorf("state after stable: next %s highest %s history %d", s.Next, s.Highest(), len(s.History))
	}
	if ok, _ := Gate(s, Beta, ev); ok {
		t.Error("the legal review for v0.1.0 must not cover the v0.2.0 cycle")
	}

	p := filepath.Join(t.TempDir(), "c.json")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p)
	if err != nil || back.Current[Stable].Version != "v0.1.0" {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	if got := back.Text(); got == "" || back.NextVersion(Alpha) != "v0.2.0-alpha.1" {
		t.Errorf("text %q next alpha %s", got, back.NextVersion(Alpha))
	}
}

func TestRepositoryStateIsValid(t *testing.T) {
	s, err := Load("../../release/channels.json")
	if err != nil {
		t.Fatal(err)
	}
	for c, r := range s.Current {
		if Of(r.Version) != c {
			t.Errorf("current %s holds %s", c, r.Version)
		}
	}
	lr, err := LoadLegal("../../release/legal-review.json")
	if err != nil {
		t.Fatalf("legal review record: %v", err)
	}
	// The record must be self-describing (AGENTS.md 5.8): it names the
	// accepted High risks and hashes every legal document it reviewed.
	if len(lr.Documents) == 0 {
		t.Error("legal review record lists no reviewed documents")
	}
	for _, must := range []string{"LICENSE", "EULA.md", "ACCEPTABLE_USE.md", "DISCLAIMER.md", "PRIVACY.md", "TEACHING.md", "internal/terms/terms.go"} {
		if _, ok := lr.Documents[must]; !ok {
			t.Errorf("legal review record does not hash %s", must)
		}
	}
	if lr.OpenHighRisks == 0 && len(lr.AcceptedHighRisks) == 0 {
		t.Error("open_high_risks is 0 but no accepted High risks are named; the register records accepted Highs")
	}
	if stale := lr.StaleDocuments("../.."); len(stale) > 0 {
		t.Errorf("legal documents changed since the AI legal reviewer's record; a new review entry is needed for: %v", stale)
	}
}

func TestStaleDocuments(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("hello\n")))
	lr := LegalReview{Documents: map[string]string{"a.md": sum}}
	if s := lr.StaleDocuments(dir); len(s) != 0 {
		t.Errorf("matching document reported stale: %v", s)
	}
	lr.Documents["a.md"] = "0000"
	lr.Documents["missing.md"] = sum
	s := lr.StaleDocuments(dir)
	if len(s) != 2 || s[0] != "a.md" || !strings.HasPrefix(s[1], "missing.md: ") {
		t.Errorf("stale and missing documents not reported: %v", s)
	}
}

// Evidence without the tested commit must never promote beyond Alpha.
func TestGateRequiresTheTestedCommit(t *testing.T) {
	s := &State{Next: "v0.1.0", Current: map[Channel]Release{Alpha: {Channel: Alpha, Version: "v0.1.0-alpha.1", Commit: "aaa", Date: "2026-10-01"}}}
	legal := LegalReview{Version: "v0.1.0-alpha.1", Reviewed: "2026-10-01", Reviewer: "AI legal reviewer"}
	ev := Evidence{CIGreen: true, LabPass: true, Legal: legal, Now: day("2026-10-20")}
	if ok, cs := Gate(s, Beta, ev); ok {
		t.Fatalf("promotion without a commit passed: %v", cs)
	}
	ev.Commit = "aaa"
	if ok, cs := Gate(s, Beta, ev); !ok {
		t.Fatalf("with the tested commit it should pass: %v", names(cs, false))
	}
	s.Next = "v0.2.0"
	if ok, _ := Gate(s, Beta, ev); ok {
		t.Error("an alpha from another cycle must not be promoted under the new version")
	}
}
