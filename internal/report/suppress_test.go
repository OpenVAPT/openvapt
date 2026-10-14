package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/report"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func parse(t *testing.T, s string) (*report.Suppressions, error) {
	t.Helper()
	return report.ParseSuppressions("s.json", []byte(s), now)
}

func TestSuppressRejects(t *testing.T) {
	cases := map[string]string{
		"malformed":       `[{"id":`,
		"not a list":      `{"id":"HOST-SSH-005"}`,
		"unknown field":   `[{"id":"HOST-SSH-005","reason":"r","expires":"2027-01-01","why":"x"}]`,
		"duplicate key":   `[{"id":"HOST-SSH-005","id":"HOST-SSH-006","reason":"r","expires":"2027-01-01"}]`,
		"trailing":        `[] []`,
		"missing id":      `[{"reason":"r","expires":"2027-01-01"}]`,
		"unknown id":      `[{"id":"NOPE-001","reason":"r","expires":"2027-01-01"}]`,
		"missing reason":  `[{"id":"HOST-SSH-005","expires":"2027-01-01"}]`,
		"blank reason":    `[{"id":"HOST-SSH-005","reason":"  ","expires":"2027-01-01"}]`,
		"missing expires": `[{"id":"HOST-SSH-005","reason":"r"}]`,
		"bad date":        `[{"id":"HOST-SSH-005","reason":"r","expires":"01/01/2027"}]`,
		"over 365 days":   `[{"id":"HOST-SSH-005","reason":"r","expires":"2027-10-15"}]`,
		"bad glob":        `[{"id":"HOST-SSH-005","target":"[","reason":"r","expires":"2027-01-01"}]`,
	}
	for name, in := range cases {
		if _, err := parse(t, in); err == nil {
			t.Errorf("%s: accepted %s", name, in)
		}
	}
	if _, err := parse(t, `[{"id":"HOST-SSH-005","reason":"r","expires":"2027-10-14"}]`); err != nil {
		t.Errorf("exactly 365 days ahead rejected: %v", err)
	}
}

func TestSuppressExpiredIgnored(t *testing.T) {
	s, err := parse(t, `[{"id":"HOST-SSH-005","reason":"r","expires":"2026-10-13"},{"id":"HOST-SSH-006","reason":"r","expires":"2026-10-14"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Expired) != 1 || s.Expired[0].ID != "HOST-SSH-005" || len(s.Active) != 1 {
		t.Fatalf("expired %v active %v", s.Expired, s.Active)
	}
}

func TestLoadSuppressionsBoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := report.LoadSuppressions(dir, now); err == nil {
		t.Error("a directory was accepted")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte("["+strings.Repeat(" ", report.MaxSuppressFileSize)+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := report.LoadSuppressions(big, now); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversized file: %v", err)
	}
	sample := filepath.Join("..", "..", "docs", "suppress.sample.json")
	if _, err := report.LoadSuppressions(sample, now); err != nil {
		t.Errorf("docs sample does not load: %v", err)
	}
}

func sampleReport() *report.Report {
	r := &report.Report{Schema: report.SchemaVersion, Findings: []report.Finding{{
		ID: "HOST-SSH-005", Title: "T", Severity: "high", Status: string(check.Fail),
		Results: []check.Result{
			{Status: check.Fail, Target: "/etc/ssh/sshd_config", Message: "bad"},
			{Status: check.Fail, Target: "/etc/ssh/sshd_config.d/x.conf", Message: "bad too"},
		},
	}}}
	r.Summarise()
	return r
}

func TestApplySuppressionsVisible(t *testing.T) {
	s, err := parse(t, `[{"id":"HOST-SSH-005","target":"/etc/ssh/sshd_config.d/*","reason":"Accepted for lab","expires":"2027-01-01","added_by":"ops"}]`)
	if err != nil {
		t.Fatal(err)
	}
	r := sampleReport()
	r.ApplySuppressions(s)
	f := r.Findings[0]
	if f.Status != string(check.Fail) || r.Summary.High != 1 {
		t.Fatal("suppression changed status or counts")
	}
	if len(f.Suppressed) != 1 || f.FullySuppressed() {
		t.Fatalf("partial suppression wrong: %+v", f.Suppressed)
	}
	if r.Suppression == nil || r.Suppression.Suppressed != 1 || len(r.Suppression.SHA256) != 64 {
		t.Fatalf("header info: %+v", r.Suppression)
	}

	sarif, err := r.SARIF()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Suppressions []struct{ Kind, Justification string } `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif, &doc); err != nil {
		t.Fatal(err)
	}
	res := doc.Runs[0].Results
	if len(res) != 2 || len(res[0].Suppressions) != 0 || len(res[1].Suppressions) != 1 || res[1].Suppressions[0].Kind != "external" || !strings.Contains(res[1].Suppressions[0].Justification, "Accepted for lab") {
		t.Fatalf("sarif suppressions: %+v", res)
	}

	md := r.Markdown()
	html, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"md": md, "html": string(html)} {
		for _, want := range []string{"Suppressed Findings", "Accepted for lab", "2027-01-01", r.Suppression.SHA256, "1 failed result(s) suppressed"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s report lacks %q", name, want)
			}
		}
	}
	js, _ := r.JSON()
	if !strings.Contains(string(js), `"suppressed"`) || !strings.Contains(string(js), `"status": "fail"`) {
		t.Error("json lost the suppression or the status")
	}

	// A suppression on every failed result makes the finding fully suppressed.
	all, _ := parse(t, `[{"id":"HOST-SSH-005","reason":"r","expires":"2027-01-01"}]`)
	r2 := sampleReport()
	r2.ApplySuppressions(all)
	if !r2.Findings[0].FullySuppressed() {
		t.Error("untargeted entry did not cover every result")
	}
}

func TestNoSuppressionNoSection(t *testing.T) {
	r := sampleReport()
	r.ApplySuppressions(nil)
	if r.Suppression != nil || strings.Contains(r.Markdown(), "Suppressed Findings") {
		t.Error("suppression section shown without a file")
	}
}
