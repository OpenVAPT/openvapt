package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
)

type checkResult = check.Result

func standardsFixture() check.Standards {
	return check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.1.1"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-8"}}
}

// S-02: Load refuses non-regular and oversized files instead of blocking or
// reading them whole.
func TestLoadIsBoundedAndRegularOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("directory: %v", err)
	}
	big := filepath.Join(dir, "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxReportSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversized: %v", err)
	}
	good := filepath.Join(dir, "good.json")
	r := &Report{Schema: SchemaVersion}
	b, _ := r.JSON()
	if err := os.WriteFile(good, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(good); err != nil {
		t.Errorf("good report: %v", err)
	}
}

func TestMarkdownStandardsIncludeWSTGAndASVS(t *testing.T) {
	r := &Report{Schema: SchemaVersion, Findings: []Finding{{ID: "WEB-X-001", Title: "T", Severity: "medium", Status: "fail", Standards: standardsFixture(),
		Results: []checkResult{{Status: "fail", Target: "site", Message: "m"}}}}}
	r.Summarise()
	md := r.Markdown()
	for _, want := range []string{"CWE-319", "OWASP Top 10 A02:2021", "ASVS 9.1.1", "WSTG-CRYP-01", "NIST SP 800-53 SC-8"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown standards line missing %q", want)
		}
	}
}
