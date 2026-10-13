package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
)

func hostileReport() *Report {
	r := &Report{
		Schema: SchemaVersion, Tool: Tool{Name: "Open|VAPT", Version: "<x>", URL: "javascript:alert(1)"},
		Scan: Scan{Started: time.Now(), Host: "bad|host\n# injected", OS: "[click](https://evil.invalid)", Checks: 1}, Disclaimer: "safe\n# heading",
		Findings: []Finding{{
			ID: "X|1", Title: "[link](https://evil.invalid)", Severity: "high", Status: string(check.Incomplete), Summary: "<script>alert(1)</script>", Rationale: "why", Fix: "fix", Verify: "verify",
			Refs:    []check.Ref{{Title: "bad", URL: "javascript:alert(1)"}},
			Results: []check.Result{{Status: check.Incomplete, Target: "x|y\n# z", Message: "partial [link](https://evil.invalid)", Evidence: []string{"`boom`\n# h"}}},
		}},
	}
	r.Summarise()
	return r
}

func TestRenderersEscapeHostileValues(t *testing.T) {
	r := hostileReport()
	md := r.Markdown()
	if strings.Contains(md, "bad|host\n") || strings.Contains(md, "[click](https://evil.invalid)") || !strings.Contains(md, "Incomplete") {
		t.Fatalf("unsafe or incomplete markdown:\n%s", md)
	}
	h, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(h), "<script>alert") || strings.Contains(string(h), `href="javascript:`) || !strings.Contains(string(h), "Incomplete") {
		t.Fatalf("unsafe HTML: %s", h)
	}
	j, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var jr Report
	if json.Unmarshal(j, &jr) != nil || jr.Summary.Incomplete != 1 {
		t.Fatal("invalid JSON or missing incomplete count")
	}
	s, err := r.SARIF()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(s, &doc) != nil || !strings.Contains(string(s), "Incomplete") {
		t.Fatal("invalid SARIF or missing incomplete result")
	}
	for _, section := range []string{"Executive Summary", "Risk Heat Map", "Compliance Coverage", "Prioritised Remediation Plan", "Coverage Gaps", "Methodology", "Limitations"} {
		if !strings.Contains(md, section) || !strings.Contains(string(h), section) {
			t.Errorf("missing report section %q", section)
		}
	}
}

func TestJSONAndSARIFIncludeCategoryAndEffort(t *testing.T) {
	r := hostileReport()
	r.Findings[0].Category = check.CatNetwork
	r.Findings[0].Effort = check.EffortLow
	j, _ := r.JSON()
	s, _ := r.SARIF()
	for name, data := range map[string][]byte{"json": j, "sarif": s} {
		if !strings.Contains(string(data), `"category"`) || !strings.Contains(string(data), `"effort"`) {
			t.Errorf("%s omitted category or effort", name)
		}
	}
}

func TestLoadMigratesSchemaTwo(t *testing.T) {
	r := hostileReport()
	r.Schema = "openvapt.report/2"
	r.Findings[0].Category = ""
	r.Findings[0].Effort = ""
	b, _ := json.Marshal(r)
	p := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != SchemaVersion || got.Findings[0].Category == "" || got.Findings[0].Effort == "" {
		t.Fatalf("migration failed: %+v", got.Findings[0])
	}
}

func TestWriteAllRejectsSymlinksAndExistingFiles(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(base, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := hostileReport().WriteAll(linkDir, []string{"json"}); err == nil {
		t.Fatal("symlink directory accepted")
	}
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(realDir, "report.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := hostileReport().WriteAll(realDir, []string{"json"}); err == nil {
		t.Fatal("symlink output accepted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "keep" {
		t.Fatal("symlink target was modified")
	}
}
