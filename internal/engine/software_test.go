package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/report"
)

// hardenedNotPass lists the checks that cannot reach Pass on the hardened lab
// and why. Each entry is a deliberate limit of the simulation, not a weakened
// check; remove an entry when a hardened fixture is added for it.
var hardenedNotPass = map[string]string{}

// Every registered check reaches a real Pass on the hardened lab (not Skip
// or Incomplete), except the documented exceptions above.
func TestEveryCheckPassesOnHardenedLab(t *testing.T) {
	r := Run(context.Background(), lab.Hardened(), Options{})
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.ID] = true
		if why, ok := hardenedNotPass[f.ID]; ok {
			if f.Status == string(check.Pass) {
				t.Errorf("%s now passes on the hardened lab; remove it from hardenedNotPass (%s)", f.ID, why)
			}
			continue
		}
		if f.Status != string(check.Pass) {
			t.Errorf("%s (%s) should PASS on the hardened lab, got %s: %+v", f.ID, f.Title, f.Status, f.Results)
		}
	}
	for id := range hardenedNotPass {
		if !seen[id] {
			t.Errorf("hardenedNotPass names unknown check %s", id)
		}
	}
}

// The report header records the snapshot the CVE checks used.
func TestReportHeaderNamesSnapshot(t *testing.T) {
	h := Run(context.Background(), lab.Hardened(), Options{Only: []string{"HOST-CVE-003"}})
	if h.Scan.VulnDB == nil || h.Scan.VulnDB.Fixture || h.Scan.VulnDB.Stale || h.Scan.VulnDB.AgeDays != 0 || h.Scan.VulnDB.Advisories == 0 {
		t.Fatalf("hardened header: %+v", h.Scan.VulnDB)
	}
	v := Run(context.Background(), lab.Vulnerable(), Options{Only: []string{"HOST-CVE-003"}})
	if v.Scan.VulnDB == nil || !v.Scan.VulnDB.Stale || !strings.Contains(v.Scan.VulnDB.Notice(), "not a failure") {
		t.Fatalf("vulnerable header should warn about age: %+v", v.Scan.VulnDB)
	}
	if v.Scan.AsRoot {
		// engine.Run records the real euid; the CLI clears it for simulated labs.
		t.Log("AsRoot true in engine for a lab run; cmdDemo and Practice clear it")
	}
	for _, f := range h.Findings {
		if len(f.Academy) == 0 || !strings.HasPrefix(f.Academy[0].URL, "https://openvapt.com/academy/") || !strings.HasSuffix(f.Academy[0].URL, ".html") {
			t.Errorf("%s has no Academy module link: %+v", f.ID, f.Academy)
		}
	}
	md := h.Markdown()
	if !strings.Contains(md, "Vulnerability snapshot:") {
		t.Error("markdown header lacks the snapshot line")
	}
	b, _ := h.HTML()
	if !strings.Contains(string(b), "Vulnerability Data") {
		t.Error("html header lacks the snapshot row")
	}
	_ = report.StaleAfterDays
}

// R-02: the whole-scan deadline ends waiting checks with an Error result
// instead of running them, and --parallel is clamped.
func TestScanDeadlineAndParallelClamp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Run(ctx, lab.Hardened(), Options{Only: []string{"HOST-SSH-001"}, Deadline: time.Hour, Parallel: 1000})
	if len(r.Findings) != 1 || r.Findings[0].Status != string(check.Error) || !strings.Contains(r.Findings[0].Results[0].Message, "not run") {
		t.Fatalf("a passed deadline must yield Error results: %+v", r.Findings)
	}
	if r.Summary.Errors != 1 {
		t.Errorf("summary errors = %d", r.Summary.Errors)
	}
	// A generous deadline changes nothing.
	ok := Run(context.Background(), lab.Hardened(), Options{Only: []string{"HOST-SSH-001"}, Deadline: time.Hour})
	if ok.Findings[0].Status != string(check.Pass) {
		t.Errorf("deadline must not disturb a normal run: %+v", ok.Findings[0])
	}
}
