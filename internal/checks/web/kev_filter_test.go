package web

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/lab"
)

// A known exploited library stays reported even at a Medium rating; a plain
// Medium advisory does not.
func TestWebCVEKeepsMediumKEV(t *testing.T) {
	run := func(kev string) string {
		f := lab.Vulnerable()
		j := strings.ReplaceAll(f.Files[collect.LabSnapshotPath], `"Severity":"high","CVSSScore":0,"CVSSVector":"","Published":"","Modified":"","References":["https://nvd.nist.gov/vuln/detail/CVE-2023-30861"],"KEV":false`, `"Severity":"medium","CVSSScore":0,"CVSSVector":"","Published":"","Modified":"","References":[],"KEV":`+kev)
		f.Files[collect.LabSnapshotPath] = j
		var b strings.Builder
		for _, r := range check.Get("WEB-CVE-001").Run(context.Background(), f) {
			b.WriteString(r.Message + "\n")
		}
		return b.String()
	}
	if !strings.Contains(run("true"), "CVE-2023-30861") {
		t.Error("a known exploited Medium advisory must be reported")
	}
	if strings.Contains(run("false"), "CVE-2023-30861") {
		t.Error("a plain Medium advisory belongs out of WEB-CVE-001")
	}
}
