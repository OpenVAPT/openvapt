package web

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/lab"
)

func TestWebCVEWordPressAndFixture(t *testing.T) {
	rs := check.Get("WEB-CVE-001").Run(context.Background(), lab.Vulnerable())
	wp := false
	for _, r := range rs {
		if r.Target == "wordpress" && r.Status == check.Fail && strings.Contains(r.Message, "5.2.1") {
			wp = true
		}
	}
	if !wp {
		t.Errorf("vulnerable WordPress core must fail WEB-CVE-001: %+v", rs)
	}
	f := lab.Hardened()
	delete(f.Files, collect.LabSnapshotPath)
	rs = check.Get("WEB-CVE-001").Run(context.Background(), f)
	if len(rs) != 1 || rs[0].Status != check.Incomplete {
		t.Errorf("fixture snapshot must give Incomplete, got %+v", rs)
	}
	// A snapshot without WordPress data cannot pass a WordPress inventory.
	f = lab.Hardened()
	f.Files[collect.LabSnapshotPath] = strings.ReplaceAll(f.Files[collect.LabSnapshotPath], "WordPress:Core", "Other:Core")
	rs = check.Get("WEB-CVE-001").Run(context.Background(), f)
	found := false
	for _, r := range rs {
		if r.Status == check.Incomplete && strings.Contains(r.Message, "No WordPress advisory data in snapshot") {
			found = true
		}
	}
	if !found {
		t.Errorf("want Incomplete for uncovered WordPress inventory, got %+v", rs)
	}
}
