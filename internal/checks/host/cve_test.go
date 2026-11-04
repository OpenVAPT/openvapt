package host

import (
	"context"
	"github.com/openvapt/openvapt/internal/vulndb"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/lab"
)

// A build that embeds only the test fixture snapshot must say so: Incomplete,
// never Pass, for every CVE check.
func TestCVEChecksAreIncompleteOnFixtureSnapshot(t *testing.T) {
	if s, err := vulndb.Embedded(); err != nil || !s.Header.Fixture {
		t.Skip("a real snapshot is embedded (release build); this test covers the fixture-only path")
	}
	f := lab.Hardened()
	delete(f.Files, collect.LabSnapshotPath) // fall back to the embedded fixture
	for _, id := range []string{"HOST-CVE-001", "HOST-CVE-002", "HOST-CVE-003"} {
		rs := check.Get(id).Run(context.Background(), f)
		if len(rs) != 1 || rs[0].Status != check.Incomplete {
			t.Errorf("%s on fixture snapshot: want Incomplete, got %+v", id, rs)
		}
	}
}

func TestCVEMatchesNameTheirMatcher(t *testing.T) {
	rs := check.Get("HOST-CVE-001").Run(context.Background(), lab.Vulnerable())
	if len(rs) == 0 || rs[0].Status != check.Fail {
		t.Fatalf("expected failures, got %+v", rs)
	}
	for _, r := range rs {
		if len(r.Evidence) == 0 || r.Evidence[0] != "matcher: range" {
			t.Errorf("missing matcher label: %+v", r)
		}
	}
}
