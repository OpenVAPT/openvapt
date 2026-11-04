package host

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/lab"
)

// A release the snapshot has no data for must never read as clean.
func TestUncoveredReleaseIsIncomplete(t *testing.T) {
	f := lab.Hardened()
	f.Files["/etc/os-release"] = "ID=alpine\nVERSION_ID=3.19.1\n"
	f.Files["/lib/apk/db/installed"] = "P:musl\nV:1.2.4-r0\n"
	for _, id := range []string{"HOST-CVE-001", "HOST-CVE-002", "HOST-CVE-004"} {
		rs := check.Get(id).Run(context.Background(), f)
		if len(rs) != 1 || rs[0].Status != check.Incomplete {
			t.Errorf("%s: %+v", id, rs)
		}
	}
}
