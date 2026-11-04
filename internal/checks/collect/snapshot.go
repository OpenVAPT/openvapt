package collect

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/vulndb"
)

// LabSnapshotPath is where a simulated lab (sys.Fake) carries its own
// vulnerability snapshot as uncompressed JSON. A real scan never reads it:
// the path is only honoured on an in-memory Fake, so the labs stay
// deterministic whatever snapshot is compiled into the binary.
const LabSnapshotPath = "/run/openvapt/lab-snapshot.json"

// VulnDB returns the vulnerability snapshot a scan should match against:
// the lab's own snapshot on a Fake that carries one, otherwise the snapshot
// embedded in the binary.
func VulnDB(ctx context.Context, s sys.System) (vulndb.Snapshot, error) {
	if f, ok := s.(*sys.Fake); ok {
		if data := f.Files[LabSnapshotPath]; data != "" {
			return vulndb.DecodeJSON(strings.NewReader(data))
		}
	}
	_ = ctx
	return vulndb.Embedded()
}

// FixtureNotice is the evidence line CVE checks give when the compiled-in
// snapshot is test fixture data rather than a generated release snapshot.
const FixtureNotice = "The embedded vulnerability snapshot is test fixture data, not advisory data: no CVE matching was possible. Build the real snapshot with 'make vulndb' (cmd/vulndbgen) or use a release build."
