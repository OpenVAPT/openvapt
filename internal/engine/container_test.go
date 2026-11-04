package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
)

// Inside a container, host-only checks are skipped with a reason and the
// report says the scan ran in a container; other checks still run.
func TestContainerSkipsHostOnlyChecks(t *testing.T) {
	for name, f := range map[string]func() *sys.Fake{"vulnerable": lab.Vulnerable, "hardened": lab.Hardened} {
		r := Run(context.Background(), lab.Container(f()), Options{})
		skipped, ran := 0, 0
		for _, fd := range r.Findings {
			if collect.HostOnly(fd.ID) {
				skipped++
				if fd.Status != string(check.Skip) || len(fd.Results) != 1 || !strings.Contains(fd.Results[0].Message, "running inside a container (docker): this setting belongs to the host") {
					t.Errorf("%s lab: %s should be skipped in a container, got %s %+v", name, fd.ID, fd.Status, fd.Results)
				}
			} else if fd.Status != string(check.Skip) {
				ran++
			}
		}
		if skipped < 30 || ran == 0 {
			t.Errorf("%s lab: skipped %d host-only checks, %d others ran", name, skipped, ran)
		}
		note := false
		for _, l := range r.Limitations {
			if strings.Contains(l, "inside a container (docker") {
				note = true
			}
		}
		if !note {
			t.Errorf("%s lab: no container note in limitations", name)
		}
	}
	// Outside a container nothing is skipped for that reason.
	r := Run(context.Background(), lab.Hardened(), Options{})
	for _, l := range r.Limitations {
		if strings.Contains(l, "inside a container") {
			t.Error("container note on a non-container lab")
		}
	}
}
