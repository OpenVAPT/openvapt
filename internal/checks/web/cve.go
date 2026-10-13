package web

import (
	"context"
	"fmt"
	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/vulndb"
	"strings"
)

func init() {
	check.Register(&check.Check{
		ID:        "WEB-CVE-001",
		Title:     "Vulnerable Web Application Libraries",
		Domain:    check.DomainWeb,
		Severity:  check.High,
		Category:  check.CatPatch,
		Effort:    check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		Summary:   "Matches local web library versions against offline OSV advisories.",
		Rationale: "Unpatched web libraries can expose users and server data to known vulnerabilities.",
		Detection: "Reads lockfiles, WordPress version files and jQuery headers under configured document roots.",
		Fix:       "Update the affected library and deploy a refreshed lockfile or asset.",
		Verify:    "Re-run OpenVAPT and verify that the vulnerable version is no longer deployed.",
		Refs:      []check.Ref{{Title: "OSV", URL: "https://osv.dev/"}, {Title: "NVD", URL: "https://nvd.nist.gov/"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			db, e := vulndb.Embedded()
			if e != nil {
				return []check.Result{check.IncompleteR("web inventory", "Snapshot could not be read")}
			}
			items, ok := collect.WebInventory(ctx, s)
			if !ok {
				return []check.Result{check.IncompleteR("web inventory", "Web libraries could not be fully inventoried", db.Notice())}
			}
			var out []check.Result
			for _, p := range items {
				for _, a := range db.Match(p.Ecosystem, p.Package, p.Version) {
					out = append(out, check.FailR(p.Package, fmt.Sprintf("%s %s: %s (%s), severity %s", p.Package, p.Version, a.ID, strings.Join(a.Aliases, ", "), a.Severity), db.Notice()))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.PassR("web inventory", "No matching advisories in the embedded snapshot", db.Notice())}
			}
			return out
		},
	})
}
