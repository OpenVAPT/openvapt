package web

import (
	"context"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "WEB-CVE-001",
		Title:     "Vulnerable Web Application Libraries",
		Domain:    check.DomainWeb,
		Severity:  check.High,
		Category:  check.CatPatch,
		Effort:    check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Matches local web library versions against offline OSV advisories; WordPress core is inventoried and reported Incomplete because OSV publishes no WordPress feed.",
		Rationale: "Unpatched web libraries can expose users and server data to known vulnerabilities.",
		Detection: "Reads lockfiles (Packagist, npm), wp-includes/version.php (inventoried as WordPress:Core; OSV publishes no WordPress export, so a real snapshot has no data for it) and jQuery file headers under configured document roots, and matches them against the snapshot. Each match names its matcher: exact version, range, or heuristic for a version read from a file header. Inventory the snapshot has no advisory data for (for example WordPress core, for which OSV publishes no feed, or the test fixture snapshot of a source build) is reported Incomplete, never Pass.",
		Fix:       "Update the affected library or WordPress core and deploy a refreshed lockfile or asset. For a source build, run 'make vulndb' to embed a generated snapshot.",
		Verify:    "Re-run OpenVAPT and verify that the vulnerable version is no longer deployed.",
		Refs:      []check.Ref{{Title: "OSV", URL: "https://osv.dev/"}, {Title: "OSV schema, defined ecosystems (WordPress)", URL: "https://ossf.github.io/osv-schema/"}, {Title: "NVD", URL: "https://nvd.nist.gov/"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			db, e := collect.VulnDB(ctx, s)
			if e != nil {
				return []check.Result{check.IncompleteR("web inventory", "Snapshot could not be read")}
			}
			if db.Header.Fixture {
				return []check.Result{check.IncompleteR("web inventory", "No advisory data: the embedded snapshot is test fixture data", collect.FixtureNotice, db.Notice())}
			}
			items, ok := collect.WebInventory(ctx, s)
			if !ok {
				return []check.Result{check.IncompleteR("web inventory", "Web libraries could not be fully inventoried", db.Notice())}
			}
			var out []check.Result
			uncovered := map[string]bool{}
			for _, p := range items {
				eco := strings.SplitN(p.Ecosystem, ":", 2)[0]
				if !db.HasEcosystem(eco) {
					uncovered[eco] = true
					continue
				}
				for _, m := range db.Match(p.Ecosystem, p.Package, p.Version) {
					a := m.Advisory
					out = append(out, check.FailR(p.Package, fmt.Sprintf("%s %s: %s (%s), severity %s", p.Package, p.Version, a.ID, strings.Join(a.Aliases, ", "), a.Severity), "matcher: "+p.Matcher(m.Matcher), "source: "+p.Path, db.Notice()))
				}
			}
			for eco := range uncovered {
				out = append(out, check.IncompleteR(eco+" inventory", "No "+eco+" advisory data in snapshot; "+eco+" components were inventoried but could not be matched", db.Notice()))
			}
			if len(out) == 0 {
				return []check.Result{check.PassR("web inventory", "No matching advisories in the embedded snapshot", db.Notice())}
			}
			return out
		},
	})
}
