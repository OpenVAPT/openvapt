package host

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

var cveRefs = []check.Ref{{Title: "OSV vulnerability database", URL: "https://osv.dev/"}, {Title: "NVD", URL: "https://nvd.nist.gov/"}, {Title: "CISA KEV", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}}
var cveStandards = check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}}

func init() {
	for _, spec := range []struct {
		id, title string
		sev       check.Severity
		kev, age  bool
		cvss      string
	}{
		// Representative vectors: a vulnerable package usually needs a reachable
		// code path (AC:H); a known exploited one is used in the wild (AC:L);
		// an outdated snapshot only hides information.
		{"HOST-CVE-001", "Installed OS Packages With Known Vulnerabilities", check.High, false, false, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"HOST-CVE-002", "Known Exploited Vulnerabilities Present", check.Critical, true, false, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"HOST-CVE-003", "Vulnerability Snapshot Outdated or Test Data", check.Low, false, true, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
	} {
		x := spec
		check.Register(&check.Check{
			ID:        x.id,
			Title:     x.title,
			Domain:    check.DomainHost,
			Severity:  x.sev,
			Category:  check.CatPatch,
			Effort:    check.EffortMedium,
			CVSS:      x.cvss,
			Summary:   "Checks installed packages against an offline vulnerability snapshot.",
			Rationale: "Known vulnerable package versions can expose a server to documented attacks.",
			Detection: "Reads installed package versions and matches OSV ecosystem ranges; each match names its matcher (exact version or range) and the snapshot date. When the binary carries only the test fixture snapshot (a source build without 'make vulndb'), the check reports Incomplete rather than Pass, because no advisory data was available.",
			Fix:       "Install the vendor security update. For a source build, run 'make vulndb' to embed a snapshot generated from OSV and CISA KEV, then rebuild.",
			Verify:    "Re-run OpenVAPT after patching and confirm the finding is absent.",
			Refs:      cveRefs,
			Standards: cveStandards,
			Run: func(ctx context.Context, s sys.System) []check.Result {
				db, e := collect.VulnDB(ctx, s)
				if e != nil {
					return []check.Result{check.IncompleteR("vulnerability snapshot", "Snapshot could not be read")}
				}
				if db.Header.Fixture {
					return []check.Result{check.IncompleteR("vulnerability snapshot", "No advisory data: the embedded snapshot is test fixture data", collect.FixtureNotice, db.Notice())}
				}
				if x.age {
					if old, _ := db.Age(time.Now()); old {
						return []check.Result{check.FailR("vulnerability snapshot", db.Notice())}
					}
					return []check.Result{check.PassR("vulnerability snapshot", db.Notice())}
				}
				items, ok := collect.HostInventory(ctx, s)
				if !ok {
					return []check.Result{check.IncompleteR("OS package inventory", "Installed packages could not be fully inventoried", db.Notice())}
				}
				var out []check.Result
				for _, p := range items {
					for _, m := range db.Match(p.Ecosystem, p.Package, p.Version) {
						a := m.Advisory
						if x.kev && !a.KEV {
							continue
						}
						if !x.kev && a.Severity != "high" && a.Severity != "critical" {
							continue
						}
						fixed := "not specified"
						for _, af := range a.Affected {
							if af.Ecosystem == p.Ecosystem && af.Package == p.Package {
								for _, r := range af.Ranges {
									for _, ev := range r.Events {
										if ev.Fixed != "" {
											fixed = ev.Fixed
										}
									}
								}
							}
						}
						out = append(out, check.FailR(p.Package, fmt.Sprintf("%s %s: %s (%s), fixed in %s, severity %s", p.Package, p.Version, a.ID, strings.Join(a.Aliases, ", "), fixed, a.Severity), "matcher: "+p.Matcher(m.Matcher), db.Notice()))
					}
				}
				if len(out) == 0 {
					return []check.Result{check.PassR("OS package inventory", "No matching advisories in the embedded snapshot", db.Notice())}
				}
				return out
			},
		})
	}
}
