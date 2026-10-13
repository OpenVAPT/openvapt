package host

import (
	"context"
	"fmt"
	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/vulndb"
	"strings"
	"time"
)

var cveRefs = []check.Ref{{Title: "OSV vulnerability database", URL: "https://osv.dev/"}, {Title: "NVD", URL: "https://nvd.nist.gov/"}, {Title: "CISA KEV", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}}
var cveStandards = check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}}

func init() {
	for _, spec := range []struct {
		id, title string
		sev       check.Severity
		kev, age  bool
	}{
		{"HOST-CVE-001", "Installed OS Packages With Known Vulnerabilities", check.High, false, false},
		{"HOST-CVE-002", "Known Exploited Vulnerabilities Present", check.Critical, true, false},
		{"HOST-CVE-003", "Vulnerability Snapshot Outdated or Test Data", check.Low, false, true},
	} {
		x := spec
		check.Register(&check.Check{
			ID:        x.id,
			Title:     x.title,
			Domain:    check.DomainHost,
			Severity:  x.sev,
			Category:  check.CatPatch,
			Effort:    check.EffortMedium,
			CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Summary:   "Checks installed packages against an offline vulnerability snapshot.",
			Rationale: "Known vulnerable package versions can expose a server to documented attacks.",
			Detection: "Reads installed package versions and matches OSV ecosystem ranges; the snapshot date and fixture status are reported.",
			Fix:       "Install the vendor security update and regenerate the release snapshot.",
			Verify:    "Re-run OpenVAPT after patching and confirm the finding is absent.",
			Refs:      cveRefs,
			Standards: cveStandards,
			Run: func(ctx context.Context, s sys.System) []check.Result {
				db, e := vulndb.Embedded()
				if e != nil {
					return []check.Result{check.IncompleteR("vulnerability snapshot", "Snapshot could not be read")}
				}
				if x.age {
					if f, ok := s.(*sys.Fake); ok && f.Files["/run/openvapt/lab-snapshot-date"] != "" {
						db.Header.Generated = f.Files["/run/openvapt/lab-snapshot-date"]
						db.Header.Fixture = false
					}
					if f, _ := db.Age(snapshotClock(s)); f {
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
					for _, a := range db.Match(p.Ecosystem, p.Package, p.Version) {
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
						out = append(out, check.FailR(p.Package, fmt.Sprintf("%s %s: %s (%s), fixed in %s, severity %s", p.Package, p.Version, a.ID, strings.Join(a.Aliases, ", "), fixed, a.Severity), db.Notice()))
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
func snapshotClock(s sys.System) time.Time {
	if f, ok := s.(*sys.Fake); ok {
		if v := f.Files["/run/openvapt/lab-snapshot-date"]; v != "" {
			if t, e := time.Parse("2006-01-02", v); e == nil {
				return t
			}
		}
	}
	return time.Now()
}
