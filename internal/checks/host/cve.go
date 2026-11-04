package host

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/vulndb"
)

var cveRefs = []check.Ref{{Title: "OSV vulnerability database", URL: "https://osv.dev/"}, {Title: "NVD", URL: "https://nvd.nist.gov/"}, {Title: "CISA KEV", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}}
var cveStandards = check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}}

// repeatsKnownFlaw records the advisory's CVEs for the group and reports
// whether every one of them was already seen.
func repeatsKnownFlaw(group string, a vulndb.Advisory, seen map[string]bool) bool {
	cves := vulndb.CVEs(a)
	all := len(cves) > 0
	for _, c := range cves {
		key := group + "\x00" + c
		if !seen[key] {
			all = false
			seen[key] = true
		}
	}
	return all
}

// minorResults gives one line per source package, because a long-lived server
// can match hundreds of lesser advisories and each one alone rarely needs action.
func minorResults(items []collect.Installed, db vulndb.Snapshot, keep func(vulndb.Advisory) bool, label string) []check.Result {
	type tally struct {
		ids     []string
		version string
		matcher string
	}
	byName := map[string]*tally{}
	seen := map[string]bool{}
	for _, p := range items {
		group := p.Source
		if group == "" {
			group = p.Package
		}
		if p.Layer != "" {
			group = "layer " + p.Layer + ": " + group
		}
		for _, nv := range p.Names() {
			for _, m := range db.MatchStream(p.Ecosystem, nv[0], nv[1], p.Stream) {
				a := m.Advisory
				if !keep(a) {
					continue
				}
				if key := group + "\x00id\x00" + a.ID; seen[key] {
					continue
				} else {
					seen[key] = true
				}
				if repeatsKnownFlaw(group, a, seen) {
					continue
				}
				t := byName[group]
				if t == nil {
					t = &tally{version: nv[1], matcher: p.Matcher(m.Matcher)}
					byName[group] = t
				}
				t.ids = append(t.ids, a.ID)
			}
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]check.Result, 0, len(names))
	for _, n := range names {
		t := byName[n]
		sort.Strings(t.ids)
		shown := t.ids
		if len(shown) > 5 {
			shown = shown[:5]
		}
		out = append(out, check.FailR(n, fmt.Sprintf("%s %s: %d %s advisories, including %s", n, t.version, len(t.ids), label, strings.Join(shown, ", ")), "matcher: "+t.matcher, db.Notice()))
	}
	return out
}

func init() {
	for _, spec := range []struct {
		id, title string
		sev       check.Severity
		kev, age  bool
		cvss      string
		minor     bool
	}{
		// Representative vectors: a vulnerable package usually needs a reachable
		// code path (AC:H); a known exploited one is used in the wild (AC:L);
		// an outdated snapshot only hides information.
		{"HOST-CVE-001", "Installed OS Packages With Known Vulnerabilities", check.High, false, false, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", false},
		{"HOST-CVE-002", "Known Exploited Vulnerabilities Present", check.Critical, true, false, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", false},
		{"HOST-CVE-003", "Vulnerability Snapshot Outdated or Test Data", check.Low, false, true, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", false},
		{"HOST-CVE-004", "Installed OS Packages With Medium or Low Advisories", check.Low, false, false, "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", true},
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
			Summary:   "Checks installed packages against an offline vulnerability snapshot. HOST-CVE-001 lists High and Critical advisories one by one, HOST-CVE-002 known exploited ones, and HOST-CVE-004 sums up Medium and Low advisories per package.",
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
				if len(items) > 0 && !db.Covers(items[0].Ecosystem) {
					return []check.Result{check.IncompleteR("OS package inventory", "The snapshot has no advisories for "+items[0].Ecosystem, db.Notice())}
				}
				if x.minor {
					out := minorResults(items, db, func(a vulndb.Advisory) bool { return a.Severity == "medium" || a.Severity == "low" }, "Medium or Low")
					if len(out) == 0 {
						return []check.Result{check.PassR("OS package inventory", "No Medium or Low advisories match the embedded snapshot", db.Notice())}
					}
					return out
				}
				var out []check.Result
				seen := map[string]bool{}    // binaries of one source share one advisory
				seenCVE := map[string]bool{} // and sources repeat one flaw under several ids
				for _, p := range items {
					group := p.Source
					if group == "" {
						group = p.Package
					}
					for _, nv := range p.Names() {
						name, version := nv[0], nv[1]
						for _, m := range db.MatchStream(p.Ecosystem, name, version, p.Stream) {
							a := m.Advisory
							if x.kev && !a.KEV {
								continue
							}
							if !x.kev && a.Severity != "high" && a.Severity != "critical" {
								continue
							}
							if key := group + "\x00" + a.ID; seen[key] {
								continue
							} else {
								seen[key] = true
							}
							if repeatsKnownFlaw(group, a, seenCVE) {
								continue
							}
							fixed := vulndb.FixedVersion(a, p.Ecosystem, name, version)
							if fixed == "" {
								fixed = "not specified"
							}
							out = append(out, check.FailR(name, fmt.Sprintf("%s %s: %s (%s), fixed in %s, severity %s", name, version, a.ID, strings.Join(a.Aliases, ", "), fixed, a.Severity), "matcher: "+p.Matcher(m.Matcher), "installed package: "+p.Package, db.Notice()))
						}
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

func init() {
	check.Register(&check.Check{
		ID: "HOST-CVE-005", Title: "Container Image Layers With Known Vulnerabilities", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatPatch, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks package lists inside local Docker image layers against the offline vulnerability snapshot.",
		Rationale: "A patched host can still run containers built from old images, because host updates never reach them.",
		Detection: "Reads the dpkg and apk package databases inside Docker overlay2 layers, refusing a final symbolic link, and matches High, Critical and known exploited advisories. It reads layers, not running containers, and rpm image layers are not covered. A later layer may hold a newer version, so each finding is labelled heuristic. It reports Incomplete when a layer cannot be read or its distribution cannot be told.",
		Fix:       "Rebuild each image from an updated base image, redeploy it and remove the old image.",
		Verify:    "Re-run this check after removing the old images and confirm the layer is no longer listed.",
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
			items, found, complete := collect.LayerInventory(ctx, s)
			if !found {
				return []check.Result{check.SkipR("image layers", "No Docker image layer with a package database was found")}
			}
			covered := items[:0]
			for _, p := range items {
				if db.Covers(p.Ecosystem) {
					covered = append(covered, p)
				} else {
					complete = false
				}
			}
			out := minorResults(covered, db, func(a vulndb.Advisory) bool {
				return a.KEV || a.Severity == "high" || a.Severity == "critical"
			}, "High, Critical or known exploited")
			if !complete {
				out = append(out, check.IncompleteR("image layers", "Some image layers could not be read, placed in a distribution or matched to snapshot data", db.Notice()))
			}
			if len(out) == 0 {
				return []check.Result{check.PassR("image layers", "No matching advisories in the embedded snapshot", db.Notice())}
			}
			return out
		},
	})
}
