package host

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// eol maps "ID VERSION_ID" to the date standard (free) security support ends.
// Sources: each vendor's published lifecycle page, cited in the check refs.
// The table is dated; a release newer than this table may be missing, while a
// release older than the oldest row of its distribution is always past end of
// support and fails. Rows added on 2026-10-13: Fedora 42, Ubuntu 25.10 and
// 26.04 LTS, Ubuntu interim releases 20.10 to 23.04, CentOS Stream 9, RHEL,
// Rocky and AlmaLinux 10, Oracle Linux 7 to 9 and Amazon Linux 1. Also on
// 2026-10-13: Fedora 43 and 44 and CentOS Stream 10. Their dates are
// approximate, from the projects' published schedules as known on that date:
// Fedora ends support four weeks after the release two versions later, so
// Fedora 43 ends about 2026-12-09 and Fedora 44 about 2027-05 (both depend
// on the Fedora 45 and 46 release dates); CentOS Stream 10 is expected to end
// about 2030-01-01. Re-check these rows when the table is next refreshed.
var eol = map[string]string{
	"ubuntu 16.04": "2021-04-30", "ubuntu 18.04": "2023-05-31", "ubuntu 20.04": "2025-05-31",
	"ubuntu 20.10": "2021-07-22", "ubuntu 21.04": "2022-01-20", "ubuntu 21.10": "2022-07-14",
	"ubuntu 22.04": "2027-06-01", "ubuntu 22.10": "2023-07-20", "ubuntu 23.04": "2024-01-25",
	"ubuntu 23.10": "2024-07-11", "ubuntu 24.04": "2029-05-31", "ubuntu 24.10": "2025-07-10",
	"ubuntu 25.04": "2026-01-15", "ubuntu 25.10": "2026-07-09", "ubuntu 26.04": "2031-05-31",
	"debian 9": "2022-06-30", "debian 10": "2024-06-30", "debian 11": "2026-08-31", "debian 12": "2028-06-30", "debian 13": "2030-06-30",
	// CentOS Linux 7 and 8; CentOS Stream 9 reports ID centos as well.
	"centos 7": "2024-06-30", "centos 8": "2021-12-31", "centos 9": "2027-05-31", "centos 10": "2030-01-01",
	"rhel 7": "2024-06-30", "rhel 8": "2029-05-31", "rhel 9": "2032-05-31", "rhel 10": "2035-05-31",
	"rocky 8": "2029-05-31", "rocky 9": "2032-05-31", "rocky 10": "2035-05-31",
	"almalinux 8": "2029-03-01", "almalinux 9": "2032-05-31", "almalinux 10": "2035-05-31",
	"ol 7": "2024-12-31", "ol 8": "2029-07-31", "ol 9": "2032-06-30",
	"fedora 39": "2024-11-26", "fedora 40": "2025-05-13", "fedora 41": "2025-12-15", "fedora 42": "2026-05-13",
	"fedora 43": "2026-12-09", "fedora 44": "2027-05-19",
	"amzn 2018.03": "2023-12-31", "amzn 2": "2026-06-30", "amzn 2023": "2029-06-30",
}

// EOLTableDate is printed in reports so readers know how fresh the table is.
const EOLTableDate = "2026-10-13"

// eolWarnDays is how close to end of support a release starts to fail, so
// there is time to plan the upgrade.
const eolWarnDays = 90

// majorOnly lists distributions whose support depends on the major version.
var majorOnly = map[string]bool{"centos": true, "rhel": true, "rocky": true, "almalinux": true, "ol": true, "debian": true}

// osEOL looks up one release. It returns the end date, whether the release
// is past (or within eolWarnDays of) end of support, and whether the result
// is known. A release older than every row for its distribution is reported
// as past end of support without a date.
func osEOL(id, ver string, now time.Time) (end string, bad, known bool, daysLeft int) {
	if majorOnly[id] {
		ver = strings.SplitN(ver, ".", 2)[0]
	}
	if e, ok := eol[id+" "+ver]; ok {
		d, err := time.Parse("2006-01-02", e)
		if err != nil {
			return "", false, false, 0
		}
		left := d.Sub(now)
		return e, left < eolWarnDays*24*time.Hour, true, int(left.Hours() / 24)
	}
	// Amazon Linux 1 used year.month versions; 2018.03 was the last, so any
	// earlier one (2017.09, 2016.09, ...) is past end of support. Comparing
	// against the oldest row would fail here, because "2" sorts before them.
	if id == "amzn" && amznYear.MatchString(ver) && versionLess(ver, "2018.03") {
		return "", true, true, 0
	}
	oldest := ""
	for k := range eol {
		if rid, rv, _ := strings.Cut(k, " "); rid == id && (oldest == "" || versionLess(rv, oldest)) {
			oldest = rv
		}
	}
	if oldest != "" && ver != "" && versionLess(ver, oldest) {
		return "", true, true, 0
	}
	return "", false, false, 0
}

var amznYear = regexp.MustCompile(`^20[01][0-9]\.[0-9]{2}$`)

// versionLess compares dotted numeric versions ("16.04" < "18.04", "9" < "10").
// A non-numeric component makes the comparison false.
func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			n, err := strconv.Atoi(as[i])
			if err != nil {
				return false
			}
			x = n
		}
		if i < len(bs) {
			n, err := strconv.Atoi(bs[i])
			if err != nil {
				return false
			}
			y = n
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func init() {
	check.Register(&check.Check{
		ID:        "HOST-OS-001",
		Title:     "Operating System Past End of Security Support",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether the Linux distribution release still receives free security updates.",
		Rationale: "Once a release reaches end of life, newly discovered vulnerabilities are never fixed. Every later CVE in the kernel, OpenSSL or the web server stays open forever.",
		Detection: "Reads ID and VERSION_ID from /etc/os-release and looks them up in a dated table of free vendor security-support dates, including Debian LTS (table date " + EOLTableDate + "). Releases older than the oldest table row for their distribution fail. Releases within 90 days of end of life also fail, so there is time to plan the upgrade.",
		Fix:       "Plan an upgrade to a supported release (for example do-release-upgrade on Ubuntu, or a fresh install and migration). Paid extended support (Ubuntu Pro, RHEL ELS) is an alternative while migrating.",
		Verify:    "cat /etc/os-release  and compare with the vendor lifecycle page.",
		Refs: []check.Ref{
			{Title: "Ubuntu release cycle", URL: "https://ubuntu.com/about/release-cycle"},
			{Title: "Debian releases and LTS", URL: "https://wiki.debian.org/LTS"},
			{Title: "Red Hat Enterprise Linux life cycle", URL: "https://access.redhat.com/support/policy/updates/errata"},
			{Title: "endoflife.date (community-maintained lifecycle data)", URL: "https://endoflife.date/"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SA-22", "SI-2"}, CISTopic: "Supported operating system versions"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			osr := collect.OSRelease(s)
			id, ver := osr["ID"], osr["VERSION_ID"]
			if id == "" {
				return []check.Result{check.SkipR("os-release", "Distribution could not be identified")}
			}
			name := osr["PRETTY_NAME"]
			if name == "" {
				name = id + " " + ver
			}
			end, bad, known, left := osEOL(id, ver, time.Now())
			switch {
			case !known:
				return []check.Result{check.SkipR(name, "Release not in the end-of-life table (dated "+EOLTableDate+")")}
			case bad && end == "":
				return []check.Result{check.FailR(name, "Release is older than every supported release in the end-of-life table (dated "+EOLTableDate+"), so security support has ended")}
			case bad && left < 0:
				return []check.Result{check.FailR(name, "Security support ended on "+end)}
			case bad:
				return []check.Result{check.FailR(name, fmt.Sprintf("Security support ends on %s (in %d days, within the %d-day planning window)", end, left, eolWarnDays))}
			}
			return []check.Result{check.PassR(name, "Supported until "+end)}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-PKG-001",
		Title:     "Security Updates Waiting to Be Installed",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks the package manager for published security updates that are not installed yet.",
		Rationale: "Most real-world compromises use vulnerabilities for which a fix was already available. Pending security updates are known, public weaknesses.",
		Detection: "Runs the package manager in simulation mode only (apt-get -s upgrade, or dnf/yum updateinfo --security). Nothing is downloaded or installed. Lines that come from a security repository are counted.",
		Fix:       "Debian/Ubuntu: apt-get update && apt-get upgrade . RHEL family: dnf upgrade --security . Consider unattended-upgrades or dnf-automatic for security patches.",
		Verify:    "Re-run openvapt; this check should pass.",
		Refs: []check.Ref{
			{Title: "NIST SP 800-40 Rev. 4, Guide to Enterprise Patch Management Planning", URL: "https://csrc.nist.gov/pubs/sp/800/40/r4/final"},
			{Title: "Debian, UnattendedUpgrades", URL: "https://wiki.debian.org/UnattendedUpgrades"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}, CISTopic: "Patch management: install security updates"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if out, err := s.Run(ctx, "apt-get", "-s", "upgrade"); err == nil {
				var sec []string
				for _, line := range strings.Split(out, "\n") {
					if strings.HasPrefix(line, "Inst ") && strings.Contains(strings.ToLower(line), "security") {
						f := strings.Fields(line)
						if len(f) > 1 {
							sec = append(sec, f[1])
						}
					}
				}
				if len(sec) > 0 {
					return []check.Result{check.FailR("apt", fmt.Sprintf("%d security updates pending", len(sec)), firstN(sec, 30)...)}
				}
				return []check.Result{check.PassR("apt", "No pending security updates (based on the last apt-get update)")}
			}
			for _, cmd := range [][]string{{"dnf", "-q", "updateinfo", "list", "--security"}, {"yum", "-q", "updateinfo", "list", "security"}} {
				if out, err := s.Run(ctx, cmd[0], cmd[1:]...); err == nil {
					var sec []string
					for _, line := range strings.Split(out, "\n") {
						if f := strings.Fields(line); len(f) >= 3 {
							sec = append(sec, f[0]+" "+f[2])
						}
					}
					if len(sec) > 0 {
						return []check.Result{check.FailR(cmd[0], fmt.Sprintf("%d security advisories pending", len(sec)), firstN(sec, 30)...)}
					}
					return []check.Result{check.PassR(cmd[0], "No pending security advisories")}
				}
			}
			return []check.Result{check.SkipR("packages", "No supported package manager found (apt, dnf, yum)")}
		},
	})
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(in[:n:n], fmt.Sprintf("... and %d more", len(in)-n))
}
