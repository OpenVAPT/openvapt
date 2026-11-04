package host

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// HOST-PKG depth: how packages arrive and whether the running kernel is the
// one installed. HOST-PKG-001 (pending security updates), HOST-UPD-001
// (automatic security updates) and HOST-UPD-002 (Debian reboot marker) are
// not repeated. Repository files are read; apt-cache and dnf are not run.

var (
	refAptSecure  = check.Ref{Title: "apt-secure(8), Debian manual pages", URL: "https://manpages.debian.org/trixie/apt/apt-secure.8.en.html"}
	refDnfConf    = check.Ref{Title: "dnf.conf(5), Ubuntu noble manual pages (gpgcheck)", URL: "https://manpages.ubuntu.com/manpages/noble/en/man5/dnf.conf.5.html"}
	refNIST80040  = check.Ref{Title: "NIST SP 800-40 Rev. 4, Guide to Enterprise Patch Management Planning", URL: "https://csrc.nist.gov/pubs/sp/800/40/r4/final"}
	refSourcesLst = check.Ref{Title: "sources.list(5), Debian manual pages", URL: "https://manpages.debian.org/trixie/apt/sources.list.5.en.html"}
)

// vendorRepoSuffixes are host name suffixes of distribution repositories.
// Anything else is listed as third party. Matching is by suffix so regional
// mirrors (my.archive.ubuntu.com) count as vendor hosts.
var vendorRepoSuffixes = []string{
	".ubuntu.com", ".canonical.com", ".debian.org", ".debian.net",
	".fedoraproject.org", ".centos.org", ".redhat.com", ".rockylinux.org", ".almalinux.org",
	".oracle.com", ".amazonaws.com", ".opensuse.org", ".suse.com", ".raspbian.org", ".raspberrypi.org", ".raspberrypi.com",
}

func vendorRepoHost(h string) bool {
	h = strings.ToLower(h)
	for _, s := range vendorRepoSuffixes {
		if strings.HasSuffix(h, s) || h == strings.TrimPrefix(s, ".") {
			return true
		}
	}
	return false
}

// repoHost extracts the host of a repository URI, or "" for local or
// unparseable ones (file:, cdrom:, copy:).
func repoHost(uri string) string {
	u, err := url.Parse(strings.Trim(uri, `"'`))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// aptSourceURIs returns the URIs of one-line (deb ...) and Deb822 (URIs:)
// apt source files, with the option block of one-line entries.
type aptSource struct {
	URI, Options string
}

func aptSources(text string) []aptSource {
	var out []aptSource
	for _, l := range activeLines(text) {
		f := strings.Fields(l)
		switch {
		case len(f) >= 2 && (f[0] == "deb" || f[0] == "deb-src"):
			opts := ""
			rest := f[1:]
			if strings.HasPrefix(rest[0], "[") {
				// Collect "[ ... ]" which may span several fields.
				var o []string
				for len(rest) > 0 {
					o = append(o, rest[0])
					done := strings.HasSuffix(rest[0], "]")
					rest = rest[1:]
					if done {
						break
					}
				}
				opts = strings.Join(o, " ")
			}
			if len(rest) > 0 {
				out = append(out, aptSource{URI: rest[0], Options: opts})
			}
		case strings.HasPrefix(l, "URIs:"):
			for _, u := range strings.Fields(strings.TrimPrefix(l, "URIs:")) {
				out = append(out, aptSource{URI: u})
			}
		}
	}
	return out
}

// repoFiles are the package repository definitions the checks read.
var (
	aptSourceFiles = []string{"/etc/apt/sources.list", "/etc/apt/sources.list.d/*.list", "/etc/apt/sources.list.d/*.sources"}
	aptConfFiles   = []string{"/etc/apt/apt.conf", "/etc/apt/apt.conf.d/*"}
	yumRepoFiles   = []string{"/etc/yum.repos.d/*.repo", "/etc/dnf/dnf.conf", "/etc/yum.conf"}
)

// aptPresent reports whether this machine uses apt.
func aptPresent(s sys.System) bool {
	if exists(s, "/etc/apt") {
		return true
	}
	for _, pat := range []string{"/etc/apt/sources.list*", "/etc/apt/apt.conf.d/*", "/etc/apt/sources.list.d/*"} {
		if m, _ := s.Glob(pat); len(m) > 0 {
			return true
		}
	}
	return false
}

// dnfPresent reports whether this machine uses dnf or yum.
func dnfPresent(s sys.System) bool {
	if exists(s, "/etc/yum.repos.d") || exists(s, "/etc/dnf") || exists(s, "/etc/yum.conf") {
		return true
	}
	m, _ := s.Glob("/etc/yum.repos.d/*.repo")
	return len(m) > 0
}

func init() {
	check.Register(&check.Check{
		ID: "HOST-PKG-002", Title: "Repository Signature Checks Disabled", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatPatch, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks that the package manager verifies repository signatures, so a tampered mirror or intercepted download cannot install code as root.",
		Rationale: "Package installation runs as root. apt and dnf verify a signature over the repository index before trusting any package in it; an entry marked trusted=yes, AllowUnauthenticated or gpgcheck=0 switches that off, and a mirror operator or anyone on the network path can then deliver a modified package at the next update.",
		Detection: "apt: reads /etc/apt/sources.list, /etc/apt/sources.list.d/*.list (entries with [trusted=yes]) and *.sources (Trusted: yes), plus /etc/apt/apt.conf and /etc/apt/apt.conf.d/* for AllowUnauthenticated or AllowInsecureRepositories set to true. dnf and yum: reads /etc/yum.repos.d/*.repo, /etc/dnf/dnf.conf and /etc/yum.conf for gpgcheck=0 in any section. Skipped when no repository files exist; Incomplete when some exist but cannot be read.",
		Fix:       "Remove trusted=yes (or Trusted: yes) from the listed source, install the repository's signing key under /etc/apt/keyrings and reference it with signed-by=; remove AllowUnauthenticated and AllowInsecureRepositories settings. On dnf and yum set gpgcheck=1 (and repo_gpgcheck=1 where supported) in each listed repository and import its key with rpm --import.",
		Verify:    "grep -r 'trusted=yes' /etc/apt/ ; grep -r 'gpgcheck=0' /etc/yum.repos.d/ /etc/dnf/dnf.conf 2>/dev/null",
		Refs:      []check.Ref{refAptSecure, refDnfConf, refNIST80040},
		Standards: check.Standards{CWE: []string{"CWE-494", "CWE-347"}, OWASP: []string{"A08:2021"}, NIST: []string{"SI-7", "CM-14", "SR-3", "SR-11"}, CISTopic: "Package manager repositories and GPG keys are configured"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var bad []string
			seen := 0
			var unreadable []string
			src, u := readAll(ctx, s, aptSourceFiles...)
			unreadable = append(unreadable, u...)
			for _, f := range src {
				seen++
				for _, e := range aptSources(f.Text) {
					if strings.Contains(strings.ToLower(e.Options), "trusted=yes") {
						bad = append(bad, f.Path+": "+repoHostOrURI(e.URI)+" marked trusted=yes (signature check off)")
					}
				}
				for _, l := range activeLines(f.Text) {
					if strings.EqualFold(strings.Join(strings.Fields(l), " "), "Trusted: yes") {
						bad = append(bad, f.Path+": Trusted: yes (signature check off)")
					}
				}
			}
			conf, u := readAll(ctx, s, aptConfFiles...)
			unreadable = append(unreadable, u...)
			for _, f := range conf {
				for _, l := range activeLines(f.Text) {
					if strings.HasPrefix(l, "//") {
						continue
					}
					low := strings.ToLower(l)
					if (strings.Contains(low, "allowunauthenticated") || strings.Contains(low, "allowinsecurerepositories")) && strings.Contains(low, "true") {
						bad = append(bad, f.Path+": "+l)
					}
				}
			}
			repos, u := readAll(ctx, s, yumRepoFiles...)
			unreadable = append(unreadable, u...)
			for _, f := range repos {
				seen++
				var keys []string
				for k := range collect.ParseKV(f.Text) {
					if k == "gpgcheck" || strings.HasSuffix(k, ".gpgcheck") {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				vals := collect.ParseKV(f.Text)
				for _, k := range keys {
					if k == "gpgcheck" && len(keys) > 1 {
						continue // the unprefixed copy duplicates the section keys
					}
					for _, v := range vals[k] {
						if strings.TrimSpace(v) == "0" {
							bad = append(bad, f.Path+": "+k+"=0")
						}
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("package repositories", "Repository signature verification is disabled", bad...)}
			}
			if len(unreadable) > 0 {
				return []check.Result{check.IncompleteR("package repositories", "Some repository files could not be read", unreadable...)}
			}
			if seen == 0 {
				return []check.Result{check.SkipR("package repositories", "No apt or dnf repository files found")}
			}
			return []check.Result{check.PassR("package repositories", fmt.Sprintf("%d repository file(s) keep signature verification on", seen))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PKG-003", Title: "Third-Party Package Repositories Present", Domain: check.DomainHost,
		Severity: check.Info, Category: check.CatPatch, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
		Summary:   "Lists package repositories that are not run by the distribution vendor, so each one can be justified.",
		Rationale: "Every repository can install software as root at the next update, so each one is a supplier you trust completely. Personal package archives, vendor repositories and forgotten test repositories are a common way for unpatched or abandoned software to stay on a server. This is informational: a third-party repository is a decision to review, not a defect by itself.",
		Detection: "Reads /etc/apt/sources.list, /etc/apt/sources.list.d/*.list and *.sources, and /etc/yum.repos.d/*.repo (baseurl, mirrorlist, metalink), and lists repository host names that do not end in a known distribution domain (ubuntu.com, canonical.com, debian.org, fedoraproject.org, centos.org, redhat.com, rockylinux.org, almalinux.org, oracle.com, amazonaws.com, opensuse.org, suse.com, raspberrypi.com). Only host names are reported.",
		Fix:       "For each listed repository, record who runs it and why it is needed; remove the ones nobody can justify (delete the file under /etc/apt/sources.list.d or /etc/yum.repos.d and apt-get update or dnf clean all). Keep the rest pinned to the packages they are for (apt preferences, dnf includepkgs).",
		Verify:    "ls /etc/apt/sources.list.d/ /etc/yum.repos.d/ 2>/dev/null",
		Refs:      []check.Ref{refSourcesLst, refNIST80040, {Title: "NIST SP 800-161 Rev. 1, Cybersecurity Supply Chain Risk Management Practices", URL: "https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final"}},
		Standards: check.Standards{CWE: []string{"CWE-1357"}, OWASP: []string{"A08:2021"}, NIST: []string{"CM-8", "SR-3", "SR-4"}, CISTopic: "Software inventory: authorised repositories (CIS Controls v8 2.5)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			hosts := map[string]string{}
			var order []string
			add := func(path, h string) {
				if h == "" || vendorRepoHost(h) {
					return
				}
				if _, ok := hosts[h]; !ok {
					order = append(order, h)
					hosts[h] = path
				}
			}
			src, unreadable := readAll(ctx, s, aptSourceFiles...)
			for _, f := range src {
				for _, e := range aptSources(f.Text) {
					add(f.Path, repoHost(e.URI))
				}
			}
			repos, u := readAll(ctx, s, "/etc/yum.repos.d/*.repo")
			unreadable = append(unreadable, u...)
			for _, f := range repos {
				vals := collect.ParseKV(f.Text)
				for k, vs := range vals {
					if strings.HasSuffix(k, ".baseurl") || strings.HasSuffix(k, ".mirrorlist") || strings.HasSuffix(k, ".metalink") {
						for _, v := range vs {
							for _, uri := range strings.Fields(v) {
								add(f.Path, repoHost(uri))
							}
						}
					}
				}
			}
			if len(order) > 0 {
				sort.Strings(order)
				ev := make([]string, 0, len(order))
				for _, h := range order {
					ev = append(ev, h+" ("+hosts[h]+")")
				}
				return []check.Result{check.FailR("package repositories", fmt.Sprintf("%d third-party repository host(s) configured", len(order)), ev...)}
			}
			if len(unreadable) > 0 {
				return []check.Result{check.IncompleteR("package repositories", "Some repository files could not be read", unreadable...)}
			}
			if len(src)+len(repos) == 0 {
				return []check.Result{check.SkipR("package repositories", "No apt or dnf repository files found")}
			}
			return []check.Result{check.PassR("package repositories", "Only distribution vendor repositories are configured")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PKG-004", Title: "Many Old Kernels Retained", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatPatch, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks that no more than three kernel versions are installed.",
		Rationale: "Every installed kernel stays bootable from the boot menu, with every vulnerability it had. Old kernels also fill /boot until updates fail to install, which is a quiet way to stop receiving kernel patches. Keeping the running kernel plus one or two fallbacks is enough.",
		Detection: "Counts kernel versions among installed packages: linux-image-<version> packages whose /var/lib/dpkg/status entry reads 'install ok installed' on Debian and Ubuntu (the /var/lib/dpkg/info/*.list files are used only when the status file cannot be read, because removed but not purged packages keep them), kernel and kernel-core from the allow-listed rpm -qa on the RHEL family. More than three fails. Skipped when no kernel package is installed (containers); Incomplete when no package database could be read.",
		Fix:       "Debian/Ubuntu: apt-get autoremove --purge  removes kernels outside the keep list. RHEL family: set installonly_limit=3 in /etc/dnf/dnf.conf and run  dnf remove --oldinstallonly . Never remove the running kernel (uname -r).",
		Verify:    "dpkg -l 'linux-image-*' | grep '^ii'  or  rpm -q kernel kernel-core",
		Refs:      []check.Ref{refNIST80040, {Title: "apt-get(8), Debian trixie manual pages (autoremove)", URL: "https://manpages.debian.org/trixie/apt/apt-get.8.en.html"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "CM-7"}, CISTopic: "Remove unneeded software versions"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			pkgs, ok := installedPackages(ctx, s)
			if !ok {
				return []check.Result{check.IncompleteR("kernels", "No package database could be read (dpkg status, dpkg info or rpm)")}
			}
			vers := kernelVersions(pkgs)
			switch {
			case len(vers) == 0:
				return []check.Result{check.SkipR("kernels", "No kernel packages are installed (container or unusual packaging)")}
			case len(vers) > 3:
				return []check.Result{check.FailR("kernels", fmt.Sprintf("%d kernel versions installed (recommended at most 3)", len(vers)), vers...)}
			}
			return []check.Result{check.PassR("kernels", fmt.Sprintf("%d kernel version(s) installed", len(vers)), vers...)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PKG-005", Title: "Running Kernel Older Than Installed Kernel", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatPatch, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks that the kernel in memory is the newest kernel installed, so kernel security fixes are actually in effect.",
		Rationale: "A kernel update protects nothing until the machine boots into it. The package manager reports the update as installed, so the gap is invisible unless the running version is compared with the installed one. HOST-UPD-002 reads the Debian reboot marker; this check works on every distribution by comparing versions.",
		Detection: "Runs the allow-listed command uname -r and compares it with the installed kernel versions (linux-image-<version> packages, or kernel and kernel-core from rpm -qa). If the newest installed version is newer than the running one, the check fails. Incomplete when the running version or the package list cannot be read; skipped when no kernel package is installed.",
		Fix:       "Schedule a maintenance window and reboot into the newest kernel. Where downtime is a problem, use the distribution's live patching service and still plan regular reboots.",
		Verify:    "uname -r  should match the newest version in  dpkg -l 'linux-image-*' | grep ^ii  or  rpm -q kernel-core .",
		Refs:      []check.Ref{refNIST80040, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}, CISTopic: "Apply installed kernel updates (CIS Controls v8 7.4)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			out, err := s.Run(ctx, "uname", "-r")
			running := strings.TrimSpace(out)
			if err != nil || running == "" {
				return []check.Result{check.IncompleteR("kernel", "uname -r could not be run")}
			}
			pkgs, ok := installedPackages(ctx, s)
			if !ok {
				return []check.Result{check.IncompleteR("kernel", "No package database could be read (dpkg status, dpkg info or rpm)")}
			}
			vers := kernelVersions(pkgs)
			if len(vers) == 0 {
				return []check.Result{check.SkipR("kernel", "No kernel packages are installed (container or unusual packaging)")}
			}
			newest := vers[len(vers)-1]
			// RPM kernels report an architecture suffix in uname that the
			// package version lacks.
			cmp := running
			for _, arch := range []string{".x86_64", ".aarch64", ".ppc64le", ".s390x"} {
				cmp = strings.TrimSuffix(cmp, arch)
			}
			if kernelLess(cmp, newest) {
				return []check.Result{check.FailR("kernel", "Running kernel "+running+" is older than installed kernel "+newest+"; a reboot is needed")}
			}
			return []check.Result{check.PassR("kernel", "Running kernel "+running+" is the newest installed")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PKG-006", Title: "Package Lists Not Refreshed Automatically", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatPatch, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that the package manager downloads fresh repository metadata on a schedule, so pending updates can be seen at all.",
		Rationale: "apt and dnf only know about updates listed in the metadata they last downloaded. Without a timer that refreshes it, HOST-PKG-001 and the administrator's own apt list --upgradable both report a clean system that is weeks behind. The refresh is read-only and separate from installing anything.",
		Detection: "apt: reads /etc/apt/apt.conf.d/* for APT::Periodic::Update-Package-Lists \"1\" or asks the allow-listed systemctl is-enabled whether apt-daily.timer is enabled. dnf: asks whether dnf-makecache.timer is enabled. Skipped when neither package manager is present; Incomplete when apt configuration cannot be read.",
		Fix:       "Debian/Ubuntu: create /etc/apt/apt.conf.d/20auto-upgrades with  APT::Periodic::Update-Package-Lists \"1\";  (dpkg-reconfigure unattended-upgrades writes it) and  systemctl enable apt-daily.timer . RHEL family:  systemctl enable --now dnf-makecache.timer .",
		Verify:    "systemctl is-enabled apt-daily.timer  or  systemctl is-enabled dnf-makecache.timer",
		Refs:      []check.Ref{{Title: "Debian, UnattendedUpgrades (APT::Periodic settings)", URL: "https://wiki.debian.org/UnattendedUpgrades"}, refNIST80040},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "RA-5"}, CISTopic: "Automated patch management (CIS Controls v8 7.4)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			switch {
			case aptPresent(s):
				files, unreadable := readAll(ctx, s, aptConfFiles...)
				for _, f := range files {
					for _, l := range activeLines(f.Text) {
						if strings.HasPrefix(l, "//") {
							continue
						}
						if strings.Contains(l, "APT::Periodic::Update-Package-Lists") && strings.Contains(l, `"1"`) {
							return []check.Result{check.PassR(f.Path, "APT::Periodic::Update-Package-Lists is 1")}
						}
					}
				}
				if len(enabledUnits(ctx, s, "apt-daily.timer")) > 0 {
					return []check.Result{check.PassR("apt-daily.timer", "apt-daily.timer is enabled")}
				}
				if len(unreadable) > 0 {
					return []check.Result{check.IncompleteR("apt", "Some apt configuration could not be read", unreadable...)}
				}
				return []check.Result{check.FailR("apt", "Package lists are not refreshed automatically (no APT::Periodic::Update-Package-Lists and apt-daily.timer not enabled)")}
			case dnfPresent(s):
				if len(enabledUnits(ctx, s, "dnf-makecache.timer")) > 0 {
					return []check.Result{check.PassR("dnf-makecache.timer", "dnf-makecache.timer is enabled")}
				}
				return []check.Result{check.FailR("dnf", "dnf-makecache.timer is not enabled")}
			}
			return []check.Result{check.SkipR("packages", "No apt or dnf configuration found")}
		},
	})
}

// repoHostOrURI returns the host of a repository URI, or the URI itself for
// local sources, for use in evidence.
func repoHostOrURI(uri string) string {
	if h := repoHost(uri); h != "" {
		return h
	}
	return uri
}
