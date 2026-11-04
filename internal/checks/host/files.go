package host

import (
	"context"
	"fmt"
	"io/fs"
	"sort"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func perm(m fs.FileMode) string { return fmt.Sprintf("%04o", uint32(m.Perm())|specialBits(m)) }

func specialBits(m fs.FileMode) uint32 {
	var b uint32
	if m&fs.ModeSetuid != 0 {
		b |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		b |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		b |= 0o1000
	}
	return b
}

func init() {
	check.Register(&check.Check{
		ID:        "HOST-FS-001",
		Title:     "Sensitive Account Files Have Unsafe Permissions",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks that /etc/shadow and /etc/gshadow are not readable by others, and /etc/passwd and /etc/group are not writable by others.",
		Rationale: "Readable shadow files let any local user (or a compromised web app) copy password hashes and crack them offline. Writable passwd/group files let them create a root account.",
		Detection: "Stats each file without reading its contents and inspects the permission bits for 'other' and 'group' access.",
		Fix:       "chown root:root /etc/passwd /etc/group && chmod 644 /etc/passwd /etc/group ; chown root:shadow /etc/shadow /etc/gshadow && chmod 640 /etc/shadow /etc/gshadow  (use root:root and 000 on RHEL-family systems).",
		Verify:    "stat -c '%a %U:%G %n' /etc/passwd /etc/group /etc/shadow /etc/gshadow",
		Refs:      []check.Ref{{Title: "shadow(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/shadow.5.html"}, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-3", "AC-6"}, CISTopic: "File permissions: account database files"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			var out []check.Result
			for _, f := range []struct {
				path string
				bad  fs.FileMode
				why  string
			}{
				{"/etc/shadow", 0o004 | 0o002, "readable or writable by others"},
				{"/etc/gshadow", 0o004 | 0o002, "readable or writable by others"},
				{"/etc/passwd", 0o022, "writable by group or others"},
				{"/etc/group", 0o022, "writable by group or others"},
			} {
				st, err := s.Stat(f.path)
				if err != nil {
					continue
				}
				if st.Mode.Perm()&f.bad != 0 {
					out = append(out, check.FailR(f.path, f.path+" is "+f.why, "mode "+perm(st.Mode)))
				} else {
					out = append(out, check.PassR(f.path, f.path+" permissions are safe", "mode "+perm(st.Mode)))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("/etc", "Account files not found")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-FS-002",
		Title:     "Temporary Directory Missing the Sticky Bit",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
		Summary:   "Checks that world-writable temp directories have the sticky bit set.",
		Rationale: "Without the sticky bit any user can delete or replace other users' files in /tmp, enabling symlink attacks against root-run scripts.",
		Detection: "Stats /tmp and /var/tmp; world-writable without the sticky bit (mode 1777 expected) fails.",
		Fix:       "chmod 1777 /tmp /var/tmp",
		Verify:    "stat -c '%a %n' /tmp /var/tmp  should print 1777 for both.",
		Refs:      []check.Ref{{Title: "chmod(1), Linux man-pages (restricted deletion flag)", URL: "https://man7.org/linux/man-pages/man1/chmod.1.html"}},
		Standards: check.Standards{CWE: []string{"CWE-377", "CWE-732"}, NIST: []string{"AC-3"}, CISTopic: "Filesystem: sticky bit on world-writable directories"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			var out []check.Result
			for _, d := range []string{"/tmp", "/var/tmp"} {
				st, err := s.Stat(d)
				if err != nil {
					continue
				}
				if st.Mode.Perm()&0o002 != 0 && st.Mode&fs.ModeSticky == 0 {
					out = append(out, check.FailR(d, d+" is world-writable without the sticky bit", "mode "+perm(st.Mode)))
				} else {
					out = append(out, check.PassR(d, d+" is protected", "mode "+perm(st.Mode)))
				}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-FS-003",
		Title:     "World-Writable Files in System Configuration",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Looks for files under /etc and in cron directories that any user can modify.",
		Rationale: "A world-writable config or cron file lets any local user change how a root-owned service behaves, often leading straight to root.",
		Detection: "Walks /etc (metadata only, up to 20000 files, symlinks not followed) and lists regular files with the 'other write' bit set, plus directories up to three levels deep that are world-writable without the sticky bit (anyone could replace files inside them).",
		Fix:       "For each listed file or directory: chmod o-w <path>. Then find out how it became writable (a deployment script or a careless chmod 777).",
		Verify:    "find /etc -xdev \\( -type f -perm -0002 \\) -o \\( -type d -perm -0002 ! -perm -1000 \\)  should print nothing.",
		Refs:      []check.Ref{refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-3", "CM-6"}, CISTopic: "File permissions: no world-writable files"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			walk, err := s.Walk(ctx, "/etc", 20000)
			files := walk.Files
			if err != nil && len(files) == 0 {
				return []check.Result{check.ErrR("/etc", err)}
			}
			var bad []string
			for _, f := range files {
				if f.Mode.Perm()&0o002 != 0 {
					bad = append(bad, perm(f.Mode)+" "+f.Path)
				}
			}
			bad = append(bad, worldWritableDirs(s, "/etc", 3, 5000)...)
			if len(bad) > 0 {
				if len(bad) > 25 {
					bad = append(bad[:25], fmt.Sprintf("... and %d more", len(bad)-25))
				}
				return []check.Result{check.FailR("/etc", "World-writable files found", bad...)}
			}
			if !walk.Complete {
				return []check.Result{check.IncompleteR("/etc", fmt.Sprintf("Filesystem walk was partial after %d files", len(files)))}
			}
			return []check.Result{check.PassR("/etc", fmt.Sprintf("No world-writable files among %d checked", len(files)))}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-FS-004",
		Title:     "Unexpected SUID or SGID Programs",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Looks for set-user-ID or set-group-ID programs in places where packages do not normally install them.",
		Rationale: "A SUID program runs with its owner's rights (usually root). One placed in /tmp, /home, /var/www or /opt is a common persistence and privilege-escalation trick.",
		Detection: "Walks /tmp, /var/tmp, /dev/shm, /home, /var/www, /srv, /opt and /usr/local (metadata only) and lists files with the SUID or SGID bit.",
		Fix:       "Confirm whether each program is needed. Remove the bit with chmod u-s,g-s <file>, or delete the file if you did not put it there and investigate how it arrived.",
		Verify:    "find /tmp /home /var/www /opt /usr/local -xdev -perm /6000 -type f  should print nothing unexpected.",
		Refs:      []check.Ref{{Title: "MITRE ATT&CK T1548.001, Setuid and Setgid", URL: "https://attack.mitre.org/techniques/T1548/001/"}},
		Standards: check.Standards{CWE: []string{"CWE-250"}, NIST: []string{"CM-7", "AC-6"}, CISTopic: "Filesystem: audit SUID and SGID executables"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var bad []string
			complete := true
			for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/var/www", "/srv", "/opt", "/usr/local"} {
				walk, err := s.Walk(ctx, root, 20000)
				if err != nil || !walk.Complete {
					complete = false
				}
				for _, f := range walk.Files {
					if f.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
						bad = append(bad, perm(f.Mode)+" "+f.Path)
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("filesystem", "SUID/SGID programs outside standard system paths", bad...)}
			}
			if !complete {
				return []check.Result{check.IncompleteR("filesystem", "One or more filesystem walks were partial or unreadable")}
			}
			return []check.Result{check.PassR("filesystem", "No SUID/SGID programs in unusual locations")}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-FS-005",
		Title:     "Cron Files Writable by Non-Root Users",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks that system cron files and directories are owned by root and not writable by others.",
		Rationale: "Cron runs these jobs as root. Anyone who can edit them can run any command as root at the next scheduled minute.",
		Detection: "Stats /etc/crontab, /etc/cron.d and its files, and the cron.hourly/daily/weekly/monthly directories, flagging non-root owners or group/other write bits.",
		Fix:       "chown root:root <path> && chmod go-w <path>  for each listed path (600 for /etc/crontab is a common hardening choice).",
		Verify:    "stat -c '%a %U %n' /etc/crontab /etc/cron.*",
		Refs:      []check.Ref{{Title: "crontab(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/crontab.5.html"}, {Title: "MITRE ATT&CK T1053.003, Cron", URL: "https://attack.mitre.org/techniques/T1053/003/"}},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-3", "CM-6"}, CISTopic: "Job schedulers: cron permissions"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			paths := []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
			more, _ := s.Glob("/etc/cron.d/*")
			paths = append(paths, more...)
			var bad []string
			seen := 0
			for _, p := range paths {
				st, err := s.Stat(p)
				if err != nil {
					continue
				}
				seen++
				if (st.UID > 0) || st.Mode.Perm()&0o022 != 0 {
					bad = append(bad, fmt.Sprintf("%s uid=%d %s", perm(st.Mode), st.UID, p))
				}
			}
			if seen == 0 {
				return []check.Result{check.SkipR("cron", "No system cron files found")}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("cron", "Cron paths can be modified by non-root users", bad...)}
			}
			return []check.Result{check.PassR("cron", "Cron files are root-owned and not group/other writable")}
		},
	})
}

// worldWritableDirs lists directories under root, up to depth levels, that
// are writable by others and lack the sticky bit. Stat does not follow
// symlinks, so a symlink is never reported as a directory.
func worldWritableDirs(s sys.System, root string, depth, limit int) []string {
	var bad []string
	pat := root
	seen := 0
	for d := 0; d < depth; d++ {
		pat += "/*"
		paths, _ := s.Glob(pat)
		sort.Strings(paths)
		for _, p := range paths {
			if seen >= limit {
				return bad
			}
			st, err := s.Stat(p)
			if err != nil || !st.IsDir {
				continue
			}
			seen++
			if st.Mode.Perm()&0o002 != 0 && st.Mode&fs.ModeSticky == 0 {
				bad = append(bad, perm(st.Mode)+" "+p+"/ (directory, no sticky bit)")
			}
		}
	}
	return bad
}
