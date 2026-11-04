package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// Filesystem depth: mount layout and options, ownership, SUID inventory,
// boot files, cron access lists and shell umasks. Everything is metadata
// (/proc/mounts, stat) except the small text files named in each check.
//
// Sources: NIST SP 800-123, NIST SP 800-53 AC-6, CM-6 and CM-7, CIS
// Controls v8 safeguards 3.3 and 4.1 by id, Linux man-pages.

var (
	refMount8   = check.Ref{Title: "mount(8), Linux man-pages (nodev, nosuid, noexec)", URL: "https://man7.org/linux/man-pages/man8/mount.8.html"}
	refProcMnt  = check.Ref{Title: "proc(5), Linux man-pages (/proc/[pid]/mounts)", URL: "https://man7.org/linux/man-pages/man5/proc.5.html"}
	refATT1548  = check.Ref{Title: "MITRE ATT&CK T1548.001, Setuid and Setgid", URL: "https://attack.mitre.org/techniques/T1548/001/"}
	refCrontab1 = check.Ref{Title: "crontab(1), Linux man-pages (cron.allow and cron.deny)", URL: "https://man7.org/linux/man-pages/man1/crontab.1.html"}
	refAt1      = check.Ref{Title: "at(1), Linux man-pages (at.allow and at.deny)", URL: "https://man7.org/linux/man-pages/man1/at.1.html"}
	refUmask    = check.Ref{Title: "umask(2), Linux man-pages", URL: "https://man7.org/linux/man-pages/man2/umask.2.html"}
)

// mounts reads /proc/mounts into mount point -> options. ok is false when
// the file is missing, partial or unreadable.
func mounts(ctx context.Context, s sys.System) (map[string]string, bool) {
	text, complete, ok := readText(ctx, s, "/proc/mounts")
	if !ok || !complete {
		return nil, false
	}
	m := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			m[f[1]] = f[3]
		}
	}
	return m, true
}

func hasOpt(opts, want string) bool { return strings.Contains(","+opts+",", ","+want+",") }

// separateMountRule describes a path that should be its own filesystem.
type separateMountRule struct {
	id, title, summary, rationale, fix, cvss string
	sev                                      check.Severity
	paths                                    []string // any one of these as a separate mount satisfies the rule
	opts                                     []string // options that must then be present
	cwe                                      string
}

var separateMountRules = []separateMountRule{
	{
		id: "HOST-FS-010", title: "/var/tmp Not a Separate Filesystem", sev: check.Low,
		cvss:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L",
		summary:   "Checks that /var/tmp is its own mount (or a bind mount of /tmp) with nodev, nosuid and noexec.",
		rationale: "/var/tmp is world-writable and survives reboots. On the root filesystem it can be filled to exhaust disk space, and it accepts planted device files and executables unless mounted with restricting options.",
		fix:       "Mount /var/tmp as a separate filesystem, or bind-mount it onto /tmp:  /tmp /var/tmp none bind,nodev,nosuid,noexec 0 0  in /etc/fstab, then reboot or remount. Caution: /var/tmp is meant to survive reboots and some installers and databases run programs from it, so check what uses it before binding it to /tmp with noexec, and keep console access when editing /etc/fstab (a wrong line can stop the boot).",
		paths:     []string{"/var/tmp"}, opts: []string{"nodev", "nosuid", "noexec"}, cwe: "CWE-276",
	},
	{
		id: "HOST-FS-011", title: "/home Not a Separate Filesystem With nodev", sev: check.Low,
		cvss:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L",
		summary:   "Checks that user home directories live on their own mount with nodev (and nosuid where practical).",
		rationale: "Users control the contents of /home. A separate mount stops a user filling the root filesystem, and nodev stops device files being created in a home directory to reach raw disks or memory.",
		fix:       "Place /home on its own partition or logical volume and add nodev,nosuid to its options in /etc/fstab; remount with: mount -o remount /home . Caution: moving /home to a new volume needs a backup, a maintenance window and console access; a wrong /etc/fstab line can stop the boot.",
		paths:     []string{"/home"}, opts: []string{"nodev"}, cwe: "CWE-276",
	},
	{
		id: "HOST-FS-012", title: "Log Directories on the Root Filesystem", sev: check.Low,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",
		summary:   "Checks that /var/log (or /var) is a separate filesystem so runaway logging cannot fill the root disk.",
		rationale: "Logs grow under attacker influence (failed logins, scanner noise). When they share the root filesystem, filling them stops the whole server, and when the disk is full new security events are lost.",
		fix:       "Place /var/log (and ideally /var/log/audit) on its own partition or logical volume, listed in /etc/fstab with nodev,nosuid,noexec. Caution: moving log directories needs a backup, a maintenance window and console access; stop the logging services while copying, and a wrong /etc/fstab line can stop the boot.",
		paths:     []string{"/var/log", "/var"}, opts: nil, cwe: "CWE-770",
	},
}

func init() {
	for _, r := range separateMountRules {
		r := r
		check.Register(&check.Check{
			ID: r.id, Title: r.title, Domain: check.DomainHost, Severity: r.sev, Category: check.CatConfig, Effort: check.EffortMedium, CVSS: r.cvss,
			Summary: r.summary, Rationale: r.rationale,
			Detection: "Reads /proc/mounts (no command is run) and looks for a mount entry for " + strings.Join(r.paths, " or ") + mountOptsText(r.opts) + ". Unreadable or partial /proc/mounts is reported as incomplete.",
			Fix:       r.fix,
			Verify:    "findmnt -no TARGET,OPTIONS " + strings.Join(r.paths, " "),
			Refs:      []check.Ref{refMount8, refProcMnt, refNIST800123},
			Standards: check.Standards{CWE: []string{r.cwe}, NIST: []string{"CM-6", "CM-7", "SC-5"}, CISTopic: "Separate partitions and mount options (CIS Controls v8 4.1)"},
			Run: func(ctx context.Context, s sys.System) []check.Result {
				m, ok := mounts(ctx, s)
				if !ok {
					return []check.Result{check.IncompleteR("/proc/mounts", "Mount table could not be read")}
				}
				for _, p := range r.paths {
					o, found := m[p]
					if !found {
						continue
					}
					var miss []string
					for _, need := range r.opts {
						if !hasOpt(o, need) {
							miss = append(miss, need)
						}
					}
					if len(miss) > 0 {
						return []check.Result{check.FailR(p, p+" is a separate mount but lacks "+strings.Join(miss, ", "), "options "+o)}
					}
					return []check.Result{check.PassR(p, p+" is a separate mount", "options "+o)}
				}
				return []check.Result{check.FailR(r.paths[0], r.paths[0]+" is not a separate filesystem (it lives on the root filesystem)")}
			},
		})
	}

	check.Register(&check.Check{
		ID: "HOST-FS-013", Title: "Temporary Filesystems Allow Executables", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks that /tmp, /var/tmp and /dev/shm, where they are separate mounts, carry the noexec option.",
		Rationale: "Attackers who gain a foothold download tools into a world-writable temporary directory and run them from there. noexec makes that step fail and forces noisier workarounds.",
		Detection: "Reads /proc/mounts. Each of /tmp, /var/tmp and /dev/shm that appears as a mount must include noexec; paths that are not separate mounts are skipped (HOST-FS-008 covers nodev and nosuid, HOST-FS-010 covers /var/tmp as a mount).",
		Fix:       "Add noexec to the mount options of each temporary filesystem (systemd tmp.mount drop-in or /etc/fstab) and remount. Some package managers need exec on /tmp during installs; set TMPDIR for them rather than removing noexec.",
		Verify:    "findmnt -no TARGET,OPTIONS /tmp /var/tmp /dev/shm",
		Refs:      []check.Ref{refMount8, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-276"}, NIST: []string{"CM-6", "CM-7"}, CISTopic: "noexec on temporary filesystems (CIS Controls v8 4.1)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			m, ok := mounts(ctx, s)
			if !ok {
				return []check.Result{check.IncompleteR("/proc/mounts", "Mount table could not be read")}
			}
			var out []check.Result
			for _, mp := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
				o, found := m[mp]
				if !found {
					continue
				}
				if hasOpt(o, "noexec") {
					out = append(out, check.PassR(mp, mp+" is mounted noexec", "options "+o))
				} else {
					out = append(out, check.FailR(mp, mp+" allows executables", "options "+o))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("/proc/mounts", "Temporary directories are not separate mounts")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-014", Title: "World-Writable Files Outside Temporary Directories", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
		Summary:   "Looks for files that any user can modify in program, service and home locations other than /etc (which HOST-FS-003 covers).",
		Rationale: "A world-writable script, binary or data file lets any local account, including a compromised web application, change what other users and services run or read.",
		Detection: "Walks /usr/local, /opt, /srv, /var/www, /home, /root, /usr/bin and /usr/sbin (metadata only, up to 20000 files per tree, symlinks not followed) and lists regular files with the 'other write' bit set.",
		Fix:       "For each listed file: chmod o-w <path>. Then find the deployment step or chmod 777 habit that created it.",
		Verify:    "find /usr/local /opt /srv /var/www /home /usr/bin /usr/sbin -xdev -type f -perm -0002  should print nothing.",
		Refs:      []check.Ref{refNIST800123, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-3", "AC-6", "CM-6"}, CISTopic: "No world-writable files (CIS Controls v8 3.3)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var bad []string
			total, complete, seen := 0, true, false
			for _, root := range []string{"/usr/local", "/opt", "/srv", "/var/www", "/home", "/root", "/usr/bin", "/usr/sbin"} {
				w, err := s.Walk(ctx, root, 20000)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						complete = false
					}
					continue
				}
				seen = true
				if !w.Complete {
					complete = false
				}
				total += len(w.Files)
				for _, f := range w.Files {
					if f.Mode.Perm()&0o002 != 0 {
						bad = append(bad, perm(f.Mode)+" "+f.Path)
					}
				}
			}
			sort.Strings(bad)
			if len(bad) > 0 {
				if len(bad) > 25 {
					bad = append(bad[:25], fmt.Sprintf("... and %d more", len(bad)-25))
				}
				return []check.Result{check.FailR("filesystem", fmt.Sprintf("%d world-writable file(s) found", len(bad)), bad...)}
			}
			if !seen || !complete {
				return []check.Result{check.IncompleteR("filesystem", fmt.Sprintf("Filesystem walk was partial after %d files", total))}
			}
			return []check.Result{check.PassR("filesystem", fmt.Sprintf("No world-writable files among %d checked", total))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-015", Title: "Files With No Known Owner or Group", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Looks for files whose owner or group id no longer appears in /etc/passwd or /etc/group.",
		Rationale: "When an account is deleted, its files keep the numeric id. The next account created with that id silently inherits them, which can hand a new user old keys, scripts or cron jobs.",
		Detection: "Reads the numeric ids from /etc/passwd and /etc/group, then walks /etc, /usr/local, /opt, /srv, /var/www, /home and /root (metadata only, up to 20000 files per tree, symlinks not followed) and lists files whose uid or gid is unknown. Unreadable account files make the check incomplete.",
		Fix:       "Decide who should own each listed file and apply  chown <user>:<group> <path>, or remove files that belonged to a deleted account after checking their contents.",
		Verify:    "find /etc /usr/local /opt /srv /var/www /home -xdev \\( -nouser -o -nogroup \\)  should print nothing.",
		Refs:      []check.Ref{refNIST800123, {Title: "passwd(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/passwd.5.html"}},
		Standards: check.Standards{CWE: []string{"CWE-282"}, NIST: []string{"AC-2", "AC-6", "CM-6"}, CISTopic: "No unowned or ungrouped files (CIS Controls v8 3.3)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			uids, ok1 := idSet(ctx, s, "/etc/passwd", 2)
			gids, ok2 := idSet(ctx, s, "/etc/group", 2)
			if !ok1 || !ok2 {
				return []check.Result{check.IncompleteR("/etc/passwd", "Account or group database could not be read")}
			}
			var bad []string
			total, complete, seen := 0, true, false
			for _, root := range []string{"/etc", "/usr/local", "/opt", "/srv", "/var/www", "/home", "/root"} {
				w, err := s.Walk(ctx, root, 20000)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						complete = false
					}
					continue
				}
				seen = true
				if !w.Complete {
					complete = false
				}
				total += len(w.Files)
				for _, f := range w.Files {
					switch {
					case !uids[f.UID] && !gids[f.GID]:
						bad = append(bad, fmt.Sprintf("uid=%d gid=%d %s (no such user or group)", f.UID, f.GID, f.Path))
					case !uids[f.UID]:
						bad = append(bad, fmt.Sprintf("uid=%d %s (no such user)", f.UID, f.Path))
					case !gids[f.GID]:
						bad = append(bad, fmt.Sprintf("gid=%d %s (no such group)", f.GID, f.Path))
					}
				}
			}
			sort.Strings(bad)
			if len(bad) > 0 {
				if len(bad) > 25 {
					bad = append(bad[:25], fmt.Sprintf("... and %d more", len(bad)-25))
				}
				return []check.Result{check.FailR("filesystem", fmt.Sprintf("%d file(s) have an unknown owner or group", len(bad)), bad...)}
			}
			if !seen || !complete {
				return []check.Result{check.IncompleteR("filesystem", fmt.Sprintf("Filesystem walk was partial after %d files", total))}
			}
			return []check.Result{check.PassR("filesystem", fmt.Sprintf("Every one of %d files has a known owner and group", total))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-016", Title: "SUID or SGID Programs Outside the Known Baseline", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatAccess, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Lists set-user-ID and set-group-ID programs in the system binary directories that are not on the documented baseline of what distributions ship.",
		Rationale: "Every SUID program is a door into another account, usually root. Programs such as nmap, vim, find, python or a custom helper with the SUID bit are a known route to instant root; the fewer unexplained SUID programs, the smaller that door.",
		Detection: "Walks /bin, /sbin, /usr/bin, /usr/sbin, /usr/libexec and /usr/lib (metadata only, up to 20000 files per tree, symlinks not followed), keeps files with the SUID or SGID bit, and reports those whose file name is not in the baseline list kept in this check's source (passwd, sudo, su, mount, ping, ssh-keysign and about forty others). An empty inventory is reported as incomplete.",
		Fix:       "For each listed program decide whether the bit is needed. Remove it with  chmod u-s,g-s <path>  or uninstall the package. Record the ones you keep so the next review is quick. Caution: programs such as passwd, sudo, su, mount and ping need their bit to work for normal users; removing it from those breaks password changes and administrator access.",
		Verify:    "find /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/lib -xdev -type f -perm /6000  and compare with your record.",
		Refs:      []check.Ref{refATT1548, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-250"}, NIST: []string{"AC-6", "CM-7"}, CISTopic: "Audit SUID and SGID executables (CIS Controls v8 4.1)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var unknown, known []string
			complete := true
			for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib"} {
				w, err := s.Walk(ctx, root, 20000)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						complete = false
					}
					continue
				}
				if !w.Complete {
					complete = false
				}
				for _, f := range w.Files {
					if f.Mode&(fs.ModeSetuid|fs.ModeSetgid) == 0 {
						continue
					}
					if suidBaseline[path.Base(f.Path)] {
						known = append(known, f.Path)
					} else {
						unknown = append(unknown, perm(f.Mode)+" "+f.Path)
					}
				}
			}
			sort.Strings(unknown)
			if len(unknown) > 0 {
				if len(unknown) > 25 {
					unknown = append(unknown[:25], fmt.Sprintf("... and %d more", len(unknown)-25))
				}
				return []check.Result{check.FailR("filesystem", fmt.Sprintf("%d SUID/SGID program(s) are not on the baseline", len(unknown)), unknown...)}
			}
			if !complete || len(known) == 0 {
				return []check.Result{check.IncompleteR("filesystem", "SUID/SGID inventory was partial or empty")}
			}
			return []check.Result{check.PassR("filesystem", fmt.Sprintf("All %d SUID/SGID programs are on the baseline", len(known)))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-017", Title: "World-Writable Directories Without the Sticky Bit", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
		Summary:   "Looks for shared writable directories outside /tmp and /etc that let any user delete or replace other users' files.",
		Rationale: "In a world-writable directory without the sticky bit, any user can remove or swap a file placed there by another user or by a service, which turns upload folders and spool directories into file-replacement attacks.",
		Detection: "Lists directories up to three levels below /var, /home, /opt, /srv and /usr/local (metadata only, at most 5000 per tree, symlinks never treated as directories) and reports those writable by others without the sticky bit. HOST-FS-002 covers /tmp and /var/tmp; HOST-FS-003 covers /etc.",
		Fix:       "chmod +t <dir>  for directories that must stay shared, or  chmod o-w <dir>  for those that should not be writable by everyone.",
		Verify:    "find /var /home /opt /srv /usr/local -xdev -type d -perm -0002 ! -perm -1000  should print nothing.",
		Refs:      []check.Ref{{Title: "chmod(1), Linux man-pages (restricted deletion flag)", URL: "https://man7.org/linux/man-pages/man1/chmod.1.html"}, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-377"}, NIST: []string{"AC-3", "CM-6"}, CISTopic: "Sticky bit on world-writable directories (CIS Controls v8 3.3)"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			var bad []string
			seen := 0
			for _, root := range []string{"/var", "/home", "/opt", "/srv", "/usr/local"} {
				b, n := worldWritableDirsCount(s, root, 3, 5000)
				bad = append(bad, b...)
				seen += n
			}
			sort.Strings(bad)
			if len(bad) > 0 {
				if len(bad) > 25 {
					bad = append(bad[:25], fmt.Sprintf("... and %d more", len(bad)-25))
				}
				return []check.Result{check.FailR("filesystem", fmt.Sprintf("%d shared directory(ies) lack the sticky bit", len(bad)), bad...)}
			}
			if seen == 0 {
				return []check.Result{check.IncompleteR("filesystem", "No directories could be listed")}
			}
			return []check.Result{check.PassR("filesystem", fmt.Sprintf("No world-writable directories without the sticky bit among %d checked", seen))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-018", Title: "Kernel Symbol Map or Initial RAM Disk Readable by Others", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that /boot/System.map-* and the initial RAM disk images are not readable by every user.",
		Rationale: "System.map lists every kernel symbol address, which defeats kptr_restrict and helps kernel exploits. An initial RAM disk can embed network credentials, disk-unlock key files or custom scripts that should not be world-readable.",
		Detection: "Stats /boot/System.map-*, /boot/initrd.img-*, /boot/initramfs-*.img and /boot/initrd-* (metadata only) and fails if any is readable by others. Skipped when none exist (for example inside a container).",
		Fix:       "chmod 600 /boot/System.map-* /boot/initrd* /boot/initramfs*  and, on Debian family systems, set  UMASK=0077  in /etc/initramfs-tools/initramfs.conf so new images are created private.",
		Verify:    "stat -c '%a %n' /boot/System.map-* /boot/initrd*",
		Refs:      []check.Ref{refKernelDocs, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-497", "CWE-732"}, NIST: []string{"AC-3", "AC-6"}, CISTopic: "Boot file permissions (CIS Controls v8 3.3)"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			var bad []string
			seen := 0
			for _, pat := range []string{"/boot/System.map-*", "/boot/initrd.img-*", "/boot/initramfs-*.img", "/boot/initrd-*"} {
				paths, _ := s.Glob(pat)
				sort.Strings(paths)
				for _, p := range paths {
					st, err := s.Stat(p)
					if err != nil || st.IsDir {
						continue
					}
					seen++
					if st.Mode.Perm()&0o004 != 0 {
						bad = append(bad, perm(st.Mode)+" "+p)
					}
				}
			}
			if seen == 0 {
				return []check.Result{check.SkipR("/boot", "No kernel symbol map or initial RAM disk found")}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/boot", fmt.Sprintf("%d boot file(s) are readable by others", len(bad)), bad...)}
			}
			return []check.Result{check.PassR("/boot", fmt.Sprintf("%d boot file(s) are private to root", seen))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-019", Title: "Cron and At Not Restricted to Allowed Users", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks that cron.allow and at.allow exist, are private to root, and that the deny lists are not relied upon instead.",
		Rationale: "By default every local account may schedule jobs. A deny list only names known accounts; an allow list says exactly who may schedule, which is what least privilege asks for and what makes persistence by a compromised service account harder.",
		Detection: "Stats /etc/cron.allow and /etc/at.allow (metadata only). For each scheduler that is installed (/etc/crontab or /etc/cron.d for cron, /etc/at.deny, /etc/at.allow or /var/spool/at for at), a missing allow file, an allow file not owned by root, or one readable or writable by group or others fails. A deny file present without an allow file is reported.",
		Fix:       "Create the allow lists:  touch /etc/cron.allow /etc/at.allow && chmod 600 /etc/cron.allow /etc/at.allow && chown root:root /etc/cron.allow /etc/at.allow  then add one user name per line for the accounts that need scheduling, and remove /etc/cron.deny and /etc/at.deny. Caution: once cron.allow exists, crontabs of users not listed stop running, so list every service and user account that has a crontab (ls /var/spool/cron/crontabs or /var/spool/cron) before creating it.",
		Verify:    "stat -c '%a %U %n' /etc/cron.allow /etc/at.allow; ls /etc/cron.deny /etc/at.deny 2>&1",
		Refs:      []check.Ref{refCrontab1, refAt1, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-862"}, NIST: []string{"AC-6", "CM-7"}, CISTopic: "Restrict cron and at to authorised users (CIS Controls v8 4.1)"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			var out []check.Result
			for _, sch := range []struct {
				name, allow, deny string
				present           []string
			}{
				{"cron", "/etc/cron.allow", "/etc/cron.deny", []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/var/spool/cron"}},
				{"at", "/etc/at.allow", "/etc/at.deny", []string{"/etc/at.deny", "/etc/at.allow", "/var/spool/at", "/var/spool/cron/atjobs", "/usr/bin/at"}},
			} {
				installed := false
				for _, p := range sch.present {
					if _, err := s.Stat(p); err == nil {
						installed = true
						break
					}
				}
				if !installed {
					continue
				}
				_, denyErr := s.Stat(sch.deny)
				st, err := s.Stat(sch.allow)
				switch {
				case errors.Is(err, fs.ErrNotExist):
					msg := sch.allow + " does not exist, so every user may schedule " + sch.name + " jobs"
					if denyErr == nil {
						msg = sch.allow + " does not exist; only " + sch.deny + " limits who may schedule " + sch.name + " jobs"
					}
					out = append(out, check.FailR(sch.allow, msg))
				case err != nil:
					out = append(out, check.IncompleteR(sch.allow, "Could not stat "+sch.allow))
				case st.UID != 0 || st.Mode.Perm()&0o077 != 0:
					out = append(out, check.FailR(sch.allow, sch.allow+" is not private to root", fmt.Sprintf("mode %s uid=%d", perm(st.Mode), st.UID)))
				default:
					ev := []string{"mode " + perm(st.Mode)}
					if denyErr == nil {
						ev = append(ev, sch.deny+" also exists (ignored when the allow file is present)")
					}
					out = append(out, check.PassR(sch.allow, sch.allow+" restricts "+sch.name+" to listed users", ev...))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("cron", "Neither cron nor at is installed")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-020", Title: "Cron Configuration Readable by Other Users", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that /etc/crontab is mode 600 and the cron.d, cron.hourly, cron.daily, cron.weekly and cron.monthly directories are mode 700, all owned by root.",
		Rationale: "Readable cron configuration tells a local attacker exactly which scripts root runs and when, which is the reconnaissance step before replacing one of them. HOST-FS-005 stops writing; this check stops reading.",
		Detection: "Stats /etc/crontab and the five cron directories (metadata only). Any group or other permission bit, or a non-root owner, fails. Paths that do not exist are skipped.",
		Fix:       "chown root:root /etc/crontab /etc/cron.* && chmod 600 /etc/crontab && chmod 700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly",
		Verify:    "stat -c '%a %U %n' /etc/crontab /etc/cron.*",
		Refs:      []check.Ref{{Title: "crontab(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/crontab.5.html"}, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-3", "AC-6"}, CISTopic: "Cron file permissions (CIS Controls v8 3.3)"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			var bad []string
			seen := 0
			for _, p := range []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
				st, err := s.Stat(p)
				if err != nil {
					continue
				}
				seen++
				if st.UID != 0 || st.Mode.Perm()&0o077 != 0 {
					bad = append(bad, fmt.Sprintf("%s uid=%d %s", perm(st.Mode), st.UID, p))
				}
			}
			if seen == 0 {
				return []check.Result{check.SkipR("cron", "No system cron files found")}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("cron", fmt.Sprintf("%d cron path(s) are readable by group or others", len(bad)), bad...)}
			}
			return []check.Result{check.PassR("cron", fmt.Sprintf("%d cron path(s) are private to root", seen))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-021", Title: "Shell Profile Sets a Permissive File Creation Mask", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that system-wide shell start-up files do not set a umask that leaves new files readable by every user.",
		Rationale: "A umask line in /etc/profile or /etc/bash.bashrc overrides the login.defs default for every interactive shell. Many distributions still ship  umask 022  there, which makes every file an administrator creates readable by all local accounts.",
		Detection: "Reads /etc/profile, /etc/bash.bashrc, /etc/bashrc, /etc/zsh/zshrc and /etc/profile.d/*.sh and finds lines of the form  umask NNN. A value that leaves the 'other' read bit open (022, 002, 000) fails; 027 or stricter passes. Files that exist but could not be read fully make the check incomplete; when no shell file sets a umask the check is skipped (HOST-FS-009 covers login.defs).",
		Fix:       "Change every  umask 022  line in the listed files to  umask 027, or remove the line so the login.defs value applies. Users start a new login shell to pick it up.",
		Verify:    "grep -rn '^[[:space:]]*umask' /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/ 2>/dev/null",
		Refs:      []check.Ref{refUmask, refLoginDefs},
		Standards: check.Standards{CWE: []string{"CWE-276"}, NIST: []string{"AC-6", "CM-6"}, CISTopic: "Default user umask in shell start-up files (CIS Controls v8 3.3)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			paths := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc"}
			more, _ := s.Glob("/etc/profile.d/*.sh")
			sort.Strings(more)
			paths = append(paths, more...)
			var bad, good []string
			partial := false
			for _, p := range paths {
				r, err := s.ReadFile(ctx, p)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						partial = true
					}
					continue
				}
				if !r.Complete {
					partial = true
				}
				for _, m := range umaskLine.FindAllStringSubmatch(string(r.Data), -1) {
					n, err := strconv.ParseUint(m[1], 8, 32)
					if err != nil {
						continue
					}
					if n&0o004 == 0 {
						bad = append(bad, p+": umask "+m[1])
					} else {
						good = append(good, p+": umask "+m[1])
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/etc/profile", fmt.Sprintf("%d shell file(s) set a umask that lets other users read new files", len(bad)), bad...)}
			}
			if partial {
				return []check.Result{check.IncompleteR("/etc/profile", "One or more shell start-up files could not be read fully")}
			}
			if len(good) == 0 {
				return []check.Result{check.SkipR("/etc/profile", "No umask is set in the shell start-up files; /etc/login.defs applies")}
			}
			return []check.Result{check.PassR("/etc/profile", "Shell start-up files set a restrictive umask", good...)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-022", Title: "Account Database Files or Their Backups Not Owned and Locked by Root", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks the owner and permissions of /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow and their dash-suffixed backup copies.",
		Rationale: "The tools that edit accounts leave a backup copy (passwd-, shadow-) next to the live file. A readable shadow- backup leaks the same password hashes as shadow itself, and a file not owned by root can be rewritten by whoever owns it. HOST-FS-001 checks the mode of the live files; this check adds ownership and the backups.",
		Detection: "Stats the eight files (metadata only). passwd, group and their backups must be owned by uid 0 and not writable by group or others; shadow, gshadow and their backups must be owned by uid 0 and have no permission bits for others. Files that do not exist are skipped; none existing is reported as incomplete.",
		Fix:       "chown root:root /etc/passwd /etc/passwd- /etc/group /etc/group- && chmod 644 /etc/passwd /etc/group && chmod 600 /etc/passwd- /etc/group- ; chown root:shadow /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- && chmod 640 /etc/shadow /etc/gshadow && chmod 600 /etc/shadow- /etc/gshadow-  (use root:root and mode 000 on RHEL family systems).",
		Verify:    "stat -c '%a %U:%G %n' /etc/passwd* /etc/group* /etc/shadow* /etc/gshadow*",
		Refs:      []check.Ref{{Title: "shadow(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/shadow.5.html"}, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-522"}, NIST: []string{"AC-3", "AC-6", "IA-5"}, CISTopic: "Account database file ownership and permissions (CIS Controls v8 3.3)"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			var bad []string
			seen := 0
			for _, f := range []struct {
				path string
				bad  fs.FileMode
				why  string
			}{
				{"/etc/passwd", 0o022, "writable by group or others"}, {"/etc/passwd-", 0o022, "writable by group or others"},
				{"/etc/group", 0o022, "writable by group or others"}, {"/etc/group-", 0o022, "writable by group or others"},
				{"/etc/shadow", 0o007, "accessible by others"}, {"/etc/shadow-", 0o007, "accessible by others"},
				{"/etc/gshadow", 0o007, "accessible by others"}, {"/etc/gshadow-", 0o007, "accessible by others"},
			} {
				st, err := s.Stat(f.path)
				if err != nil {
					continue
				}
				seen++
				switch {
				case st.UID != 0:
					bad = append(bad, fmt.Sprintf("%s uid=%d %s (not owned by root)", perm(st.Mode), st.UID, f.path))
				case st.Mode.Perm()&f.bad != 0:
					bad = append(bad, fmt.Sprintf("%s %s (%s)", perm(st.Mode), f.path, f.why))
				}
			}
			if seen == 0 {
				return []check.Result{check.IncompleteR("/etc/passwd", "No account database files could be stat'ed")}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/etc/passwd", fmt.Sprintf("%d account file(s) have an unsafe owner or mode", len(bad)), bad...)}
			}
			return []check.Result{check.PassR("/etc/passwd", fmt.Sprintf("%d account file(s) are root-owned with the expected modes", seen))}
		},
	})
}

var umaskLine = regexp.MustCompile(`(?m)^[ \t]*umask[ \t]+0?([0-7]{3})[ \t]*(?:#.*)?$`)

// idSet reads the numeric ids in colon-separated field idx of an account
// database file. ok is false when the file is missing or partial.
func idSet(ctx context.Context, s sys.System, path string, idx int) (map[int]bool, bool) {
	r, err := s.ReadFile(ctx, path)
	if err != nil || !r.Complete {
		return nil, false
	}
	ids := map[int]bool{}
	for _, line := range strings.Split(string(r.Data), "\n") {
		f := strings.Split(line, ":")
		if len(f) <= idx {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(f[idx])); err == nil {
			ids[n] = true
		}
	}
	return ids, len(ids) > 0
}

// worldWritableDirsCount is worldWritableDirs plus the number of directories
// it looked at, so a caller can tell "nothing wrong" from "nothing seen".
func worldWritableDirsCount(s sys.System, root string, depth, limit int) ([]string, int) {
	var bad []string
	pat := root
	seen := 0
	for d := 0; d < depth; d++ {
		pat += "/*"
		paths, _ := s.Glob(pat)
		sort.Strings(paths)
		for _, p := range paths {
			if seen >= limit {
				return bad, seen
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
	return bad, seen
}

func mountOptsText(opts []string) string {
	if len(opts) == 0 {
		return ""
	}
	return " carrying the options " + strings.Join(opts, ", ")
}

// suidBaseline lists program names that mainstream distributions ship with
// the SUID or SGID bit. Anything else with the bit in a system binary
// directory deserves a look. Names only; paths vary between distributions.
//
// Sources, checked 2026-10-14 against the distributions' own package file
// lists: Debian 12 and Ubuntu 24.04 (packages.debian.org and
// packages.ubuntu.com "list of files" pages for passwd, util-linux,
// openssh-client, dbus, libutempter0, snapd, polkitd, fuse3, cifs-utils,
// xserver-xorg-legacy, uidmap, lxc, evolution-data-server, sssd-common) and
// RHEL 9 / AlmaLinux 9 (rpm -ql file lists for shadow-utils, util-linux,
// openssh-clients, dbus-daemon, libutempter, polkit, fuse3, cockpit-ws,
// grub2-tools-minimal, initscripts, sssd-common and sssd-krb5-common). The
// sssd helpers krb5_child, ldap_child, proxy_child and selinux_child live in
// /usr/libexec/sssd and are installed setuid root on both families.
// abrt-action-install-debuginfo-to-abrt-cache (abrt), qemu-bridge-helper
// (qemu-kvm-common) and staprun (systemtap-runtime) are setuid root in
// their packages on the RHEL family and are common on server installs.
var suidBaseline = map[string]bool{
	"krb5_child": true, "ldap_child": true, "proxy_child": true, "selinux_child": true,
	"abrt-action-install-debuginfo-to-abrt-cache": true, "qemu-bridge-helper": true, "staprun": true, "netreport": true,
	"passwd": true, "chage": true, "chfn": true, "chsh": true, "gpasswd": true, "newgrp": true, "expiry": true, "sg": true,
	"su": true, "sudo": true, "sudoedit": true, "pkexec": true, "polkit-agent-helper-1": true, "doas": true,
	"mount": true, "umount": true, "fusermount": true, "fusermount3": true, "mount.nfs": true, "mount.cifs": true, "ntfs-3g": true,
	"ping": true, "ping6": true, "traceroute6.iputils": true, "arping": true, "clockdiff": true,
	"ssh-keysign": true, "ssh-agent": true, "unix_chkpwd": true, "unix2_chkpwd": true, "pam_timestamp_check": true, "pam_extrausers_chkpwd": true,
	"dbus-daemon-launch-helper": true, "utempter": true, "pt_chown": true, "chrome-sandbox": true, "snap-confine": true,
	"at": true, "crontab": true, "wall": true, "write": true, "bsd-write": true, "locate": true, "mlocate": true, "plocate": true,
	"dotlockfile": true, "mail-dotlock": true, "lockfile": true, "procmail": true, "exim4": true, "sendmail": true, "sendmail.postfix": true, "postdrop": true, "postqueue": true,
	"newuidmap": true, "newgidmap": true, "lxc-user-nic": true, "bwrap": true, "screen": true, "Xorg": true, "Xorg.wrap": true,
	"cockpit-session": true, "grub2-set-bootflag": true, "usernetctl": true, "dmcrypt-get-device": true, "pppd": true, "vmware-user-suid-wrapper": true,
	"su-l": true, "userhelper": true, "ksu": true, "pam_krb5_storetmp": true, "chromium-sandbox": true, "spice-client-glib-usb-acl-helper": true,
	"xtrlock": true, "camel-lock-helper-1.2": true,
}
