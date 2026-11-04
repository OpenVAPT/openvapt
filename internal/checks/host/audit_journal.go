package host

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// HOST-AUD: depth checks on the Linux audit daemon, its rule set and log
// files, and on journald and syslog forwarding. HOST-LOG-002 asks whether
// auditd is running; these checks ask whether what it records is useful and
// protected. Only configuration files are read; the audit log itself is
// never opened.

var (
	refAuditctl   = check.Ref{Title: "auditctl(8), Linux man-pages", URL: "https://man7.org/linux/man-pages/man8/auditctl.8.html"}
	refAuditdConf = check.Ref{Title: "auditd.conf(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/auditd.conf.5.html"}
	refNIST80092  = check.Ref{Title: "NIST SP 800-92, Guide to Computer Security Log Management", URL: "https://csrc.nist.gov/pubs/sp/800/92/final"}
	refJournald   = check.Ref{Title: "journald.conf(5), systemd", URL: "https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html"}
	refRsyslog    = check.Ref{Title: "rsyslog.conf(5), Debian trixie manual pages (forwarding actions)", URL: "https://manpages.debian.org/trixie/rsyslog/rsyslog.conf.5.en.html"}
)

// auditState is the outcome of looking for audit rule files.
type auditState int

const (
	auditRead      auditState = iota // rule files read (possibly none exist)
	auditAbsent                      // /etc/audit does not exist: auditd is not installed
	auditUnreadble                   // rule files exist but could not be read
)

// auditRules returns the active lines of every audit rule file.
func auditRules(ctx context.Context, s sys.System) ([]string, auditState) {
	if !exists(s, "/etc/audit") {
		return nil, auditAbsent
	}
	files, unreadable := readAll(ctx, s, "/etc/audit/rules.d/*.rules", "/etc/audit/audit.rules")
	if len(files) == 0 && len(unreadable) > 0 {
		return nil, auditUnreadble
	}
	var lines []string
	for _, f := range files {
		lines = append(lines, activeLines(f.Text)...)
	}
	return lines, auditRead
}

// ruleWatches reports whether any rule watches path (-w path, -F path=path
// or -F dir=path). A watch on a parent directory also counts.
func ruleWatches(lines []string, path string) bool {
	for _, l := range lines {
		f := strings.Fields(l)
		for i, t := range f {
			var p string
			switch {
			case t == "-w" && i+1 < len(f):
				p = f[i+1]
			case strings.HasPrefix(t, "path="):
				p = strings.TrimPrefix(t, "path=")
			case strings.HasPrefix(t, "dir="):
				p = strings.TrimPrefix(t, "dir=")
			default:
				continue
			}
			if strings.TrimSuffix(p, "/") == strings.TrimSuffix(path, "/") || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
				return true
			}
		}
	}
	return false
}

// ruleSyscall reports whether any rule audits the named system call.
func ruleSyscall(lines []string, name string) bool {
	for _, l := range lines {
		f := strings.Fields(l)
		for i, t := range f {
			if t != "-S" || i+1 >= len(f) {
				continue
			}
			for _, sc := range strings.Split(f[i+1], ",") {
				if sc == name || sc == "all" {
					return true
				}
			}
		}
	}
	return false
}

// auditRuleCheck registers one check that requires a set of audit rules.
// missing returns the rules that are absent, in plain words.
func auditRuleCheck(id, title, cvss string, sev check.Severity, summary, rationale, detection, fix, verify, cisTopic string, nist []string, missing func(lines []string) []string) {
	check.Register(&check.Check{
		ID: id, Title: title, Domain: check.DomainHost,
		Severity: sev, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      cvss,
		Summary:   summary,
		Rationale: rationale,
		Detection: detection + " Reads the active lines of /etc/audit/rules.d/*.rules and /etc/audit/audit.rules; the audit log itself is never read. The loaded rule set is not read (auditctl is not on the read-only allow-list), so when the rules are in the files the allow-listed systemctl is-active auditd must report active for a Pass; otherwise the result is Incomplete, and the evidence says the loaded rules were not verified.",
		Fix:       fix,
		Verify:    verify,
		Refs:      []check.Ref{refAuditctl, refNIST80092, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: nist, CISTopic: cisTopic},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			lines, st := auditRules(ctx, s)
			switch st {
			case auditAbsent:
				return []check.Result{check.SkipR("audit rules", "auditd is not installed (/etc/audit is missing); see HOST-LOG-002")}
			case auditUnreadble:
				return []check.Result{check.IncompleteR("audit rules", "Audit rule files exist but could not be read (run as root for this check)")}
			}
			if m := missing(lines); len(m) > 0 {
				return []check.Result{check.FailR("audit rules", "Audit rules are missing", m...)}
			}
			// The loaded rule set (auditctl -l) is not read: auditctl is not
			// on the allow-list. Rules on disk only take effect while auditd
			// runs, so a Pass needs the daemon active.
			const unverified = "loaded rules were not verified (auditctl -l is not run); the rule files on disk were read"
			out, err := s.Run(ctx, "systemctl", "is-active", "auditd")
			state := strings.TrimSpace(out)
			if err != nil && state == "" {
				return []check.Result{check.IncompleteR("audit rules", "The required rules are in the rule files, but whether auditd is running could not be confirmed (systemctl is-active auditd did not run)", unverified)}
			}
			if state != "active" {
				return []check.Result{check.IncompleteR("audit rules", "The required rules are in the rule files, but auditd is "+state+", so they are not loaded", unverified, "systemctl is-active auditd: "+state)}
			}
			return []check.Result{check.PassR("audit rules", "The required audit rules are present in the rule files and auditd is active", unverified)}
		},
	})
}

var lowAudit = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N"

// remoteLog matches an rsyslog forwarding action: a selector followed by @host
// or @@host, or the omfwd module.
var remoteLog = regexp.MustCompile(`^\S+\s+@{1,2}\S|omfwd|target=`)

func init() {
	check.Register(&check.Check{
		ID: "HOST-AUD-001", Title: "Audit Daemon Not Enabled at Boot", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      lowAudit,
		Summary:   "Checks that the audit daemon (auditd) is set to start at every boot, not only running now.",
		Rationale: "An audit daemon that was started by hand stops recording at the next reboot, leaving a gap exactly when an attacker who forced a restart would want one. HOST-LOG-002 reports whether auditd is running; this check reports whether it will come back.",
		Detection: "Runs the allow-listed read-only command systemctl is-enabled auditd and reads the single word it prints: enabled, static, alias or indirect pass; disabled, masked or enabled-runtime fail. If the command cannot run and /etc/audit exists the result is Incomplete; if /etc/audit does not exist the check is skipped.",
		Fix:       "systemctl enable auditd  (on some distributions: systemctl enable --now auditd). Then confirm the rules in /etc/audit/rules.d load at boot with augenrules --check.",
		Verify:    "systemctl is-enabled auditd  should print enabled.",
		Refs:      []check.Ref{{Title: "auditd(8), Linux man-pages", URL: "https://man7.org/linux/man-pages/man8/auditd.8.html"}, refNIST80092},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-2", "AU-12"}, CISTopic: "Audit daemon enabled at boot (CIS Controls v8 8.2)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			out, err := s.Run(ctx, "systemctl", "is-enabled", "auditd")
			state := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
			switch state {
			case "enabled", "static", "alias", "indirect":
				return []check.Result{check.PassR("auditd", "auditd is "+state)}
			case "disabled", "masked", "masked-runtime", "enabled-runtime":
				return []check.Result{check.FailR("auditd", "auditd is "+state+", so it will not record after the next reboot")}
			}
			if err != nil && !exists(s, "/etc/audit") {
				return []check.Result{check.SkipR("auditd", "auditd is not installed (/etc/audit is missing); see HOST-LOG-002")}
			}
			return []check.Result{check.IncompleteR("auditd", "systemctl is-enabled auditd gave no usable answer")}
		},
	})

	auditRuleCheck("HOST-AUD-002", "Identity Files Not Audited", lowAudit, check.Low,
		"Checks that changes to the account, group, password and sudo files are recorded by the audit system.",
		"An attacker who adds an account, joins a privileged group or grants themselves sudo edits one of a handful of files. A watch rule on each makes that change an audit event with the user, process and time attached; without it the change leaves no trace beyond the file itself.",
		"Requires a watch (-w or -F path=) on /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow, /etc/sudoers and /etc/sudoers.d.",
		"Add to /etc/audit/rules.d/50-identity.rules:  -w /etc/passwd -p wa -k identity  and the same for /etc/group, /etc/shadow, /etc/gshadow, /etc/sudoers and /etc/sudoers.d/ , then run augenrules --load.",
		"auditctl -l | grep -E 'passwd|shadow|sudoers'",
		"Audit changes to identity files (CIS Controls v8 8.5)", []string{"AU-2", "AU-12", "AC-2(4)"},
		func(lines []string) []string {
			var m []string
			for _, p := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d"} {
				if !ruleWatches(lines, p) {
					m = append(m, "no watch on "+p)
				}
			}
			return m
		})

	auditRuleCheck("HOST-AUD-003", "Login and Logout Events Not Audited", lowAudit, check.Low,
		"Checks that the files recording logins, failed logins and sessions are watched by the audit system.",
		"Login records are the first thing an investigator asks for and the first thing an intruder cleans. Watching lastlog, the failed-login store and the wtmp and btmp session files makes tampering itself an audit event.",
		"Requires a watch on /var/log/lastlog, on a failed-login store (/var/log/faillog, /var/log/faillock, /var/run/faillock or /var/log/tallylog), and on /var/log/wtmp and /var/log/btmp.",
		"Add to /etc/audit/rules.d/50-login.rules:  -w /var/log/lastlog -p wa -k logins ,  -w /var/run/faillock -p wa -k logins ,  -w /var/log/wtmp -p wa -k session ,  -w /var/log/btmp -p wa -k session , then augenrules --load.",
		"auditctl -l | grep -E 'lastlog|faillock|wtmp|btmp'",
		"Audit login, logout and session events (CIS Controls v8 8.5)", []string{"AU-2", "AU-12", "AC-7"},
		func(lines []string) []string {
			var m []string
			if !ruleWatches(lines, "/var/log/lastlog") {
				m = append(m, "no watch on /var/log/lastlog")
			}
			if !ruleWatches(lines, "/var/log/faillog") && !ruleWatches(lines, "/var/log/faillock") && !ruleWatches(lines, "/var/run/faillock") && !ruleWatches(lines, "/var/log/tallylog") {
				m = append(m, "no watch on the failed-login store (/var/run/faillock or /var/log/faillog)")
			}
			for _, p := range []string{"/var/log/wtmp", "/var/log/btmp"} {
				if !ruleWatches(lines, p) {
					m = append(m, "no watch on "+p)
				}
			}
			return m
		})

	auditRuleCheck("HOST-AUD-004", "System Time Changes Not Audited", lowAudit, check.Low,
		"Checks that the audit system records changes to the system clock and time zone.",
		"Moving the clock is a classic way to confuse log timelines, forge timestamps or defeat certificate and token expiry. Auditing the time-setting system calls and /etc/localtime attributes every change to a user and process.",
		"Requires a rule on the system calls adjtimex, settimeofday and clock_settime, and a watch on /etc/localtime.",
		"Add to /etc/audit/rules.d/50-time.rules:  -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change  (and the same with arch=b32), plus  -w /etc/localtime -p wa -k time-change , then augenrules --load.",
		"auditctl -l | grep -E 'settimeofday|localtime'",
		"Audit date and time modification (CIS Controls v8 8.5)", []string{"AU-2", "AU-8", "AU-12"},
		func(lines []string) []string {
			var m []string
			for _, sc := range []string{"adjtimex", "settimeofday", "clock_settime"} {
				if !ruleSyscall(lines, sc) {
					m = append(m, "no rule for system call "+sc)
				}
			}
			if !ruleWatches(lines, "/etc/localtime") {
				m = append(m, "no watch on /etc/localtime")
			}
			return m
		})

	auditRuleCheck("HOST-AUD-005", "Kernel Module Loading Not Audited", lowAudit, check.Low,
		"Checks that loading and unloading kernel modules is recorded by the audit system.",
		"A rootkit is usually a kernel module. Auditing init_module, finit_module and delete_module (or the kmod program) records the moment one is loaded, which is often the only evidence that survives.",
		"Requires a rule on the system calls init_module and delete_module (finit_module is recommended as well), or a watch or execution rule on the kmod, insmod, rmmod and modprobe programs.",
		"Add to /etc/audit/rules.d/50-modules.rules:  -a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules  (and arch=b32), or  -a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules , then augenrules --load.",
		"auditctl -l | grep -E 'init_module|kmod'",
		"Audit kernel module loading and unloading (CIS Controls v8 8.5)", []string{"AU-2", "AU-12", "CM-7"},
		func(lines []string) []string {
			if ruleSyscall(lines, "init_module") && ruleSyscall(lines, "delete_module") {
				return nil
			}
			for _, p := range []string{"/usr/bin/kmod", "/bin/kmod", "/sbin/insmod", "/sbin/modprobe", "/usr/sbin/modprobe"} {
				if ruleWatches(lines, p) {
					return nil
				}
			}
			return []string{"no rule for init_module and delete_module, and no rule on the kmod program"}
		})

	auditRuleCheck("HOST-AUD-006", "Privileged Command Use Not Audited", lowAudit, check.Low,
		"Checks that the audit system records when ordinary users run privileged (setuid or setgid) programs.",
		"Programs such as sudo, su, passwd and mount run with elevated rights. Recording each execution by a real user (auid at or above the first normal user id) shows who used privilege and when, which is the core of a usable audit trail.",
		"Requires at least one execution rule that combines -F perm=x with an -F auid>= filter (the usual form for privileged programs), or an execve rule filtered on euid=0.",
		"Generate rules for every setuid and setgid program:  find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f | awk '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=1000 -F auid!=unset -k privileged\"}' > /etc/audit/rules.d/50-privileged.rules  then augenrules --load.",
		"auditctl -l | grep 'perm=x'",
		"Audit use of privileged commands (CIS Controls v8 8.5)", []string{"AU-2", "AU-12", "AC-6(9)"},
		func(lines []string) []string {
			for _, l := range lines {
				if (strings.Contains(l, "perm=x") && strings.Contains(l, "auid>=")) || (strings.Contains(l, "-S execve") && strings.Contains(l, "euid=0")) {
					return nil
				}
			}
			return []string{"no execution rule with perm=x and an auid>= filter"}
		})

	auditRuleCheck("HOST-AUD-007", "Audit Configuration Not Immutable", lowAudit, check.Low,
		"Checks that the audit rule set ends with -e 2, which locks the rules until the next reboot.",
		"Without the immutable flag, anyone who gains root can delete the audit rules (auditctl -D) and work unobserved. With -e 2 the rules can only be changed by rebooting, which is itself a loud, logged event.",
		"Requires the last active line of the audit rules to be -e 2.",
		"Add  -e 2  as the last line of the last file in /etc/audit/rules.d (for example 99-finalize.rules), then augenrules --load and reboot. Plan rule changes before enabling it: every later change needs a reboot.",
		"auditctl -s | grep enabled  should print enabled 2.",
		"Audit configuration is immutable (CIS Controls v8 8.2)", []string{"AU-9", "AU-12"},
		func(lines []string) []string {
			if len(lines) == 0 {
				return []string{"no audit rules at all"}
			}
			if strings.Join(strings.Fields(lines[len(lines)-1]), " ") != "-e 2" {
				return []string{"last rule is not -e 2 (found: " + lines[len(lines)-1] + ")"}
			}
			return nil
		})

	check.Register(&check.Check{
		ID: "HOST-AUD-008", Title: "Audit Log Files Readable by Others", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that the audit log directory and files can be read only by root.",
		Rationale: "Audit logs record which user ran which command with which arguments, including file names and sometimes secrets passed on a command line. They are also the record an intruder most wants to edit. Both reasons call for root-only access.",
		Detection: "Stats /var/log/audit (metadata only) and every file in it. The directory must not grant group write or any access to others (0750 or stricter); files must be owned by root with mode 0640 or stricter. Log contents are never read. If the directory does not exist the check is skipped; if it cannot be inspected the result is Incomplete.",
		Fix:       "chmod 0750 /var/log/audit && chmod 0600 /var/log/audit/* && chown -R root:root /var/log/audit , and set log_group = root in /etc/audit/auditd.conf so new files keep these modes.",
		Verify:    "stat -c '%a %U %n' /var/log/audit /var/log/audit/*",
		Refs:      []check.Ref{refAuditdConf, refNIST80092},
		Standards: check.Standards{CWE: []string{"CWE-532", "CWE-732"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-9", "AC-6"}, CISTopic: "Audit log files and directory are protected (CIS Controls v8 8.2)"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			dir, err := s.Stat("/var/log/audit")
			if err != nil {
				if !exists(s, "/etc/audit") {
					return []check.Result{check.SkipR("/var/log/audit", "auditd is not installed")}
				}
				return []check.Result{check.IncompleteR("/var/log/audit", "The audit log directory could not be inspected (run as root for this check)")}
			}
			var bad []string
			if dir.Mode.Perm()&0o027 != 0 || dir.UID != 0 {
				bad = append(bad, fmt.Sprintf("directory /var/log/audit mode %04o uid %d (need 0750 or stricter, owned by root)", dir.Mode.Perm(), dir.UID))
			}
			files, _ := s.Glob("/var/log/audit/*")
			for _, p := range files {
				st, err := s.Stat(p)
				if err != nil || st.IsDir {
					continue
				}
				if st.Mode.Perm()&0o137 != 0 || st.UID != 0 {
					bad = append(bad, fmt.Sprintf("%s mode %04o uid %d (need 0640 or stricter, owned by root)", p, st.Mode.Perm(), st.UID))
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/var/log/audit", "Audit logs are accessible beyond root", bad...)}
			}
			return []check.Result{check.PassR("/var/log/audit", "Audit log directory and files are restricted to root")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-AUD-009", Title: "Audit Daemon Ignores a Full Log Disk", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      lowAudit,
		Summary:   "Checks that auditd is told what to do when its log file is full or the disk runs low, rather than silently dropping events.",
		Rationale: "With max_log_file_action = ignore the log grows until the disk is full; with suspend auditing simply stops. An unset space_left_action means nobody is warned before that happens. Either way an attacker who fills the disk switches auditing off.",
		Detection: "Reads max_log_file_action, space_left_action and admin_space_left_action from /etc/audit/auditd.conf. Each must be set and must not be ignore or suspend. Skipped when auditd is not installed; Incomplete when the file exists but cannot be read.",
		Fix:       "In /etc/audit/auditd.conf set  max_log_file_action = keep_logs  (or rotate with enough num_logs),  space_left_action = email  (or syslog or exec), and  admin_space_left_action = halt  or  single  as policy requires, then systemctl restart auditd. Caution: admin_space_left_action = halt or single stops the server or drops it to single-user mode when the audit disk fills; choose it only where losing audit records is worse than downtime, and give /var/log/audit room and monitoring first.",
		Verify:    "grep -E '^(max_log_file_action|space_left_action|admin_space_left_action)' /etc/audit/auditd.conf",
		Refs:      []check.Ref{refAuditdConf, refNIST80092},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-4", "AU-5"}, CISTopic: "Audit log storage and full-disk actions (CIS Controls v8 8.3)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, st := readState(ctx, s, "/etc/audit/auditd.conf")
			switch st {
			case fileMissing:
				if !exists(s, "/etc/audit") {
					return []check.Result{check.SkipR("/etc/audit/auditd.conf", "auditd is not installed")}
				}
				return []check.Result{check.IncompleteR("/etc/audit/auditd.conf", "auditd.conf is missing although /etc/audit exists")}
			case fileUnreadable:
				return []check.Result{check.IncompleteR("/etc/audit/auditd.conf", "Not readable (run as root for this check)")}
			}
			cfg := []collect.ConfigFile{{Path: "/etc/audit/auditd.conf", Values: collect.ParseKV(text), Complete: true}}
			var bad []string
			for _, k := range []string{"max_log_file_action", "space_left_action", "admin_space_left_action"} {
				v, _, ok := collect.First(cfg, k)
				v = strings.ToLower(strings.TrimSpace(v))
				switch {
				case !ok || v == "":
					bad = append(bad, k+" is not set")
				case v == "ignore" || v == "suspend":
					bad = append(bad, k+" = "+v)
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/etc/audit/auditd.conf", "auditd will drop or stop auditing when the log disk fills", bad...)}
			}
			return []check.Result{check.PassR("/etc/audit/auditd.conf", "Full-disk actions are configured")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-AUD-010", Title: "Journal Not Persistent or Not Compressed", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      lowAudit,
		Summary:   "Checks that systemd-journald is configured to keep the journal on disk and to compress it.",
		Rationale: "Storage=volatile keeps the journal only in memory, so a reboot (or a crash an attacker caused) erases the evidence. Compression keeps a persistent journal small enough to retain for weeks. HOST-LOG-001 looks for the journal directory; this check reads the configuration that decides what happens to it.",
		Detection: "Reads Storage= and Compress= from /etc/systemd/journald.conf and /etc/systemd/journald.conf.d/*.conf. Storage=persistent passes; auto or unset passes only when /var/log/journal exists; volatile or none fails. Compress=no fails. Incomplete when the files exist but cannot be read; skipped when systemd is not present.",
		Fix:       "In /etc/systemd/journald.conf set  Storage=persistent  and  Compress=yes , create the directory with  mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal , then systemctl restart systemd-journald.",
		Verify:    "journalctl --header | head  and  ls -d /var/log/journal",
		Refs:      []check.Ref{refJournald, refNIST80092},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-4", "AU-9", "AU-11"}, CISTopic: "journald persistent storage and compression (CIS Controls v8 8.3)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, unreadable := readAll(ctx, s, "/etc/systemd/journald.conf.d/*.conf", "/etc/systemd/journald.conf")
			if len(files) == 0 {
				if len(unreadable) > 0 {
					return []check.Result{check.IncompleteR("journald.conf", "journald configuration exists but could not be read")}
				}
				if !exists(s, "/etc/systemd") {
					return []check.Result{check.SkipR("journald.conf", "systemd is not present")}
				}
				return []check.Result{check.IncompleteR("journald.conf", "No journald configuration file was found under /etc/systemd")}
			}
			var cfg []collect.ConfigFile
			for _, f := range files {
				cfg = append(cfg, collect.ConfigFile{Path: f.Path, Values: collect.ParseKV(f.Text), Complete: true})
			}
			var bad []string
			storage, path, ok := collect.First(cfg, "storage")
			storage = strings.ToLower(strings.TrimSpace(storage))
			if !ok || storage == "" {
				storage, path = "auto", "default"
			}
			switch storage {
			case "persistent":
			case "auto":
				if st, err := s.Stat("/var/log/journal"); err != nil || !st.IsDir {
					bad = append(bad, "Storage="+storage+" ("+path+") with no /var/log/journal directory: the journal is lost at reboot")
				}
			default:
				bad = append(bad, "Storage="+storage+" ("+path+"): the journal is lost at reboot")
			}
			if v, p, ok := collect.First(cfg, "compress"); ok {
				switch strings.ToLower(strings.TrimSpace(v)) {
				case "no", "false", "0", "off":
					bad = append(bad, "Compress="+v+" ("+p+")")
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("journald.conf", "The journal is not kept persistently and compressed", bad...)}
			}
			return []check.Result{check.PassR("journald.conf", "Storage="+storage+", compression on")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-AUD-011", Title: "Logs Not Forwarded to a Remote Collector", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortMedium,
		CVSS:      lowAudit,
		Summary:   "Checks that system logs are sent to another machine, so an intruder with root cannot erase the only copy.",
		Rationale: "Whoever gains root on a server can delete or edit its local logs. A copy that already left the machine, to a log server or a SIEM, is the record an investigation can trust. NIST SP 800-92 treats centralised log collection as a basic log management control.",
		Detection: "Looks for a forwarding rule in /etc/rsyslog.conf and /etc/rsyslog.d/*.conf (a selector followed by @host or @@host, or an omfwd action), a network destination in /etc/syslog-ng/syslog-ng.conf, or a URL= in /etc/systemd/journal-upload.conf. The remote address is never copied into the report. Incomplete when a file exists but cannot be read.",
		Fix:       "rsyslog: create /etc/rsyslog.d/90-remote.conf with  *.* action(type=\"omfwd\" target=\"logs.example.internal\" port=\"6514\" protocol=\"tcp\" StreamDriver=\"gtls\" StreamDriverMode=\"1\" StreamDriverAuthMode=\"x509/name\")  and restart rsyslog. Or configure systemd-journal-upload with URL= pointing at a journal-remote collector. Prefer TLS so logs are not readable in transit.",
		Verify:    "grep -rE '^[^#].*@|omfwd' /etc/rsyslog.conf /etc/rsyslog.d/  or  grep '^URL=' /etc/systemd/journal-upload.conf",
		Refs:      []check.Ref{refNIST80092, refRsyslog, {Title: "journal-upload.conf(5), systemd", URL: "https://www.freedesktop.org/software/systemd/man/latest/journal-upload.conf.html"}},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-9(2)", "AU-6", "SI-4"}, CISTopic: "Centralised log collection (CIS Controls v8 8.9)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, unreadable := readAll(ctx, s, "/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf", "/etc/syslog-ng/syslog-ng.conf", "/etc/syslog-ng/conf.d/*.conf", "/etc/systemd/journal-upload.conf")
			for _, f := range files {
				for _, l := range activeLines(f.Text) {
					isSyslogNG := strings.Contains(f.Path, "syslog-ng")
					switch {
					case !isSyslogNG && strings.HasSuffix(f.Path, "journal-upload.conf") && strings.HasPrefix(l, "URL=") && strings.TrimSpace(strings.TrimPrefix(l, "URL=")) != "":
						return []check.Result{check.PassR(f.Path, "journal-upload forwards the journal to a remote collector")}
					case isSyslogNG && strings.HasPrefix(l, "destination") && (strings.Contains(l, "network(") || strings.Contains(l, "syslog(") || strings.Contains(l, "tcp(") || strings.Contains(l, "udp(")):
						return []check.Result{check.PassR(f.Path, "syslog-ng has a network destination")}
					case !isSyslogNG && !strings.HasSuffix(f.Path, "journal-upload.conf") && remoteLog.MatchString(l):
						return []check.Result{check.PassR(f.Path, "rsyslog forwards logs to a remote host")}
					}
				}
			}
			if len(unreadable) > 0 {
				return []check.Result{check.IncompleteR("syslog", "Some logging configuration could not be read", unreadable...)}
			}
			return []check.Result{check.FailR("syslog", "No remote log destination is configured; the only copy of the logs is on this machine")}
		},
	})
}
