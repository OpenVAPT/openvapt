package host

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// HOST-PAM: authentication policy beyond what HOST-PWD covers. HOST-PWD
// already checks the hashing algorithm (001), obsolete hashes (002),
// minimum length (003), lockout after failures (004) and forced rotation
// (005), and HOST-FS-009 checks UMASK, so none of those is repeated here.
// Everything is read from PAM stacks, login.defs, useradd defaults and
// shell start-up files; no command is run.

var (
	refPAMUnix      = check.Ref{Title: "pam_unix(8), Linux-PAM", URL: "https://man7.org/linux/man-pages/man8/pam_unix.8.html"}
	refPAMWheel     = check.Ref{Title: "pam_wheel(8), Linux-PAM", URL: "https://man7.org/linux/man-pages/man8/pam_wheel.8.html"}
	refPAMPwhistory = check.Ref{Title: "pam_pwhistory(8), Linux-PAM", URL: "https://man7.org/linux/man-pages/man8/pam_pwhistory.8.html"}
	refUseradd      = check.Ref{Title: "useradd(8), Linux man-pages (default INACTIVE value)", URL: "https://man7.org/linux/man-pages/man8/useradd.8.html"}
	refBash         = check.Ref{Title: "Bash Reference Manual, Bash Variables (TMOUT)", URL: "https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html"}
)

var (
	passwordStacks = []string{"/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}
	authStacks     = []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}
	lowIdentity    = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
	lowLocal       = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"
)

// pamStacks reads the given PAM files. It returns the files read, whether
// any exists, and whether some exist but could not be read.
func pamStacks(ctx context.Context, s sys.System, paths []string) (files []textFile, unreadable []string) {
	return readAll(ctx, s, paths...)
}

// pamOption returns the value of option=... on the first active line that
// names module, or "" and false.
func pamOption(text, module, option string) (string, bool) {
	for _, l := range activeLines(text) {
		if !strings.Contains(l, module) {
			continue
		}
		for _, a := range strings.Fields(l) {
			if v, ok := strings.CutPrefix(a, option+"="); ok {
				return v, true
			}
		}
	}
	return "", false
}

// pamUses reports whether an active line of the stack names the module.
func pamUses(text, module string) bool {
	for _, l := range activeLines(text) {
		if strings.Contains(l, module) {
			return true
		}
	}
	return false
}

// loginDefsInt reads one numeric setting from /etc/login.defs.
func loginDefsInt(ctx context.Context, s sys.System, key string) (n int, set bool, st fileState) {
	text, st := readState(ctx, s, "/etc/login.defs")
	if st != fileRead {
		return 0, false, st
	}
	cfg := []collect.ConfigFile{{Path: "/etc/login.defs", Values: collect.ParseKV(text), Complete: true}}
	v, _, ok := collect.First(cfg, key)
	if !ok {
		return 0, false, fileRead
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false, fileRead
	}
	return n, true, fileRead
}

// loginDefsCheck registers a check on one numeric login.defs setting.
func loginDefsCheck(id, title, cvss string, sev check.Severity, key, summary, rationale, fix, cisTopic string, good func(int) bool, want string) {
	check.Register(&check.Check{
		ID: id, Title: title, Domain: check.DomainHost,
		Severity: sev, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      cvss,
		Summary:   summary,
		Rationale: rationale,
		Detection: "Reads " + key + " from /etc/login.defs; " + want + " passes. An unset value fails, because the built-in default does not meet the requirement. Skipped when the file does not exist; Incomplete when it cannot be read.",
		Fix:       fix,
		Verify:    "grep '^" + key + "' /etc/login.defs",
		Refs:      []check.Ref{refLoginDefs, refNIST63B},
		Standards: check.Standards{CWE: []string{"CWE-262"}, OWASP: []string{"A07:2021"}, NIST: []string{"IA-5(1)"}, CISTopic: cisTopic},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			n, set, st := loginDefsInt(ctx, s, key)
			switch st {
			case fileMissing:
				return []check.Result{check.SkipR("/etc/login.defs", "File not found")}
			case fileUnreadable:
				return []check.Result{check.IncompleteR("/etc/login.defs", "Not readable")}
			}
			if !set {
				return []check.Result{check.FailR("/etc/login.defs", key+" is not set ("+want+")")}
			}
			if !good(n) {
				return []check.Result{check.FailR("/etc/login.defs", fmt.Sprintf("%s %d (%s)", key, n, want))}
			}
			return []check.Result{check.PassR("/etc/login.defs", fmt.Sprintf("%s %d", key, n))}
		},
	})
}

var (
	pathAssign = regexp.MustCompile(`(?m)^\s*(?:export\s+)?PATH=(\S*)`)
	tmoutLine  = regexp.MustCompile(`(?m)^\s*(?:readonly\s+|export\s+|typeset\s+-x\s+|declare\s+-x\s+)?TMOUT=(\d+)`)
)

func init() {
	check.Register(&check.Check{
		ID: "HOST-PAM-001", Title: "Password Quality Module Not Enforced", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      lowIdentity,
		Summary:   "Checks that new passwords pass through pam_pwquality with its dictionary check on, so dictionary words and user-name variants are rejected.",
		Rationale: "NIST SP 800-63B-4 asks verifiers to reject passwords found in dictionaries and blocklists rather than to impose composition rules. pam_pwquality does that work on Linux, but only when the password stack actually calls it and its dictcheck and usercheck options are not switched off. A minlen in pwquality.conf (HOST-PWD-003) does nothing if the module is never invoked.",
		Detection: "Reads /etc/pam.d/common-password, /etc/pam.d/system-auth and /etc/pam.d/password-auth for an active pam_pwquality (or pam_passwdqc or pam_cracklib) line, then reads dictcheck, usercheck and enforcing from /etc/security/pwquality.conf.d/*.conf and /etc/security/pwquality.conf and from the module line. A missing module, dictcheck=0, usercheck=0 or enforcing=0 fails. Skipped when no password stack exists; Incomplete when one exists but cannot be read.",
		Fix:       "Install libpam-pwquality (Debian/Ubuntu) or libpwquality (RHEL family). Make sure the password stack has  password requisite pam_pwquality.so retry=3  before pam_unix (pam-auth-update or authselect enable-feature with-pwquality), and in /etc/security/pwquality.conf keep  dictcheck = 1  and  usercheck = 1 . Pair it with a breached-password blocklist where possible. Keep a root session open and test a login and a password change in a second session before closing it: a wrong PAM line can lock every user out.",
		Verify:    "grep pam_pwquality /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null; grep -rE '^(dictcheck|usercheck|enforcing)' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/",
		Refs:      []check.Ref{refPwquality, refNIST63B},
		Standards: check.Standards{CWE: []string{"CWE-521"}, OWASP: []string{"A07:2021"}, NIST: []string{"IA-5(1)"}, CISTopic: "Password creation requirements enforced through PAM (CIS Controls v8 5.2)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, unreadable := pamStacks(ctx, s, passwordStacks)
			if len(files) == 0 {
				if len(unreadable) > 0 {
					return []check.Result{check.IncompleteR("pam", "Password stack exists but could not be read", unreadable...)}
				}
				return []check.Result{check.SkipR("pam", "PAM password stack not found")}
			}
			var bad []string
			var module textFile
			for _, f := range files {
				if pamUses(f.Text, "pam_pwquality") || pamUses(f.Text, "pam_passwdqc") || pamUses(f.Text, "pam_cracklib") {
					module = f
					break
				}
			}
			if module.Path == "" {
				bad = append(bad, "no pam_pwquality line in "+files[0].Path)
			}
			cfg := collect.ReadConfigs(ctx, s, "/etc/security/pwquality.conf.d/*.conf", "/etc/security/pwquality.conf")
			for _, k := range []string{"dictcheck", "usercheck", "enforcing"} {
				v, path, ok := collect.First(cfg, k)
				if mv, mok := pamOption(module.Text, "pam_pwquality", k); mok {
					v, path, ok = mv, module.Path, true
				}
				if ok && strings.TrimSpace(v) == "0" {
					bad = append(bad, k+" = 0 ("+path+")")
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("pam", "Password quality checks are not enforced", bad...)}
			}
			return []check.Result{check.PassR(module.Path, "pam_pwquality is active with dictionary and user-name checks")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PAM-002", Title: "Account Lockout Releases Too Quickly", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      lowIdentity,
		Summary:   "Checks that a locked account stays locked for at least 15 minutes (or until an administrator unlocks it).",
		Rationale: "This check and HOST-PWD-004 split one control so a single root cause is never counted twice: HOST-PWD-004 covers whether lockout exists and its deny threshold (how many failures lock the account); this check covers only unlock_time (how long the lock lasts). How long the lock lasts decides whether it slows an attacker: pam_faillock's default unlock_time of 600 seconds lets guessing resume every ten minutes. Fifteen minutes or more, or 0 (manual unlock), makes online guessing impractical.",
		Detection: "Reads unlock_time from the pam_faillock lines of /etc/pam.d/common-auth, /etc/pam.d/system-auth and /etc/pam.d/password-auth, then from /etc/security/faillock.conf, else uses the module default of 600. A value of 0 or at least 900 passes. No pam_faillock at all is skipped, because HOST-PWD-004 already reports the missing lockout. Skipped when no authentication stack exists; Incomplete when one exists but cannot be read.",
		Fix:       "In /etc/security/faillock.conf set  unlock_time = 900  (or 0 to require an administrator to run faillock --reset), keeping deny between 3 and 10. Keep a root session open and test in a second session before closing the first: a wrong PAM line can lock every user out, and unlock_time = 0 means locked accounts, administrators included, wait for faillock --reset.",
		Verify:    "grep -E 'unlock_time' /etc/security/faillock.conf /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null",
		Refs:      []check.Ref{refFaillock, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-307"}, OWASP: []string{"A07:2021"}, NIST: []string{"AC-7"}, CISTopic: "Lockout duration for failed password attempts (CIS Controls v8 5.2)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, unreadable := pamStacks(ctx, s, authStacks)
			if len(files) == 0 {
				if len(unreadable) > 0 {
					return []check.Result{check.IncompleteR("pam", "Authentication stack exists but could not be read", unreadable...)}
				}
				return []check.Result{check.SkipR("pam", "PAM authentication stack not found")}
			}
			var stack textFile
			for _, f := range files {
				if pamUses(f.Text, "pam_faillock") {
					stack = f
					break
				}
			}
			if stack.Path == "" {
				// HOST-PWD-004 reports the missing lockout; failing here as
				// well would count one root cause twice.
				return []check.Result{check.SkipR("pam", "No pam_faillock in the authentication stack, so there is no lockout duration to check; HOST-PWD-004 reports the missing lockout")}
			}
			unlock, src := 600, "pam_faillock default"
			if v, ok := pamOption(stack.Text, "pam_faillock", "unlock_time"); ok {
				if n, err := strconv.Atoi(v); err == nil {
					unlock, src = n, stack.Path
				}
			} else if v, _, ok := collect.First(collect.ReadConfigs(ctx, s, "/etc/security/faillock.conf"), "unlock_time"); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					unlock, src = n, "/etc/security/faillock.conf"
				}
			}
			if unlock == 0 || unlock >= 900 {
				return []check.Result{check.PassR(src, fmt.Sprintf("unlock_time=%d", unlock))}
			}
			return []check.Result{check.FailR(src, fmt.Sprintf("unlock_time=%d seconds (need 900 or more, or 0 for manual unlock)", unlock))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PAM-003", Title: "su Not Restricted to an Administrative Group", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      lowLocal,
		Summary:   "Checks that only members of a named group (wheel or sudo) may use su to become another user.",
		Rationale: "Without pam_wheel, every local account, including a compromised web service user, can run su and start guessing the root password. Restricting su to an administrative group removes that path and leaves sudo, which logs each command, as the way to gain privilege.",
		Detection: "Reads /etc/pam.d/su for an active line  auth required pam_wheel.so  (any control value, with or without use_uid and group=). Skipped when the file does not exist; Incomplete when it cannot be read.",
		Fix:       "In /etc/pam.d/su uncomment or add  auth required pam_wheel.so use_uid group=sudo  (group=wheel on the RHEL family), and make sure the group contains only administrators. Caution: add every administrator who uses su to that group first and test from a second session, or they lose su access.",
		Verify:    "grep -E '^auth\\s+required\\s+pam_wheel.so' /etc/pam.d/su",
		Refs:      []check.Ref{refPAMWheel, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-250", "CWE-862"}, NIST: []string{"AC-6(2)", "AC-3"}, CISTopic: "Access to the su command is restricted (CIS Controls v8 5.4)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, st := readState(ctx, s, "/etc/pam.d/su")
			switch st {
			case fileMissing:
				return []check.Result{check.SkipR("/etc/pam.d/su", "File not found")}
			case fileUnreadable:
				return []check.Result{check.IncompleteR("/etc/pam.d/su", "Not readable")}
			}
			for _, l := range activeLines(text) {
				f := strings.Fields(l)
				if len(f) >= 3 && f[0] == "auth" && strings.Contains(f[2], "pam_wheel.so") {
					return []check.Result{check.PassR("/etc/pam.d/su", "su is restricted by pam_wheel: "+l)}
				}
			}
			return []check.Result{check.FailR("/etc/pam.d/su", "No active pam_wheel line: any user may attempt su")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PAM-004", Title: "Password History Not Enforced", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      lowIdentity,
		Summary:   "Checks that PAM remembers at least the last 5 passwords so a changed password cannot be changed straight back.",
		Rationale: "When a password must be changed after a suspected compromise, the point is lost if the user can set the old one again. pam_pwhistory (or pam_unix remember=) keeps recent hashes and refuses reuse. Five is a common minimum.",
		Detection: "Reads /etc/pam.d/common-password, /etc/pam.d/system-auth and /etc/pam.d/password-auth for remember=N on a pam_pwhistory or pam_unix line, or remember in /etc/security/pwhistory.conf. N of 5 or more passes. Skipped when no password stack exists; Incomplete when one exists but cannot be read.",
		Fix:       "Add  password required pam_pwhistory.so remember=5 use_authtok  before pam_unix in the password stack (pam-auth-update on Debian/Ubuntu, authselect enable-feature with-pwhistory on the RHEL family), or set  remember = 5  in /etc/security/pwhistory.conf. Keep a root session open and test a password change in a second session before closing it: a wrong PAM line can block password changes or logins.",
		Verify:    "grep -E 'remember' /etc/pam.d/common-password /etc/pam.d/system-auth /etc/security/pwhistory.conf 2>/dev/null",
		Refs:      []check.Ref{refPAMPwhistory, refPAMUnix, refNIST63B},
		Standards: check.Standards{CWE: []string{"CWE-262"}, OWASP: []string{"A07:2021"}, NIST: []string{"IA-5(1)"}, CISTopic: "Password reuse is limited (CIS Controls v8 5.2)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, unreadable := pamStacks(ctx, s, passwordStacks)
			if len(files) == 0 {
				if len(unreadable) > 0 {
					return []check.Result{check.IncompleteR("pam", "Password stack exists but could not be read", unreadable...)}
				}
				return []check.Result{check.SkipR("pam", "PAM password stack not found")}
			}
			best, src := -1, ""
			for _, f := range files {
				for _, mod := range []string{"pam_pwhistory", "pam_unix"} {
					if v, ok := pamOption(f.Text, mod, "remember"); ok {
						if n, err := strconv.Atoi(v); err == nil && n > best {
							best, src = n, f.Path
						}
					}
				}
			}
			if best < 0 {
				if v, _, ok := collect.First(collect.ReadConfigs(ctx, s, "/etc/security/pwhistory.conf"), "remember"); ok {
					if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
						best, src = n, "/etc/security/pwhistory.conf"
					}
				}
			}
			switch {
			case best < 0:
				return []check.Result{check.FailR(files[0].Path, "No remember= setting: old passwords can be reused at once")}
			case best < 5:
				return []check.Result{check.FailR(src, fmt.Sprintf("remember=%d (recommended 5 or more)", best))}
			}
			return []check.Result{check.PassR(src, fmt.Sprintf("remember=%d", best))}
		},
	})

	loginDefsCheck("HOST-PAM-005", "Minimum Password Age Not Set", lowIdentity, check.Low, "PASS_MIN_DAYS",
		"Checks that a password cannot be changed again on the same day it was set.",
		"Password history (HOST-PAM-004) only works if users cannot cycle through several changes in a minute to get back to a favourite password. PASS_MIN_DAYS 1 closes that loop with no real cost to users.",
		"Set  PASS_MIN_DAYS 1  in /etc/login.defs, and for existing accounts  chage --mindays 1 <user> .",
		"Minimum days between password changes (CIS Controls v8 5.2)",
		func(n int) bool { return n >= 1 }, "1 or more")

	loginDefsCheck("HOST-PAM-006", "Password Expiry Warning Too Short", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", check.Info, "PASS_WARN_AGE",
		"Reports whether users are warned at least 7 days before a password expires.",
		"Where passwords do expire, a short or missing warning means users are locked out without notice and support staff reset passwords under pressure, which is when weak temporary passwords and social engineering succeed. This is informational: with no expiry (HOST-PWD-005) the warning never fires.",
		"Set  PASS_WARN_AGE 7  in /etc/login.defs, and for existing accounts  chage --warndays 7 <user> .",
		"Password expiration warning days (CIS Controls v8 5.2)",
		func(n int) bool { return n >= 7 }, "7 or more")

	check.Register(&check.Check{
		ID: "HOST-PAM-007", Title: "Inactive Accounts Never Locked", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      lowIdentity,
		Summary:   "Checks that new accounts are set to lock automatically after a password has been expired and unused for at most 30 days.",
		Rationale: "Accounts of people who left, or test accounts nobody remembers, stay usable for years unless something disables them. The INACTIVE default in /etc/default/useradd makes new accounts lock themselves a fixed number of days after their password expires.",
		Detection: "Reads INACTIVE from /etc/default/useradd. A value from 0 to 30 passes; -1 (never) or an unset value fails, because useradd's built-in default is -1. A missing file also fails for the same reason; Incomplete when the file cannot be read.",
		Fix:       "useradd -D -f 30  (writes INACTIVE=30 to /etc/default/useradd), and for existing accounts  chage --inactive 30 <user> . Caution: this locks accounts whose password has expired for 30 days, so exempt break-glass and rarely used administrator accounts or keep their passwords current.",
		Verify:    "useradd -D | grep INACTIVE",
		Refs:      []check.Ref{refUseradd, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-262"}, NIST: []string{"AC-2(3)"}, CISTopic: "Inactive password lock (CIS Controls v8 5.3)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, st := readState(ctx, s, "/etc/default/useradd")
			if st == fileUnreadable {
				return []check.Result{check.IncompleteR("/etc/default/useradd", "Not readable")}
			}
			if st == fileMissing {
				return []check.Result{check.FailR("/etc/default/useradd", "File not found, so useradd uses its built-in INACTIVE=-1 (never lock)")}
			}
			cfg := []collect.ConfigFile{{Path: "/etc/default/useradd", Values: collect.ParseKV(text), Complete: true}}
			v, _, ok := collect.First(cfg, "inactive")
			if !ok || strings.TrimSpace(v) == "" {
				return []check.Result{check.FailR("/etc/default/useradd", "INACTIVE is not set (default -1: accounts never lock)")}
			}
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return []check.Result{check.IncompleteR("/etc/default/useradd", fmt.Sprintf("INACTIVE %q is not a number", v))}
			}
			if n < 0 || n > 30 {
				return []check.Result{check.FailR("/etc/default/useradd", fmt.Sprintf("INACTIVE=%d (need 0 to 30)", n))}
			}
			return []check.Result{check.PassR("/etc/default/useradd", fmt.Sprintf("INACTIVE=%d", n))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PAM-008", Title: "Root PATH Contains Unsafe Entries", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
		Summary:   "Checks that the PATH set for root does not include the current directory, empty entries, relative paths or directories other users can write to.",
		Rationale: "When root's PATH contains . or an empty element, typing ls in a directory an attacker controls runs the attacker's ls as root. A world-writable directory on the PATH has the same effect for every command name that is not found earlier. This is one of the oldest Unix privilege escalations and still common in copied dotfiles.",
		Detection: "Reads PATH= assignments from /root/.bashrc, /root/.profile, /root/.bash_profile, /etc/environment, /etc/profile and /etc/profile.d/*.sh. Entries that are ., empty (a leading, trailing or doubled colon) or relative fail; absolute directories are stat-ed (metadata only) and fail if world-writable or not owned by root. Entries that expand variables ($PATH, $HOME) are not judged. Incomplete when no readable file sets PATH.",
		Fix:       "Edit the listed file so PATH holds only absolute, root-owned directories, for example  PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" , remove any . or trailing colon, and  chmod o-w  any listed directory. Log out and in again.",
		Verify:    "sudo -i sh -c 'echo $PATH'  should show no . or empty element;  ls -ld $(echo $PATH | tr : ' ')",
		Refs:      []check.Ref{{Title: "MITRE ATT&CK T1574.007, Hijack Execution Flow: Path Interception by PATH Environment Variable", URL: "https://attack.mitre.org/techniques/T1574/007/"}, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-426", "CWE-427"}, NIST: []string{"CM-6", "AC-6"}, CISTopic: "Root PATH integrity (CIS Controls v8 4.1)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, unreadable := readAll(ctx, s, "/root/.bashrc", "/root/.profile", "/root/.bash_profile", "/etc/environment", "/etc/profile", "/etc/profile.d/*.sh")
			var bad []string
			found := false
			for _, f := range files {
				for _, m := range pathAssign.FindAllStringSubmatch(f.Text, -1) {
					found = true
					val := strings.Trim(m[1], `"'`)
					parts := strings.Split(val, ":")
					for i, p := range parts {
						switch {
						case p == "":
							where := "doubled colon"
							if i == 0 {
								where = "leading colon"
							} else if i == len(parts)-1 {
								where = "trailing colon"
							}
							bad = append(bad, f.Path+": empty entry ("+where+") means the current directory")
						case p == ".":
							bad = append(bad, f.Path+": entry . (current directory)")
						case strings.HasPrefix(p, "$") || strings.HasPrefix(p, "~"):
							// Variable or home expansion: value depends on the login, not judged.
						case !strings.HasPrefix(p, "/"):
							bad = append(bad, f.Path+": relative entry "+p)
						default:
							if st, err := s.Stat(p); err == nil {
								if st.Mode.Perm()&0o002 != 0 {
									bad = append(bad, fmt.Sprintf("%s: %s is world-writable (mode %04o)", f.Path, p, st.Mode.Perm()))
								} else if st.UID != 0 {
									bad = append(bad, fmt.Sprintf("%s: %s is owned by uid %d, not root", f.Path, p, st.UID))
								}
							}
						}
					}
				}
			}
			if !found {
				if len(unreadable) > 0 {
					return []check.Result{check.IncompleteR("root PATH", "Shell start-up files could not be read", unreadable...)}
				}
				return []check.Result{check.IncompleteR("root PATH", "No PATH= assignment found in root's shell start-up files; the effective PATH could not be determined from files alone")}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("root PATH", "Root's PATH contains unsafe entries", bad...)}
			}
			return []check.Result{check.PassR("root PATH", "PATH assignments contain only absolute, root-owned directories")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PAM-009", Title: "No Shell Idle Timeout", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      lowLocal,
		Summary:   "Checks that interactive shells log out after at most 15 minutes without input (TMOUT).",
		Rationale: "A root shell left open on an unattended terminal, or a forgotten SSH session on a shared workstation, is free privilege for whoever sits down next. TMOUT makes bash and ksh close an idle session automatically; readonly stops users from switching it off.",
		Detection: "Reads /etc/profile, /etc/profile.d/*.sh, /etc/bash.bashrc and /etc/bashrc for a TMOUT=N assignment (optionally readonly, export, typeset -x or declare -x). N from 1 to 900 passes; 0, a larger value or no assignment fails. Incomplete when none of the files can be read.",
		Fix:       "Create /etc/profile.d/99-tmout.sh with  TMOUT=900 ; readonly TMOUT ; export TMOUT  (mode 644, owned by root). Sessions that must stay open should use a multiplexer such as tmux with its own lock, not a longer TMOUT. Caution: a readonly TMOUT ends idle interactive shells, including foreground jobs left waiting in them; run long jobs under nohup, systemd-run or a multiplexer.",
		Verify:    "grep -rE '^\\s*(readonly |export )?TMOUT=' /etc/profile /etc/profile.d/ /etc/bash.bashrc /etc/bashrc 2>/dev/null",
		Refs:      []check.Ref{refBash, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-613"}, OWASP: []string{"A07:2021"}, NIST: []string{"AC-11", "AC-12"}, CISTopic: "Default user shell timeout (CIS Controls v8 4.3)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, unreadable := readAll(ctx, s, "/etc/profile", "/etc/profile.d/*.sh", "/etc/bash.bashrc", "/etc/bashrc")
			if len(files) == 0 {
				if len(unreadable) > 0 {
					return []check.Result{check.IncompleteR("TMOUT", "Shell start-up files could not be read", unreadable...)}
				}
				return []check.Result{check.IncompleteR("TMOUT", "No shell start-up files were found")}
			}
			best, src := -1, ""
			for _, f := range files {
				for _, m := range tmoutLine.FindAllStringSubmatch(f.Text, -1) {
					if n, err := strconv.Atoi(m[1]); err == nil && (best < 0 || n > best) {
						best, src = n, f.Path
					}
				}
			}
			switch {
			case best < 0:
				return []check.Result{check.FailR("TMOUT", "No TMOUT is set in the shell start-up files")}
			case best == 0 || best > 900:
				return []check.Result{check.FailR(src, fmt.Sprintf("TMOUT=%d (need 1 to 900 seconds)", best))}
			}
			return []check.Result{check.PassR(src, fmt.Sprintf("TMOUT=%d", best))}
		},
	})
}
