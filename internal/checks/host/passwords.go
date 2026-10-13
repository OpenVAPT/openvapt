package host

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

var (
	refLoginDefs = check.Ref{Title: "login.defs(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/login.defs.5.html"}
	refNIST63B   = check.Ref{Title: "NIST SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"}
	refPwquality = check.Ref{Title: "pwquality.conf(5), libpwquality", URL: "https://man7.org/linux/man-pages/man5/pwquality.conf.5.html"}
	refFaillock  = check.Ref{Title: "pam_faillock(8), Linux-PAM", URL: "https://man7.org/linux/man-pages/man8/pam_faillock.8.html"}
)

// readText returns a file's contents, whether it was read completely, and
// whether it exists at all.
func readText(ctx context.Context, s sys.System, path string) (string, bool, bool) {
	r, err := s.ReadFile(ctx, path)
	if err != nil {
		return "", false, false
	}
	return string(r.Data), r.Complete, true
}

func init() {
	check.Register(&check.Check{
		ID: "HOST-PWD-001", Title: "Weak Password Hashing Algorithm Configured", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks that new passwords are hashed with a modern, slow algorithm (SHA-512 or yescrypt).",
		Rationale: "If the shadow file ever leaks, fast or obsolete hashes such as MD5 or DES can be cracked in minutes. Slow, salted algorithms make offline cracking far more expensive.",
		Detection: "Reads ENCRYPT_METHOD from /etc/login.defs. SHA512 and YESCRYPT pass; MD5, DES, SHA256 or an unset value on systems that default to weaker hashing fail.",
		Fix:       "Set  ENCRYPT_METHOD YESCRYPT  (or SHA512 on older systems) in /etc/login.defs, and make sure pam_unix uses the same algorithm. Ask users to change passwords so existing hashes are upgraded.",
		Verify:    "grep -i '^ENCRYPT_METHOD' /etc/login.defs",
		Refs:      []check.Ref{refLoginDefs, refNIST63B},
		Standards: check.Standards{CWE: []string{"CWE-916", "CWE-328"}, OWASP: []string{"A02:2021"}, NIST: []string{"IA-5(1)"}, CISTopic: "Password hashing algorithm"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg := collect.ReadConfigs(ctx, s, "/etc/login.defs")
			if len(cfg) == 0 {
				return []check.Result{check.SkipR("/etc/login.defs", "File not found")}
			}
			v, _, ok := collect.First(cfg, "encrypt_method")
			switch strings.ToUpper(v) {
			case "SHA512", "YESCRYPT":
				return []check.Result{check.PassR("/etc/login.defs", "ENCRYPT_METHOD "+strings.ToUpper(v))}
			}
			if !ok {
				return []check.Result{check.FailR("/etc/login.defs", "ENCRYPT_METHOD is not set; set SHA512 or YESCRYPT explicitly")}
			}
			return []check.Result{check.FailR("/etc/login.defs", "ENCRYPT_METHOD "+v+" is weak")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PWD-002", Title: "Accounts With Obsolete Password Hashes", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks /etc/shadow for passwords still stored with MD5 or traditional DES crypt.",
		Rationale: "Old hashes survive configuration changes until the user changes the password. MD5-crypt and DES hashes can be cracked quickly with commodity hardware.",
		Detection: "Reads /etc/shadow (needs root) and inspects only the hash prefix of each password field: $1$ (MD5) or a 13-character field without a $ prefix (DES) fail. The hash itself is never copied.",
		Fix:       "Configure a modern algorithm (HOST-PWD-001), then force a password change for each listed account (chage -d 0 <user>) or lock unused accounts (passwd -l <user>).",
		Verify:    "Re-run this check; no accounts should be listed.",
		Refs:      []check.Ref{{Title: "crypt(5), Linux man-pages (hashing methods)", URL: "https://man7.org/linux/man-pages/man5/crypt.5.html"}, refNIST63B},
		Standards: check.Standards{CWE: []string{"CWE-916", "CWE-328"}, OWASP: []string{"A02:2021"}, NIST: []string{"IA-5(1)"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, complete, ok := readText(ctx, s, "/etc/shadow")
			if !ok {
				return []check.Result{check.SkipR("/etc/shadow", "Not readable (run as root for this check)")}
			}
			var weak []string
			for _, line := range strings.Split(text, "\n") {
				f := strings.Split(line, ":")
				if len(f) < 2 || f[0] == "" {
					continue
				}
				h := f[1]
				if strings.HasPrefix(h, "$1$") {
					weak = append(weak, f[0]+" (MD5-crypt)")
				} else if len(h) == 13 && !strings.ContainsAny(h, "$!*") {
					weak = append(weak, f[0]+" (DES crypt)")
				}
			}
			if len(weak) > 0 {
				return []check.Result{check.FailR("/etc/shadow", "Accounts use obsolete password hashes", weak...)}
			}
			if !complete {
				return []check.Result{check.IncompleteR("/etc/shadow", "File was only partly read")}
			}
			return []check.Result{check.PassR("/etc/shadow", "No obsolete password hashes")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PWD-003", Title: "Short Minimum Password Length", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that the password quality policy requires at least 12 characters.",
		Rationale: "Length is the single most effective property against guessing. NIST SP 800-63B recommends allowing long passphrases and rejecting short passwords.",
		Detection: "Reads minlen from /etc/security/pwquality.conf and /etc/security/pwquality.conf.d/*.conf. A value below 12, or no pwquality configuration, fails.",
		Fix:       "Install libpam-pwquality (Debian/Ubuntu) or libpwquality (RHEL family) and set  minlen = 12  (or more) in /etc/security/pwquality.conf.",
		Verify:    "grep -r '^minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/",
		Refs:      []check.Ref{refPwquality, refNIST63B},
		Standards: check.Standards{CWE: []string{"CWE-521"}, OWASP: []string{"A07:2021"}, NIST: []string{"IA-5(1)"}, CISTopic: "Password creation requirements"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg := collect.ReadConfigs(ctx, s, "/etc/security/pwquality.conf.d/*.conf", "/etc/security/pwquality.conf")
			v, path, ok := collect.First(cfg, "minlen")
			if !ok {
				return []check.Result{check.FailR("pwquality", "No minimum password length is configured (pwquality minlen)")}
			}
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 12 {
				return []check.Result{check.FailR(path, "minlen = "+v+" (recommended 12 or more)")}
			}
			return []check.Result{check.PassR(path, "minlen = "+v)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PWD-004", Title: "No Account Lockout After Failed Logins", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks that PAM temporarily locks accounts after repeated failed logins.",
		Rationale: "Without lockout, local and PAM-backed remote logins can be guessed indefinitely. A temporary lock after a few failures slows attacks and makes them visible.",
		Detection: "Reads the PAM authentication stacks (/etc/pam.d/common-auth, /etc/pam.d/system-auth, /etc/pam.d/password-auth) and looks for pam_faillock or pam_tally2.",
		Fix:       "Enable pam_faillock (authselect enable-feature with-faillock on RHEL family; pam-auth-update or a faillock profile on Debian/Ubuntu) with settings such as deny=5 unlock_time=900 in /etc/security/faillock.conf. Test carefully in a second session first.",
		Verify:    "grep -E 'pam_faillock|pam_tally2' /etc/pam.d/common-auth /etc/pam.d/system-auth",
		Refs:      []check.Ref{refFaillock, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-307"}, OWASP: []string{"A07:2021"}, NIST: []string{"AC-7"}, CISTopic: "Lockout for failed password attempts"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			found := false
			for _, p := range []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"} {
				text, _, ok := readText(ctx, s, p)
				if !ok {
					continue
				}
				found = true
				for _, line := range strings.Split(text, "\n") {
					t := strings.TrimSpace(line)
					if !strings.HasPrefix(t, "#") && (strings.Contains(t, "pam_faillock") || strings.Contains(t, "pam_tally2")) {
						return []check.Result{check.PassR(p, "Account lockout module configured", t)}
					}
				}
			}
			if !found {
				return []check.Result{check.SkipR("pam", "PAM authentication stack not found")}
			}
			return []check.Result{check.FailR("pam", "No pam_faillock or pam_tally2 in the authentication stack")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-PWD-005", Title: "Passwords Never Expire by Default", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that a maximum password age is set for new accounts.",
		Rationale: "NIST no longer recommends routine forced rotation, but an upper bound (for example 365 days) still limits how long a silently compromised password stays valid, and many policies require one.",
		Detection: "Reads PASS_MAX_DAYS from /etc/login.defs. Unset, 99999, or more than 365 fails.",
		Fix:       "Set  PASS_MAX_DAYS 365  (or your policy's value) in /etc/login.defs; apply to existing users with chage --maxdays 365 <user>.",
		Verify:    "grep '^PASS_MAX_DAYS' /etc/login.defs",
		Refs:      []check.Ref{refLoginDefs, refNIST63B},
		Standards: check.Standards{CWE: []string{"CWE-262"}, NIST: []string{"IA-5(1)"}, CISTopic: "Password expiration"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg := collect.ReadConfigs(ctx, s, "/etc/login.defs")
			if len(cfg) == 0 {
				return []check.Result{check.SkipR("/etc/login.defs", "File not found")}
			}
			v, _, ok := collect.First(cfg, "pass_max_days")
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if !ok || err != nil || n > 365 {
				return []check.Result{check.FailR("/etc/login.defs", fmt.Sprintf("PASS_MAX_DAYS is %q (recommended 365 or less)", v))}
			}
			return []check.Result{check.PassR("/etc/login.defs", "PASS_MAX_DAYS "+v)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-USR-004", Title: "Duplicate User IDs", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks that no two accounts share the same numeric user id.",
		Rationale: "Accounts with the same UID are the same user to the kernel: they own each other's files and processes, and audit logs cannot tell them apart.",
		Detection: "Reads /etc/passwd and reports any UID used by more than one account.",
		Fix:       "Give each account a unique UID (usermod -u <new-uid> <user>) and fix file ownership (find / -xdev -uid <old-uid>).",
		Verify:    "cut -d: -f3 /etc/passwd | sort | uniq -d  should print nothing.",
		Refs:      []check.Ref{{Title: "passwd(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/passwd.5.html"}},
		Standards: check.Standards{CWE: []string{"CWE-286"}, NIST: []string{"AC-2", "IA-2"}, CISTopic: "No duplicate UIDs"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, _, ok := readText(ctx, s, "/etc/passwd")
			if !ok {
				return []check.Result{check.SkipR("/etc/passwd", "Not readable")}
			}
			byUID := map[string][]string{}
			var order []string
			for _, line := range strings.Split(text, "\n") {
				f := strings.Split(line, ":")
				if len(f) >= 3 && f[0] != "" && !strings.HasPrefix(f[0], "+") {
					if _, seen := byUID[f[2]]; !seen {
						order = append(order, f[2])
					}
					byUID[f[2]] = append(byUID[f[2]], f[0])
				}
			}
			var dup []string
			for _, uid := range order {
				if len(byUID[uid]) > 1 {
					dup = append(dup, "UID "+uid+": "+strings.Join(byUID[uid], ", "))
				}
			}
			if len(dup) > 0 {
				return []check.Result{check.FailR("/etc/passwd", "Accounts share user ids", dup...)}
			}
			return []check.Result{check.PassR("/etc/passwd", "Every account has a unique UID")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-USR-005", Title: "System Accounts With Login Shells", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks that service accounts (UID below 1000, other than root) cannot log in interactively.",
		Rationale: "Service accounts should never need a shell. A login shell gives an attacker who compromises the service, or guesses its password, an interactive foothold.",
		Detection: "Reads /etc/passwd and lists accounts with UID 1 to 999 whose shell is not nologin, false, sync, halt or shutdown.",
		Fix:       "usermod -s /usr/sbin/nologin <account>  for each listed account (use /sbin/nologin on RHEL family).",
		Verify:    "awk -F: '$3>0 && $3<1000 {print $1, $7}' /etc/passwd",
		Refs:      []check.Ref{{Title: "nologin(8), Linux man-pages", URL: "https://man7.org/linux/man-pages/man8/nologin.8.html"}},
		Standards: check.Standards{CWE: []string{"CWE-250"}, NIST: []string{"AC-2", "CM-7"}, CISTopic: "System accounts are secured"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, _, ok := readText(ctx, s, "/etc/passwd")
			if !ok {
				return []check.Result{check.SkipR("/etc/passwd", "Not readable")}
			}
			var bad []string
			for _, line := range strings.Split(text, "\n") {
				f := strings.Split(line, ":")
				if len(f) < 7 {
					continue
				}
				uid, err := strconv.Atoi(f[2])
				if err != nil || uid < 1 || uid >= 1000 {
					continue
				}
				sh := f[6]
				if strings.HasSuffix(sh, "nologin") || strings.HasSuffix(sh, "/false") || strings.HasSuffix(sh, "/sync") || strings.HasSuffix(sh, "/halt") || strings.HasSuffix(sh, "/shutdown") {
					continue
				}
				bad = append(bad, f[0]+" ("+sh+")")
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/etc/passwd", "System accounts have login shells", bad...)}
			}
			return []check.Result{check.PassR("/etc/passwd", "System accounts have no login shell")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-USR-006", Title: "Legacy NIS Entries in Account Files", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks /etc/passwd, /etc/shadow and /etc/group for legacy '+' NIS inclusion entries.",
		Rationale: "'+' entries pull accounts from NIS, an unencrypted legacy directory service. If NIS is gone, the entry can still be abused to create unexpected accounts.",
		Detection: "Reads the account files and lists lines beginning with '+'.",
		Fix:       "Remove the '+' lines (with vipw / vigr) and use a modern directory service such as SSSD with LDAPS if central accounts are needed.",
		Verify:    "grep '^+' /etc/passwd /etc/shadow /etc/group  should print nothing.",
		Refs:      []check.Ref{{Title: "nsswitch.conf(5), Linux man-pages (compat mode)", URL: "https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html"}},
		Standards: check.Standards{CWE: []string{"CWE-287"}, NIST: []string{"IA-2", "CM-7"}, CISTopic: "No legacy + entries"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var bad []string
			for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/group"} {
				text, _, ok := readText(ctx, s, p)
				if !ok {
					continue
				}
				for _, line := range strings.Split(text, "\n") {
					if strings.HasPrefix(line, "+") {
						bad = append(bad, p+": "+strings.SplitN(line, ":", 2)[0])
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("account files", "Legacy NIS '+' entries found", bad...)}
			}
			return []check.Result{check.PassR("account files", "No legacy NIS entries")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-USR-007", Title: "Insecure Trust Files in Home Directories", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Looks for .rhosts, .shosts and .netrc files in user home directories.",
		Rationale: ".rhosts and .shosts grant password-less trust to other hosts. .netrc files usually hold plain-text passwords for FTP or other services.",
		Detection: "Reads home directories from /etc/passwd and checks each for .rhosts, .shosts and .netrc (file existence only; contents are never read).",
		Fix:       "Delete .rhosts and .shosts files. Replace .netrc credentials with a secret manager or key-based authentication, then delete the file and rotate the passwords it contained.",
		Verify:    "Re-run this check; no files should be listed.",
		Refs:      []check.Ref{{Title: "MITRE ATT&CK T1552.001, Unsecured Credentials: Credentials In Files", URL: "https://attack.mitre.org/techniques/T1552/001/"}},
		Standards: check.Standards{CWE: []string{"CWE-256", "CWE-287"}, NIST: []string{"IA-5", "CM-6"}, CISTopic: "No .rhosts, .netrc files"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, _, ok := readText(ctx, s, "/etc/passwd")
			if !ok {
				return []check.Result{check.SkipR("/etc/passwd", "Not readable")}
			}
			var bad []string
			for _, line := range strings.Split(text, "\n") {
				f := strings.Split(line, ":")
				if len(f) < 6 || f[5] == "" || f[5] == "/" {
					continue
				}
				for _, n := range []string{".rhosts", ".shosts", ".netrc"} {
					if _, err := s.Stat(f[5] + "/" + n); err == nil {
						bad = append(bad, f[5]+"/"+n)
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("home directories", "Insecure trust or credential files found", bad...)}
			}
			return []check.Result{check.PassR("home directories", "No .rhosts, .shosts or .netrc files")}
		},
	})
}
