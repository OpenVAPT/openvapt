package host

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "HOST-USR-001",
		Title:     "Extra Accounts With Root Privileges (UID 0)",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks /etc/passwd for accounts other than root that have user id 0.",
		Rationale: "Any account with UID 0 is root, whatever its name. Extra UID 0 accounts are a classic backdoor and bypass sudo logging.",
		Detection: "Reads /etc/passwd and lists every entry whose third field (UID) is 0, other than 'root'.",
		Fix:       "Investigate who created each account. Remove it (userdel <name>) or give it a normal UID (usermod -u <new-uid> <name>). Grant admin rights through sudo instead.",
		Verify:    "awk -F: '$3==0' /etc/passwd  should print only the root line.",
		Refs:      []check.Ref{{Title: "passwd(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/passwd.5.html"}, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-250", "CWE-266"}, NIST: []string{"AC-2", "AC-6"}, CISTopic: "User accounts: root is the only UID 0 account"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			r, err := s.ReadFile(ctx, "/etc/passwd")
			if err != nil {
				return []check.Result{check.ErrR("/etc/passwd", err)}
			}
			var extra []string
			if !r.Complete {
				return []check.Result{check.IncompleteR("/etc/passwd", "File was truncated while reading")}
			}
			for _, line := range strings.Split(string(r.Data), "\n") {
				f := strings.Split(line, ":")
				if len(f) >= 4 && f[2] == "0" && f[0] != "root" {
					extra = append(extra, f[0]+":x:0:"+f[3])
				}
			}
			if len(extra) > 0 {
				return []check.Result{check.FailR("/etc/passwd", "Accounts other than root have UID 0", extra...)}
			}
			return []check.Result{check.PassR("/etc/passwd", "Only root has UID 0")}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-USR-002",
		Title:     "Accounts Without a Password",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks /etc/shadow for accounts whose password field is empty.",
		Rationale: "An empty password field means the account can log in with no password at all on any service that allows password logins. The score uses a local attack vector: any local user can switch to the account (su) without a password, while the SSH daemon refuses empty passwords unless PermitEmptyPasswords is yes. If HOST-SSH-003 also fails, the same account is open from the network and should be treated as Critical.",
		Detection: "Reads /etc/shadow (needs root) and lists entries whose second field is empty. Locked ('!' or '*') entries pass. Hashes are never copied into the report.",
		Fix:       "For each listed user either set a password (passwd <user>) or lock the account (passwd -l <user>).",
		Verify:    "awk -F: '$2==\"\"' /etc/shadow  should print nothing.",
		Refs:      []check.Ref{{Title: "shadow(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/shadow.5.html"}},
		Standards: check.Standards{CWE: []string{"CWE-258", "CWE-521"}, NIST: []string{"IA-5"}, CISTopic: "User accounts: password fields are not empty"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			r, err := s.ReadFile(ctx, "/etc/shadow")
			if err != nil {
				return []check.Result{check.SkipR("/etc/shadow", "Not readable (run as root for this check)")}
			}
			var empty []string
			if !r.Complete {
				return []check.Result{check.IncompleteR("/etc/shadow", "File was truncated while reading")}
			}
			for _, line := range strings.Split(string(r.Data), "\n") {
				f := strings.Split(line, ":")
				if len(f) >= 2 && f[0] != "" && f[1] == "" {
					empty = append(empty, f[0])
				}
			}
			if len(empty) > 0 {
				return []check.Result{check.FailR("/etc/shadow", "Accounts have an empty password", empty...)}
			}
			return []check.Result{check.PassR("/etc/shadow", "Every account has a password or is locked")}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-USR-003",
		Title:     "Sudo Rules Without Password (NOPASSWD)",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks sudoers files for rules that grant root without asking for a password.",
		Rationale: "NOPASSWD means anyone who takes over that user (a stolen SSH key, a hijacked session, a web shell running as that user) becomes root instantly.",
		Detection: "Reads /etc/sudoers and /etc/sudoers.d/* and lists active lines containing NOPASSWD.",
		Fix:       "Edit with visudo and remove NOPASSWD, or restrict it to one specific, harmless command for automation accounts.",
		Verify:    "grep -r NOPASSWD /etc/sudoers /etc/sudoers.d  should print nothing, or only narrowly scoped commands.",
		Refs:      []check.Ref{{Title: "sudoers(5) manual", URL: "https://www.sudo.ws/docs/man/sudoers.man/"}},
		Standards: check.Standards{CWE: []string{"CWE-306"}, NIST: []string{"AC-6", "IA-11"}, CISTopic: "Sudo: re-authentication for privilege escalation"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files := []string{"/etc/sudoers"}
			more, _ := s.Glob("/etc/sudoers.d/*")
			files = append(files, more...)
			var hits []string
			readable := false
			complete := true
			for _, f := range files {
				r, err := s.ReadFile(ctx, f)
				if err != nil {
					continue
				}
				readable = true
				complete = complete && r.Complete
				for _, line := range strings.Split(string(r.Data), "\n") {
					t := strings.TrimSpace(line)
					if !strings.HasPrefix(t, "#") && strings.Contains(t, "NOPASSWD") {
						hits = append(hits, f+": "+t)
					}
				}
			}
			if !readable {
				return []check.Result{check.SkipR("/etc/sudoers", "Not readable (run as root for this check)")}
			}
			if len(hits) > 0 {
				return []check.Result{check.FailR("/etc/sudoers", "Sudo rules grant root without a password", hits...)}
			}
			if !complete {
				return []check.Result{check.IncompleteR("/etc/sudoers", "One or more sudoers files were truncated")}
			}
			return []check.Result{check.PassR("/etc/sudoers", "No NOPASSWD sudo rules")}
		},
	})
}
