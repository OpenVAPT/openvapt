package host

import (
	"context"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "HOST-SSH-001",
		Title:     "SSH Allows Direct Root Login",
		Domain:    check.DomainHost,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether the SSH daemon accepts logins as root with a password.",
		Rationale: "Root is the one account name every attacker knows. Allowing it over SSH turns any password guess into full control of the server, and removes the audit trail of which person used root.",
		Detection: "Reads the effective sshd configuration (sshd -T, or the config files as a fallback) and inspects PermitRootLogin. The values 'yes' (and missing, on old OpenSSH where the default was yes) fail. 'prohibit-password', 'without-password', 'forced-commands-only' and 'no' pass. A risky value set inside a Match block in the config files fails as a conditional finding, with the Match condition in the evidence.",
		Fix:       "In /etc/ssh/sshd_config set:  PermitRootLogin no  (or prohibit-password if key-based root login is truly required). Log in as a named user and use sudo. Then run: sshd -t && systemctl reload sshd",
		Verify:    "sshd -T | grep -i permitrootlogin  should print 'permitrootlogin no'.",
		Refs:      []check.Ref{refSSHDManual, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-250"}, NIST: []string{"AC-6(2)", "IA-2"}, CISTopic: "SSH server configuration: root login"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			v, set := cfg["permitrootlogin"]
			if v == "yes" {
				return []check.Result{check.FailR("sshd", "Root may log in over SSH with a password", "permitrootlogin "+v)}
			}
			if !set {
				return []check.Result{check.FailR("sshd", "PermitRootLogin is not set explicitly; older OpenSSH defaults to yes")}
			}
			if r, bad := sshMatchFail(cfg, "Root may log in over SSH with a password", "permitrootlogin"); bad {
				return []check.Result{r}
			}
			return []check.Result{check.PassR("sshd", "Direct root password login is disabled", "permitrootlogin "+v)}
		},
	})
}
