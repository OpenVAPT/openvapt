package host

import (
	"context"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "HOST-SSH-003",
		Title:     "SSH Permits Empty Passwords",
		Domain:    check.DomainHost,
		Severity:  check.Critical,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether SSH lets accounts with an empty password log in.",
		Rationale: "Any account without a password becomes an open door to anyone on the network.",
		Detection: "Reads PermitEmptyPasswords from the effective sshd configuration; 'yes' fails. A risky value set inside a Match block in the config files fails as a conditional finding, with the Match condition in the evidence.",
		Fix:       "Set  PermitEmptyPasswords no  in /etc/ssh/sshd_config, reload sshd, and give every account a password or lock it (passwd -l <user>).",
		Verify:    "sshd -T | grep -i permitemptypasswords  should print 'no'.",
		Refs:      []check.Ref{refSSHDManual},
		Standards: check.Standards{CWE: []string{"CWE-258"}, NIST: []string{"IA-5(1)"}, CISTopic: "SSH server configuration: empty passwords"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			if cfg["permitemptypasswords"] == "yes" {
				return []check.Result{check.FailR("sshd", "Empty passwords are accepted", "permitemptypasswords yes")}
			}
			if r, bad := sshMatchFail(cfg, "Empty passwords are accepted", "permitemptypasswords"); bad {
				return []check.Result{r}
			}
			return []check.Result{check.PassR("sshd", "Empty passwords are refused")}
		},
	})
}
