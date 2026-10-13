package host

import (
	"context"
	"strconv"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "HOST-SSH-005",
		Title:     "SSH X11 Forwarding Enabled",
		Domain:    check.DomainHost,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
		Summary:   "Checks whether SSH forwards graphical X11 sessions.",
		Rationale: "Servers rarely need X11. Forwarding it exposes the connecting user's display to anyone with root on the server, and widens the attack surface of sshd.",
		Detection: "Reads X11Forwarding from the effective sshd configuration; 'yes' fails. A risky value set inside a Match block in the config files fails as a conditional finding, with the Match condition in the evidence.",
		Fix:       "Set  X11Forwarding no  in /etc/ssh/sshd_config and reload sshd.",
		Verify:    "sshd -T | grep -i x11forwarding  should print 'no'.",
		Refs:      []check.Ref{refSSHDManual},
		Standards: check.Standards{CWE: []string{"CWE-1188"}, NIST: []string{"CM-7"}, CISTopic: "SSH server configuration: X11 forwarding"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			if cfg["x11forwarding"] == "yes" {
				return []check.Result{check.FailR("sshd", "X11 forwarding is enabled", "x11forwarding yes")}
			}
			if r, bad := sshMatchFail(cfg, "X11 forwarding is enabled", "x11forwarding"); bad {
				return []check.Result{r}
			}
			return []check.Result{check.PassR("sshd", "X11 forwarding is disabled")}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-SSH-006",
		Title:     "SSH Allows Many Authentication Attempts",
		Domain:    check.DomainHost,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks whether MaxAuthTries is above 4.",
		Rationale: "Each connection may try this many passwords or keys. A low limit slows guessing and makes attacks show up in the logs sooner.",
		Detection: "Reads MaxAuthTries (OpenSSH default 6); a value above 4 fails.",
		Fix:       "Set  MaxAuthTries 4  (or lower) in /etc/ssh/sshd_config and reload sshd. Consider fail2ban or sshguard for rate limiting.",
		Verify:    "sshd -T | grep -i maxauthtries  should print 4 or lower.",
		Refs:      []check.Ref{refSSHDManual},
		Standards: check.Standards{CWE: []string{"CWE-307"}, NIST: []string{"AC-7"}, CISTopic: "SSH server configuration: MaxAuthTries"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			n := 6
			if v, set := cfg["maxauthtries"]; set {
				if x, err := strconv.Atoi(v); err == nil {
					n = x
				}
			}
			if n > 4 {
				return []check.Result{check.FailR("sshd", "MaxAuthTries is "+strconv.Itoa(n)+" (recommended 4 or lower)")}
			}
			return []check.Result{check.PassR("sshd", "MaxAuthTries is "+strconv.Itoa(n))}
		},
	})
}
