package host

import (
	"context"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "HOST-SSH-002",
		Title:     "SSH Password Authentication Enabled",
		Domain:    check.DomainHost,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
		Summary:   "Checks whether SSH accepts passwords instead of only keys.",
		Rationale: "Internet-facing SSH receives constant automated password guessing. Public-key authentication cannot be guessed, phished as easily, or reused from another breached site.",
		Detection: "Reads PasswordAuthentication and KbdInteractiveAuthentication (ChallengeResponseAuthentication on older versions) from the effective sshd configuration. Either set to 'yes' fails.",
		Fix:       "Install your public key for each admin user (ssh-copy-id), confirm key login works in a second session, then set  PasswordAuthentication no  and  KbdInteractiveAuthentication no  in /etc/ssh/sshd_config and reload sshd.",
		Verify:    "sshd -T | grep -Ei 'passwordauthentication|kbdinteractive'  should show 'no' for both.",
		Refs:      []check.Ref{refSSHDManual, {Title: "NIST SP 800-63B, Digital Identity Guidelines: Authentication", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"}},
		Standards: check.Standards{CWE: []string{"CWE-307", "CWE-521"}, NIST: []string{"IA-2(1)", "IA-5"}, CISTopic: "SSH server configuration: authentication methods"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			pw := cfg["passwordauthentication"]
			kbd := cfg["kbdinteractiveauthentication"]
			if kbd == "" {
				kbd = cfg["challengeresponseauthentication"]
			}
			if pw == "yes" || pw == "" {
				return []check.Result{check.FailR("sshd", "Password logins are accepted (PasswordAuthentication defaults to yes)", "passwordauthentication "+orDefault(pw))}
			}
			if kbd == "yes" {
				return []check.Result{check.FailR("sshd", "Keyboard-interactive (password-style) logins are accepted", "kbdinteractiveauthentication yes")}
			}
			return []check.Result{check.PassR("sshd", "Only key-based SSH authentication is accepted")}
		},
	})
}

func orDefault(v string) string {
	if v == "" {
		return "(not set, default applies)"
	}
	return v
}
