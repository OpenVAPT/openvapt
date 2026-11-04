package host

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// weakSSH lists algorithm name fragments considered weak. Sources: RFC 9142
// (key exchange), RFC 8758 (RC4 deprecated), and the OpenSSH release notes
// that removed or disabled these algorithms by default.
var weakSSH = []string{"cbc", "arcfour", "3des", "blowfish", "hmac-md5", "hmac-sha1", "umac-64",
	"diffie-hellman-group1-", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "ssh-dss"}

// sshRSASHA1 reports the SHA-1 based RSA signature algorithm "ssh-rsa"
// (and its certificate form), disabled by default since OpenSSH 8.8.
func sshRSASHA1(alg string) bool {
	return alg == "ssh-rsa" || alg == "ssh-rsa-cert-v01@openssh.com"
}

func init() {
	check.Register(&check.Check{
		ID:        "HOST-SSH-004",
		Title:     "SSH Offers Weak Cryptography",
		Domain:    check.DomainHost,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks the SSH ciphers, MACs, key exchange and host key algorithms for outdated choices.",
		Rationale: "CBC-mode ciphers, RC4, MD5/SHA-1 MACs and 1024-bit Diffie-Hellman have known practical weaknesses. Offering them lets a network attacker downgrade or weaken the session.",
		Detection: "Reads ciphers, macs, kexalgorithms and hostkeyalgorithms from sshd -T and flags any algorithm whose name contains a known-weak fragment, plus the SHA-1 based ssh-rsa host key signature algorithm.",
		Fix:       "Remove the listed algorithms. On OpenSSH 8.x and later the defaults are already strong: delete any custom Ciphers/MACs/KexAlgorithms lines, or set explicit modern lists such as  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com  then reload sshd.",
		Verify:    "sshd -T | grep -Ei '^(ciphers|macs|kexalgorithms)'  should list no cbc, arcfour, md5 or sha1 entries, and hostkeyalgorithms should not list ssh-rsa.",
		Refs: []check.Ref{refSSHDManual,
			{Title: "RFC 9142, Key Exchange Method Updates for SSH", URL: "https://www.rfc-editor.org/rfc/rfc9142.html"},
			{Title: "NIST SP 800-131A Rev. 2, Transitioning Cryptographic Algorithms", URL: "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"}},
		Standards: check.Standards{CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "SSH server configuration: approved ciphers, MACs and KEX"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			var bad []string
			for _, key := range []string{"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"} {
				for _, alg := range strings.Split(cfg[key], ",") {
					for _, w := range weakSSH {
						if alg != "" && (strings.Contains(alg, w) || key == "hostkeyalgorithms" && sshRSASHA1(alg)) {
							bad = append(bad, key+": "+alg)
							break
						}
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("sshd", "Weak SSH algorithms are offered", bad...)}
			}
			if cfg["ciphers"] == "" {
				return []check.Result{check.SkipR("sshd", "Algorithm lists not available (sshd -T not readable); OpenSSH defaults assumed")}
			}
			return []check.Result{check.PassR("sshd", "No weak SSH algorithms offered")}
		},
	})
}
