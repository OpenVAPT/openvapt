package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "NET-TLS-004",
		Title:     "Weak TLS 1.2 Cipher Suites Accepted",
		Domain:    check.DomainNetwork,
		Severity:  check.Medium,
		Category:  check.CatCrypto,
		Effort:    check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
		Summary:   "A local TLS service accepts an RC4, 3DES, or CBC with SHA-1 cipher suite under TLS 1.2.",
		Rationale: "Obsolete cipher constructions lack modern authenticated encryption and are prohibited by current TLS hardening guidance.",
		Detection: "Offers restricted TLS 1.2 cipher lists to loopback services. A successful handshake proves the weak suite is accepted. Go does not implement NULL, EXPORT, or anonymous suites, so those cannot be actively offered and remain a documented limitation.",
		Fix:       "Allow only modern AEAD suites for TLS 1.2 and prefer TLS 1.3. Remove RC4, 3DES, NULL, EXPORT, anonymous, and CBC with SHA-1 suites. Caution: very old clients and devices that support only those suites stop connecting; check the access logs for them first.",
		Verify:    "Use an approved local TLS scanner and confirm each prohibited TLS 1.2 suite is rejected. Implicit TLS mail ports 465, 993, and 995 are included; STARTTLS is out of scope.",
		Refs:      refTLS,
		Standards: check.Standards{CWE: []string{"CWE-326", "CWE-327"}, OWASP: []string{"A02:2021"}, WSTG: []string{"WSTG-CRYP-01"}, ASVS: []string{"9.1.3"}, NIST: []string{"SC-8", "SC-13"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			targets := tlsTargets(s)
			if len(targets) == 0 {
				return []check.Result{check.SkipR("TLS", "No local implicit TLS service was found")}
			}
			weak := []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}
			var out []check.Result
			for _, t := range targets {
				target := t[1] + " on port " + t[0]
				accepted := []string{}
				for _, suite := range weak {
					if info, err := s.TLSWithCiphers(ctx, t[0], t[1], []uint16{suite}); err == nil {
						accepted = append(accepted, tls.CipherSuiteName(info.Cipher))
					}
				}
				if len(accepted) > 0 {
					out = append(out, check.FailR(target, "Weak TLS 1.2 cipher suite accepted", accepted...))
				} else {
					out = append(out, check.PassR(target, "Testable weak TLS 1.2 cipher suites were rejected"))
				}
			}
			return out
		}})
	check.Register(&check.Check{
		ID:        "NET-TLS-005",
		Title:     "TLS Certificate Public Key Too Small",
		Domain:    check.DomainNetwork,
		Severity:  check.Medium,
		Category:  check.CatCrypto,
		Effort:    check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
		Summary:   "A TLS leaf certificate uses RSA below 2048 bits or an elliptic curve below 256 bits.",
		Rationale: "Undersized public keys provide inadequate security strength and may permit certificate impersonation as cryptanalytic capability improves.",
		Detection: "Reads the leaf public key from loopback TLS handshakes and measures RSA modulus or elliptic curve size.",
		Fix:       "Replace the certificate and private key with RSA 2048 bits or stronger, or an approved EC key of at least 256 bits.",
		Verify:    "Inspect the renewed leaf certificate key size on ports 443, 465, 993, 995, 8443, and 10000. STARTTLS is out of scope.",
		Refs:      []check.Ref{{Title: "NIST SP 800-131A Rev. 2, Transitioning the Use of Cryptographic Algorithms and Key Lengths", URL: "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"}},
		Standards: check.Standards{CWE: []string{"CWE-326"}, OWASP: []string{"A02:2021"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-12", "SC-13"}},
		Run: certDepthRun(func(i sys.TLSInfo) bool {
			return strings.EqualFold(i.PublicKeyAlgorithm, "RSA") && i.PublicKeyBits < 2048 || (strings.EqualFold(i.PublicKeyAlgorithm, "ECDSA") || strings.Contains(strings.ToLower(i.PublicKeyAlgorithm), "elliptic")) && i.PublicKeyBits < 256
		}, "Leaf certificate public key is too small")})
	check.Register(&check.Check{
		ID:        "NET-TLS-006",
		Title:     "SHA-1 Signed TLS Leaf Certificate",
		Domain:    check.DomainNetwork,
		Severity:  check.Medium,
		Category:  check.CatCrypto,
		Effort:    check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
		Summary:   "A TLS leaf certificate is signed using SHA-1.",
		Rationale: "SHA-1 collision attacks invalidate its use for digital signatures and modern clients reject SHA-1 certificates.",
		Detection: "Reads the leaf certificate signature algorithm from loopback implicit TLS handshakes and flags SHA-1.",
		Fix:       "Reissue the certificate with SHA-256 or stronger and deploy the complete updated chain.",
		Verify:    "Inspect the signature algorithm on each implicit TLS service. STARTTLS is out of scope.",
		Refs:      []check.Ref{{Title: "NIST Transitioning Away from SHA-1", URL: "https://csrc.nist.gov/News/2022/nist-transitioning-away-from-sha-1-for-all-apps"}},
		Standards: check.Standards{CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-12", "SC-13"}},
		Run: certDepthRun(func(i sys.TLSInfo) bool {
			return strings.Contains(strings.ToLower(i.SignatureAlgorithm), "sha-1") || strings.Contains(strings.ToLower(i.SignatureAlgorithm), "sha1")
		}, "Leaf certificate uses a SHA-1 signature")})
}

func certDepthRun(bad func(sys.TLSInfo) bool, msg string) func(context.Context, sys.System) []check.Result {
	return func(ctx context.Context, s sys.System) []check.Result {
		targets := tlsTargets(s)
		if len(targets) == 0 {
			return []check.Result{check.SkipR("TLS", "No local implicit TLS service was found")}
		}
		var out []check.Result
		for _, t := range targets {
			target := t[1] + " on port " + t[0]
			i, err := s.TLS(ctx, t[0], t[1], tls.VersionTLS12, tls.VersionTLS13)
			if err != nil {
				out = append(out, check.IncompleteR(target, "TLS certificate could not be read"))
				continue
			}
			if i.PublicKeyBits == 0 || i.SignatureAlgorithm == "" {
				out = append(out, check.IncompleteR(target, "Certificate key or signature metadata was unavailable"))
				continue
			}
			if bad(i) {
				out = append(out, check.FailR(target, msg, fmt.Sprintf("key %s %d bits, signature %s", i.PublicKeyAlgorithm, i.PublicKeyBits, i.SignatureAlgorithm)))
			} else {
				out = append(out, check.PassR(target, "Certificate key strength and signature metadata passed this check"))
			}
		}
		return out
	}
}
