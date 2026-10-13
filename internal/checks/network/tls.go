package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

var refTLS = []check.Ref{
	{Title: "RFC 8996, Deprecating TLS 1.0 and TLS 1.1", URL: "https://www.rfc-editor.org/rfc/rfc8996"},
	{Title: "NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations", URL: "https://csrc.nist.gov/pubs/sp/800/52/r2/final"},
	{Title: "Mozilla Server Side TLS guidelines", URL: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
}

// tlsTargets returns (port, SNI name) pairs: port 443 for every local vhost,
// plus other common TLS ports that are listening, using the first vhost name.
func tlsTargets(s sys.System) [][2]string {
	ls, _ := collect.Listeners(s)
	vh := collect.VHosts(s)
	var out [][2]string
	if collect.ListensOn(ls, 443) {
		for _, v := range vh {
			out = append(out, [2]string{"443", v})
		}
		if len(vh) == 0 {
			out = append(out, [2]string{"443", "localhost"})
		}
	}
	name := "localhost"
	if len(vh) > 0 {
		name = vh[0]
	}
	for _, p := range []int{465, 993, 995, 8443, 10000} {
		if collect.ListensOn(ls, p) {
			out = append(out, [2]string{fmt.Sprint(p), name})
		}
	}
	return out
}

func init() {
	check.Register(&check.Check{
		ID:        "NET-TLS-001",
		Title:     "Deprecated TLS 1.0 or 1.1 Accepted",
		Domain:    check.DomainNetwork,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks whether local TLS services still accept TLS 1.0 or TLS 1.1.",
		Rationale: "TLS 1.0 and 1.1 were formally deprecated by RFC 8996 in 2021. They rely on outdated constructions (e.g. SHA-1 in the handshake) and fail PCI DSS and most compliance baselines.",
		Detection: "For each local TLS port and site name, attempts a handshake with 127.0.0.1 limited to TLS 1.0 only, then TLS 1.1 only. A completed handshake fails the check.",
		Fix:       "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3 . nginx: ssl_protocols TLSv1.2 TLSv1.3; . Postfix/Dovecot: set the minimum protocol to TLSv1.2. Reload the service afterwards.",
		Verify:    "openssl s_client -connect 127.0.0.1:443 -tls1_1 </dev/null  should fail to connect.",
		Refs:      refTLS,
		Standards: check.Standards{CWE: []string{"CWE-326", "CWE-327"}, OWASP: []string{"A02:2021"}, WSTG: []string{"WSTG-CRYP-01"}, ASVS: []string{"9.1.3"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "TLS protocol versions"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			targets := tlsTargets(s)
			if len(targets) == 0 {
				return []check.Result{check.SkipR("tls", "No local TLS services found")}
			}
			var out []check.Result
			for _, t := range targets {
				target := t[1] + " on port " + t[0]
				if _, err := s.TLS(ctx, t[0], t[1], tls.VersionTLS12, tls.VersionTLS13); err != nil {
					out = append(out, check.IncompleteR(target, "Modern TLS handshake failed, so legacy protocol rejection could not be verified", err.Error()))
					continue
				}
				var weak []string
				uncertain := false
				for _, v := range []struct {
					n string
					v uint16
				}{{"TLS 1.0", tls.VersionTLS10}, {"TLS 1.1", tls.VersionTLS11}} {
					if _, err := s.TLS(ctx, t[0], t[1], v.v, v.v); err == nil {
						weak = append(weak, v.n+" accepted")
					} else if ctx.Err() != nil || strings.Contains(strings.ToLower(err.Error()), "timeout") || strings.Contains(strings.ToLower(err.Error()), "connection reset") {
						uncertain = true
					}
				}
				if len(weak) > 0 {
					out = append(out, check.FailR(target, "Deprecated TLS versions accepted", weak...))
				} else if uncertain {
					out = append(out, check.IncompleteR(target, "A legacy TLS probe ended without a protocol-rejection result"))
				} else {
					out = append(out, check.PassR(target, "TLS 1.0 and 1.1 refused"))
				}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID:        "NET-TLS-002",
		Title:     "TLS Certificate Expired or Expiring Soon",
		Domain:    check.DomainNetwork,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L",
		Summary:   "Checks the expiry date of the certificate each local TLS service presents.",
		Rationale: "An expired certificate breaks the site for visitors and trains users to click through warnings, which is exactly what an attacker needs for interception.",
		Detection: "Performs a normal handshake with 127.0.0.1 using each site name as SNI and reads the leaf certificate's NotAfter date. Expired fails; fewer than 21 days left also fails.",
		Fix:       "Renew the certificate (certbot renew, or your provider's process) and make sure renewal is automated (systemctl list-timers | grep certbot).",
		Verify:    "echo | openssl s_client -connect 127.0.0.1:443 -servername <site> 2>/dev/null | openssl x509 -noout -enddate",
		Refs:      append([]check.Ref{{Title: "Let's Encrypt, certificate lifetimes and renewal", URL: "https://letsencrypt.org/docs/faq/"}}, refTLS[1]),
		Standards: check.Standards{CWE: []string{"CWE-298"}, OWASP: []string{"A02:2021"}, WSTG: []string{"WSTG-CRYP-01"}, ASVS: []string{"9.2.1"}, NIST: []string{"SC-12", "SC-17"}, CISTopic: "Certificate validity"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			targets := tlsTargets(s)
			if len(targets) == 0 {
				return []check.Result{check.SkipR("tls", "No local TLS services found")}
			}
			var out []check.Result
			for _, t := range targets {
				target := t[1] + " on port " + t[0]
				info, err := s.TLS(ctx, t[0], t[1], tls.VersionTLS12, tls.VersionTLS13)
				if err != nil || info.NotAfter.IsZero() {
					continue
				}
				days := int(time.Until(info.NotAfter).Hours() / 24)
				ev := "notAfter " + info.NotAfter.UTC().Format("2006-01-02")
				switch {
				case days < 0:
					out = append(out, check.FailR(target, "Certificate has expired", ev))
				case days < 21:
					out = append(out, check.FailR(target, fmt.Sprintf("Certificate expires in %d days", days), ev))
				default:
					out = append(out, check.PassR(target, fmt.Sprintf("Certificate valid for %d more days", days), ev))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("tls", "No certificate could be read")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID:        "NET-TLS-003",
		Title:     "Self-Signed or Mismatched TLS Certificate",
		Domain:    check.DomainNetwork,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
		Summary:   "Checks whether each site presents a self-signed certificate, or one that does not cover its name.",
		Rationale: "Browsers reject these certificates, so visitors either leave or learn to ignore warnings, which removes protection against interception.",
		Detection: "Reads the leaf certificate from a loopback handshake per site name. Issuer equal to subject means self-signed; the site name must appear in the certificate's DNS names (wildcards honoured).",
		Fix:       "Issue a certificate from a public CA covering every site name, for example with certbot --apache or certbot --nginx -d example.com -d www.example.com.",
		Verify:    "openssl s_client -connect 127.0.0.1:443 -servername <site> </dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName",
		Refs:      append([]check.Ref{{Title: "RFC 6125, Representation and Verification of Domain-Based Application Service Identity", URL: "https://www.rfc-editor.org/rfc/rfc6125"}}, refTLS[1]),
		Standards: check.Standards{CWE: []string{"CWE-295", "CWE-297"}, OWASP: []string{"A02:2021", "A07:2021"}, WSTG: []string{"WSTG-CRYP-01"}, ASVS: []string{"9.2.1"}, NIST: []string{"SC-17"}, CISTopic: "Certificate trust"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var out []check.Result
			for _, t := range tlsTargets(s) {
				if t[0] != "443" || t[1] == "localhost" {
					continue
				}
				info, err := s.TLS(ctx, t[0], t[1], tls.VersionTLS12, tls.VersionTLS13)
				if err != nil || info.NotAfter.IsZero() {
					continue
				}
				switch {
				case info.SelfSigned:
					out = append(out, check.FailR(t[1], "Certificate is self-signed", "subject "+info.Subject))
				case !covers(info.DNSNames, t[1]):
					out = append(out, check.FailR(t[1], "Certificate does not cover this site name", fmt.Sprintf("names %v", info.DNSNames)))
				case !info.Trusted:
					out = append(out, check.FailR(t[1], "Certificate chain is not trusted", info.TrustError))
				default:
					out = append(out, check.PassR(t[1], "Certificate is CA-issued and covers the site name"))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("tls", "No HTTPS sites found")}
			}
			return out
		},
	})
}

func covers(names []string, host string) bool {
	for _, n := range names {
		if n == host {
			return true
		}
		if len(n) > 2 && n[:2] == "*." {
			if i := indexDot(host); i > 0 && host[i:] == n[1:] {
				return true
			}
		}
	}
	return false
}

func indexDot(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}
