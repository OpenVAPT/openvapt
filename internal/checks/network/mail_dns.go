package network

import (
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
)

// NET-MAIL and NET-DNS: Postfix, Dovecot and BIND hardening read from their
// configuration files. NET-DB-010 to NET-DB-013 already cover open recursion,
// zone transfers, open relay and plaintext authentication, so those signals
// are not repeated here. Detection only; no mail or DNS traffic is sent.

var (
	postfixFiles   = []string{"/etc/postfix/main.cf"}
	postfixMarkers = []string{"/etc/postfix", "/usr/sbin/postfix"}
	dovecotFiles   = []string{"/etc/dovecot/dovecot.conf", "/etc/dovecot/conf.d/10-ssl.conf", "/etc/dovecot/local.conf"}
	dovecotMarkers = []string{"/etc/dovecot", "/usr/sbin/dovecot"}
	bindFiles      = []string{"/etc/bind/named.conf.options", "/etc/bind/named.conf", "/etc/named.conf", "/etc/named/named.conf.options"}
	bindMarkers    = []string{"/etc/bind", "/etc/named.conf", "/usr/sbin/named"}

	refPostfixTLS  = check.Ref{Title: "Postfix TLS Support", URL: "https://www.postfix.org/TLS_README.html"}
	refPostfixConf = check.Ref{Title: "Postfix Configuration Parameters", URL: "https://www.postfix.org/postconf.5.html"}
	refDovecotSSL  = check.Ref{Title: "Dovecot SSL/TLS Configuration", URL: "https://doc.dovecot.org/main/core/config/ssl.html"}
	refBINDOptions = check.Ref{Title: "BIND 9 Administrator Reference Manual, options", URL: "https://bind9.readthedocs.io/en/latest/reference.html#options-block-grammar"}
	refRFC8996     = check.Ref{Title: "RFC 8996, Deprecating TLS 1.0 and TLS 1.1", URL: "https://www.rfc-editor.org/rfc/rfc8996.html"}
)

// postfixTLSLevel returns the lower-case smtpd_tls_security_level, or "none"
// when unset (the Postfix default). The legacy smtpd_use_tls = yes is read
// as "may".
func postfixTLSLevel(fs []collect.ConfigFile) string {
	if v := values(fs, "smtpd_tls_security_level"); len(v) > 0 {
		return strings.ToLower(strings.TrimSpace(v[len(v)-1]))
	}
	if hasValue(fs, func(v string) bool { return v == "yes" }, "smtpd_use_tls") {
		return "may"
	}
	return "none"
}

// postfixWeakProtocols reports whether a Postfix TLS protocol list still
// allows TLS 1.0 or 1.1. Postfix accepts two forms: ">=TLSv1.2" and an
// exclusion list such as "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1".
func postfixWeakProtocols(list string) bool {
	l := strings.ToLower(strings.ReplaceAll(list, ",", " "))
	for _, tok := range strings.Fields(l) {
		if strings.HasPrefix(tok, ">=") {
			v := strings.TrimPrefix(tok, ">=")
			return v != "tlsv1.2" && v != "tlsv1.3"
		}
	}
	excl := map[string]bool{}
	for _, tok := range strings.Fields(l) {
		if strings.HasPrefix(tok, "!") {
			excl[strings.TrimPrefix(tok, "!")] = true
		}
	}
	return !(excl["tlsv1"] && excl["tlsv1.1"])
}

func init() {
	registerDepth(depthRule{
		id: "NET-MAIL-001", title: "Postfix SMTP TLS Not Offered or Has No Certificate", sev: check.Medium, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "smtpd_tls_security_level is none or unset, or is may or encrypt without a server certificate, so incoming SMTP sessions cannot be encrypted.",
		rationale: "Without STARTTLS every message and every authentication exchange that other servers and clients send to this host crosses the network in the clear. Opportunistic TLS (may) with a valid certificate is the baseline that other mail servers expect.",
		detection: "Reads main.cf for smtpd_tls_security_level (or the legacy smtpd_use_tls) and smtpd_tls_cert_file or smtpd_tls_chain_files. Fails when the level is none or unset, or when TLS is enabled but no certificate file is named.",
		fix:       "Set  smtpd_tls_security_level = may ,  smtpd_tls_chain_files = /etc/letsencrypt/live/<host>/privkey.pem, /etc/letsencrypt/live/<host>/fullchain.pem  (or smtpd_tls_cert_file and smtpd_tls_key_file), then postfix reload.",
		verify:    "postconf smtpd_tls_security_level smtpd_tls_chain_files  and an authorised  openssl s_client -starttls smtp -connect 127.0.0.1:25  showing a certificate.",
		patterns:  postfixFiles, markers: postfixMarkers,
		refs: []check.Ref{refPostfixTLS, refPostfixConf, {Title: "NIST SP 800-177 Rev. 1, Trustworthy Email", URL: "https://csrc.nist.gov/pubs/sp/800/177/r1/final"}},
		std:  check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.2.2"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "Mail transport encryption"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			level := postfixTLSLevel(fs)
			ev := evidence(fs, "smtpd_tls_security_level", "smtpd_tls_cert_file", "smtpd_tls_chain_files")
			if level == "none" || level == "" {
				return true, append(ev, "smtpd_tls_security_level is none or unset")
			}
			if len(values(fs, "smtpd_tls_cert_file", "smtpd_tls_chain_files")) == 0 {
				return true, append(ev, "TLS is enabled but no smtpd_tls_cert_file or smtpd_tls_chain_files is set")
			}
			return false, ev
		},
		passMsg: "STARTTLS is offered with a certificate",
	})

	registerDepth(depthRule{
		id: "NET-MAIL-002", title: "Postfix Allows TLS 1.0 or 1.1", sev: check.Medium, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "smtpd_tls_protocols or smtpd_tls_mandatory_protocols is unset or still allows TLSv1 or TLSv1.1.",
		rationale: "The Postfix default for opportunistic TLS still admits TLS 1.0 and 1.1, which RFC 8996 deprecates. Setting a floor of TLS 1.2 is compatible with every current mail server and client. Severity is Medium rather than High because SMTP opportunistic TLS already tolerates fallback to plaintext.",
		detection: "When smtpd_tls_security_level is not none, reads smtpd_tls_protocols and smtpd_tls_mandatory_protocols. Fails when either is unset or, in list form, does not exclude both TLSv1 and TLSv1.1, or, in >= form, names a version below TLSv1.2.",
		fix:       "Add  smtpd_tls_protocols = >=TLSv1.2  and  smtpd_tls_mandatory_protocols = >=TLSv1.2  (Postfix 3.6 and newer; on older releases use  !SSLv2, !SSLv3, !TLSv1, !TLSv1.1 ), then postfix reload.",
		verify:    "postconf smtpd_tls_protocols smtpd_tls_mandatory_protocols",
		patterns:  postfixFiles, markers: postfixMarkers,
		refs: []check.Ref{refPostfixTLS, refRFC8996, refNISTTLSMail},
		std:  check.Standards{CWE: []string{"CWE-326", "CWE-327"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.1.3"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "TLS protocol versions"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			if postfixTLSLevel(fs) == "none" {
				return false, []string{"smtpd_tls_security_level is none; see NET-MAIL-001"}
			}
			var ev []string
			bad := false
			for _, k := range []string{"smtpd_tls_protocols", "smtpd_tls_mandatory_protocols"} {
				v := values(fs, k)
				if len(v) == 0 {
					bad = true
					ev = append(ev, k+" is not set; the default allows TLS 1.0 and 1.1")
					continue
				}
				last := v[len(v)-1]
				if postfixWeakProtocols(last) {
					bad = true
					ev = append(ev, k+" = "+last+" (allows TLS 1.0 or 1.1)")
				} else {
					ev = append(ev, k+" = "+last)
				}
			}
			return bad, ev
		},
		passMsg: "Postfix requires TLS 1.2 or newer",
	})

	registerDepth(depthRule{
		id: "NET-MAIL-003", title: "Postfix VRFY Command Enabled", sev: check.Low, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "disable_vrfy_command is not yes, so anyone who connects can ask the server whether a mailbox exists.",
		rationale: "VRFY lets a sender enumerate valid addresses one by one, which feeds spam lists and targeted phishing. Legitimate mail flow never needs it.",
		detection: "Reads main.cf for disable_vrfy_command. Fails when absent (default no) or set to no.",
		fix:       "Add  disable_vrfy_command = yes  to main.cf and postfix reload.",
		verify:    "postconf disable_vrfy_command  should print yes; an authorised  VRFY postmaster  over a local SMTP session should return 502.",
		patterns:  postfixFiles, markers: postfixMarkers,
		refs: []check.Ref{{Title: "Postfix, disable_vrfy_command", URL: "https://www.postfix.org/postconf.5.html#disable_vrfy_command"}, {Title: "RFC 5321, Simple Mail Transfer Protocol, section 7.3", URL: "https://www.rfc-editor.org/rfc/rfc5321.html#section-7.3"}},
		std:  check.Standards{CWE: []string{"CWE-204", "CWE-200"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-7", "SI-11"}, CISTopic: "Mail server user enumeration"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			ev := evidence(fs, "disable_vrfy_command")
			if len(ev) == 0 {
				return true, []string{"disable_vrfy_command is not set; the default is no"}
			}
			return !hasValue(fs, func(v string) bool { return v == "yes" }, "disable_vrfy_command"), ev
		},
		passMsg: "VRFY is disabled",
	})

	registerDepth(depthRule{
		id: "NET-MAIL-004", title: "Dovecot Does Not Require TLS", sev: check.Medium, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "Dovecot's ssl setting is yes or no instead of required, so IMAP and POP3 clients may use unencrypted sessions.",
		rationale: "With ssl = yes, TLS is offered but a client may keep the whole session in the clear, and non-plaintext mechanisms still travel unprotected. ssl = required refuses any command before STARTTLS or implicit TLS, which makes disable_plaintext_auth (NET-DB-013) effective.",
		detection: "Reads dovecot.conf, conf.d/10-ssl.conf and local.conf for ssl. Fails unless the last value is required. ssl_min_protocol is reported as evidence.",
		fix:       "Set  ssl = required  and  ssl_min_protocol = TLSv1.2  in conf.d/10-ssl.conf, then doveadm reload. Prefer implicit TLS ports 993 and 995 for clients.",
		verify:    "doveconf ssl ssl_min_protocol  should print required and TLSv1.2.",
		patterns:  dovecotFiles, markers: dovecotMarkers,
		refs: []check.Ref{refDovecotSSL, refRFC8996},
		std:  check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.2.2"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "Mail access encryption"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			v := values(fs, "ssl")
			ev := evidence(fs, "ssl", "ssl_min_protocol")
			if len(v) == 0 {
				return true, []string{"ssl is not set; the default yes offers TLS without requiring it"}
			}
			last := strings.ToLower(strings.TrimSpace(v[len(v)-1]))
			return last != "required", ev
		},
		passMsg: "Dovecot requires TLS",
	})

	registerDepth(depthRule{
		id: "NET-DNS-001", title: "BIND Version String Disclosed", sev: check.Low, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "named.conf has no version statement in options, so a CHAOS class query for version.bind returns the exact BIND release.",
		rationale: "The version string lets an attacker match advisories to the server without any guessing. Replacing it costs nothing and does not break resolution.",
		detection: "Reads named.conf and named.conf.options and looks for a  version  statement inside options. Fails when absent.",
		fix:       "Add  version \"not disclosed\";  inside the options block and run named-checkconf, then rndc reconfig.",
		verify:    "dig @127.0.0.1 version.bind txt chaos +short  should print the chosen string.",
		patterns:  bindFiles, markers: bindMarkers,
		refs: []check.Ref{{Title: "BIND 9 Administrator Reference Manual, version statement", URL: "https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-version"}, refBINDOptions},
		std:  check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-6", "SI-11"}, CISTopic: "DNS server version disclosure"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			raw := strings.ToLower(joinRaw(fs))
			if len(values(fs, "version")) > 0 || strings.Contains(raw, "version \"") || strings.Contains(raw, "version none") {
				return false, []string{"a version statement is present"}
			}
			return true, []string{"no version statement in options"}
		},
		passMsg: "The BIND version string is replaced",
	})

	registerDepth(depthRule{
		id: "NET-DNS-002", title: "BIND DNSSEC Validation Disabled", sev: check.Medium, cat: check.CatData,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
		summary:   "named.conf sets dnssec-validation no, so the resolver accepts forged answers for signed zones.",
		rationale: "DNSSEC validation lets a recursive resolver reject spoofed records for zones that are signed, which blocks cache poisoning of those names. BIND 9.16 and newer default to  auto  with the built-in root trust anchor, so an explicit  no  is a deliberate weakening.",
		detection: "Reads named.conf and named.conf.options for dnssec-validation. Fails on  no . Absent passes with a note (the default is auto on supported releases); auto or yes passes.",
		fix:       "Set  dnssec-validation auto;  in options (remove any  no ), run named-checkconf and rndc reconfig. Authoritative-only servers with recursion off may leave it unset.",
		verify:    "dig @127.0.0.1 dnssec-failed.org a  should return SERVFAIL, and a signed name should show the ad flag.",
		patterns:  bindFiles, markers: bindMarkers,
		refs: []check.Ref{{Title: "BIND 9 Administrator Reference Manual, dnssec-validation", URL: "https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-dnssec-validation"}, {Title: "NIST SP 800-81 Rev. 2, Secure Domain Name System Deployment Guide", URL: "https://csrc.nist.gov/pubs/sp/800/81/r2/final"}},
		std:  check.Standards{CWE: []string{"CWE-345", "CWE-350"}, OWASP: []string{"A08:2021"}, NIST: []string{"SC-20", "SC-21"}, CISTopic: "DNS resolver validation"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			raw := strings.ToLower(joinRaw(fs))
			i := strings.Index(raw, "dnssec-validation")
			if i < 0 {
				return false, []string{"dnssec-validation is not set; BIND 9.16 and newer default to auto"}
			}
			rest := strings.TrimSpace(raw[i+len("dnssec-validation"):])
			if j := strings.IndexAny(rest, ";}"); j >= 0 {
				rest = strings.TrimSpace(rest[:j])
			}
			return rest == "no", []string{"dnssec-validation " + rest}
		},
		passMsg: "DNSSEC validation is enabled",
	})
}

var refNISTTLSMail = check.Ref{Title: "NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations", URL: "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}

// joinRaw rebuilds a flat text view of parsed files for formats that do not
// fit the key/value model (BIND's brace syntax). Comments were removed by the
// parser; statements keep their original words.
func joinRaw(fs []collect.ConfigFile) string {
	var b strings.Builder
	for _, f := range fs {
		for k, vs := range f.Values {
			for _, v := range vs {
				b.WriteString(k + " " + v + "\n")
			}
		}
	}
	return b.String()
}
