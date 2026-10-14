package web

import (
	"strings"

	"github.com/openvapt/openvapt/internal/check"
)

// WEB-NGX: nginx hardening read from the configuration tree (nginx.conf and
// its includes). Detection only. These complement the HTTP probes in
// WEB-HDR and WEB-EXP, which see the live response: the file view catches
// a weak setting before a site is published and explains which line to fix.

var refNginxDocs = check.Ref{Title: "nginx documentation, ngx_http_core_module", URL: "https://nginx.org/en/docs/http/ngx_http_core_module.html"}
var refNginxSSL = check.Ref{Title: "nginx documentation, ngx_http_ssl_module", URL: "https://nginx.org/en/docs/http/ngx_http_ssl_module.html"}
var refMozillaTLS = check.Ref{Title: "Mozilla, Server Side TLS guidelines", URL: "https://wiki.mozilla.org/Security/Server_Side_TLS"}
var refMozillaGen = check.Ref{Title: "Mozilla SSL Configuration Generator", URL: "https://ssl-config.mozilla.org/"}
var refNISTTLS = check.Ref{Title: "NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations", URL: "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}
var refOpenSSLConfig = check.Ref{Title: "OpenSSL, config(5): system default TLS settings (MinProtocol)", URL: "https://docs.openssl.org/3.0/man5/config/"}
var refWSTGFinger = check.Ref{Title: "OWASP WSTG-INFO-02, Fingerprint Web Server", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"}

func nginxTLSConfigured(c serverConf) bool {
	return c.anyValue("ssl_certificate") || c.has("listen", func(v string) bool { return strings.Contains(v, " ssl") || strings.HasSuffix(v, "ssl") })
}

func init() {
	on := func(v string) bool { return v == "on" }
	off := func(v string) bool { return v == "off" }

	registerServerRule(serverRule{
		id: "WEB-NGX-001", title: "nginx Version Shown in Server Header", sev: check.Low, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "nginx does not set server_tokens off, so responses and error pages carry the exact nginx version.",
		rationale: "The version string lets an attacker pick advisories that match the server instead of guessing. Hiding it is not a fix for old software, but there is no reason to publish it.",
		detection: "Reads nginx.conf and its includes under /etc/nginx and looks for server_tokens. Fails when the directive is absent (default on) or set to on or build.",
		fix:       "In the http block of nginx.conf add  server_tokens off;  then run nginx -t and reload.",
		verify:    "curl -sI https://<site>/ | grep -i '^server:'  should print Server: nginx with no version.",
		refs:      []check.Ref{refNginxDocs, refWSTGFinger},
		std:       check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.3"}, WSTG: []string{"WSTG-INFO-02"}, NIST: []string{"CM-6", "SI-11"}, CISTopic: "Web server banner and version disclosure"},
		kind:      nginxKind,
		evaluate: func(c serverConf) (bool, []string) {
			bad := !c.has("server_tokens", off) || c.has("server_tokens", func(v string) bool { return v == "on" || v == "build" })
			ev := c.evidenceFor("server_tokens")
			if len(ev) == 0 {
				ev = []string{"server_tokens is not set; the default is on"}
			}
			return bad, ev
		},
	})

	registerServerRule(serverRule{
		id: "WEB-NGX-002", title: "nginx Directory Listing Enabled in Configuration", sev: check.Medium, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "An nginx server or location block sets autoindex on.",
		rationale: "Directory listings publish every file in a folder, including uploads, backups and scripts that were never linked. The configuration view finds this even for folders the probe check did not request.",
		detection: "Reads the nginx configuration tree and flags every  autoindex on;  directive. The nginx default is off, so an absent directive passes.",
		fix:       "Remove  autoindex on;  or set  autoindex off;  in that block. Where a listing is really needed, protect the location with auth_basic or an allow list.",
		verify:    "nginx -T | grep -n autoindex  should show only off or nothing.",
		refs:      []check.Ref{{Title: "nginx documentation, ngx_http_autoindex_module", URL: "https://nginx.org/en/docs/http/ngx_http_autoindex_module.html"}},
		std:       check.Standards{CWE: []string{"CWE-548"}, OWASP: []string{"A01:2021", "A05:2021"}, ASVS: []string{"4.3.2"}, WSTG: []string{"WSTG-CONF-04"}, NIST: []string{"CM-7", "AC-3"}, CISTopic: "Web server directory listing"},
		kind:      nginxKind,
		evaluate: func(c serverConf) (bool, []string) {
			return c.has("autoindex", on), c.evidenceFor("autoindex")
		},
		passMsg: "autoindex is off or not enabled",
	})

	registerServerRule(serverRule{
		id: "WEB-NGX-003", title: "nginx Allows TLS 1.0 or 1.1", sev: check.High, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		summary:   "ssl_protocols lists SSLv3, TLSv1 or TLSv1.1, or is not set on a TLS-enabled server, so the allowed version depends on the nginx build.",
		rationale: "TLS 1.0 and 1.1 are deprecated by RFC 8996 and lack the protections of TLS 1.2 and 1.3. Clients that negotiate them are exposed to downgrade and known cipher weaknesses. The directive is not the last word: nginx uses the system OpenSSL, and when its configuration already sets a floor of TLS 1.2 (MinProtocol in openssl.cnf on Debian 12 and Ubuntu 22.04 and later, or a crypto policy of DEFAULT, FUTURE or FIPS on the RHEL family) the old versions cannot be negotiated whatever the directive lists. In that case the check reports Pass and names the floor, because rating a server High for a line that has no effect would contradict the live handshake checks (WEB-TLS). The directive is still worth tidying so the configuration says what it does.",
		detection: "Skipped when no server block is served over TLS (no ssl_certificate and no listen ... ssl). Otherwise reads every ssl_protocols directive in the nginx configuration tree. Any listed version below TLSv1.2 fails, unless /etc/crypto-policies/config or openssl.cnf (with its .include files) shows the system library already refuses TLS 1.0 and 1.1, in which case the result is Pass with the floor as evidence. When no ssl_protocols is set and the floor is unknown, the result is Incomplete because the default changed between nginx releases.",
		fix:       "Set  ssl_protocols TLSv1.2 TLSv1.3;  in the http block (the Mozilla intermediate profile), run nginx -t and reload.",
		verify:    "openssl s_client -connect 127.0.0.1:443 -servername <site> -tls1_1  should fail to connect.",
		refs:      []check.Ref{refNginxSSL, refMozillaTLS, refNISTTLS, {Title: "RFC 8996, Deprecating TLS 1.0 and TLS 1.1", URL: "https://www.rfc-editor.org/rfc/rfc8996.html"}, refOpenSSLConfig},
		std:       check.Standards{CWE: []string{"CWE-326", "CWE-327"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.1.3"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "TLS protocol versions"},
		kind:      nginxKind,
		wantFloor: true,
		skip: func(c serverConf) (bool, string) {
			return !nginxTLSConfigured(c), "No server block is served over TLS (no ssl_certificate or listen ... ssl), so the protocol list has nothing to protect"
		},
		evaluate: func(c serverConf) (bool, []string) {
			ev := weakProtocolLines(c, "ssl_protocols")
			if len(ev) > 0 {
				if floorOverrides(c) {
					return false, append(ev, c.tlsFloor.Evidence)
				}
				return true, ev
			}
			ev = c.evidenceFor("ssl_protocols")
			if c.tlsFloor.Known {
				ev = append(ev, c.tlsFloor.Evidence)
			}
			return false, ev
		},
		passMsg: "ssl_protocols allows only TLS 1.2 or newer",
		pass: func(c serverConf) string {
			if len(weakProtocolLines(c, "ssl_protocols")) > 0 {
				return floorPassMsg
			}
			if !c.anyValue("ssl_protocols") {
				return "ssl_protocols is not set, but the system crypto library floor refuses TLS 1.0 and 1.1"
			}
			return "ssl_protocols allows only TLS 1.2 or newer"
		},
		incomplete: func(c serverConf) (bool, string) {
			return !c.anyValue("ssl_protocols") && !floorOverrides(c), "TLS is configured but ssl_protocols is not set; the default depends on the nginx version, so set it explicitly"
		},
	})

	registerServerRule(serverRule{
		id: "WEB-NGX-004", title: "nginx Cipher List Includes Weak Suites", sev: check.High, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		summary:   "ssl_ciphers includes NULL, export, DES or 3DES, RC4, MD5, anonymous or other legacy suites, or ssl_prefer_server_ciphers forces a legacy order.",
		rationale: "Weak suites allow recorded traffic to be decrypted or sessions to be hijacked. Modern clients already prefer strong suites, so the Mozilla guidelines recommend a short explicit list and ssl_prefer_server_ciphers off.",
		detection: "Reads every ssl_ciphers directive and flags OpenSSL tokens that name NULL, EXPORT, DES, RC4, MD5, aNULL, ADH, AECDH, PSK, SRP, IDEA, SEED or CAMELLIA suites, and bare ALL or DEFAULT. Tokens excluded with ! or - are ignored. ssl_prefer_server_ciphers on is reported as evidence only.",
		fix:       "Use the Mozilla intermediate list, for example  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;  and  ssl_prefer_server_ciphers off;",
		verify:    "Run the nmap ssl-enum-ciphers script against 127.0.0.1 port 443 under your own test plan; it should list only grade A suites.",
		refs:      []check.Ref{refMozillaGen, refMozillaTLS, {Title: "RFC 7525, Recommendations for Secure Use of TLS and DTLS", URL: "https://www.rfc-editor.org/rfc/rfc7525.html"}},
		std:       check.Standards{CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.1.2"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "TLS cipher suites"},
		kind:      nginxKind,
		evaluate: func(c serverConf) (bool, []string) {
			var ev []string
			bad := false
			for _, l := range c.directive("ssl_ciphers") {
				if w := weakCiphers(l.Value); len(w) > 0 {
					bad = true
					ev = append(ev, l.File+": weak tokens "+strings.Join(w, ", "))
				}
			}
			if c.has("ssl_prefer_server_ciphers", on) {
				ev = append(ev, "ssl_prefer_server_ciphers on (Mozilla recommends off for modern and intermediate profiles)")
			}
			return bad, ev
		},
		passMsg: "No weak cipher token is listed",
	})

	registerServerRule(serverRule{
		id: "WEB-NGX-005", title: "nginx OCSP Stapling Off or Session Tickets On", sev: check.Low, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "A TLS-enabled nginx does not enable ssl_stapling, or leaves ssl_session_tickets on.",
		rationale: "Without stapling, every browser asks the certificate authority whether the certificate is revoked, which slows the handshake and leaks the visited site to the CA. Session tickets encrypted with a long-lived key weaken forward secrecy when the key is never rotated; the Mozilla profiles turn them off.",
		detection: "When TLS is configured, reads ssl_stapling, ssl_stapling_verify and ssl_session_tickets. Fails unless ssl_stapling is on and ssl_session_tickets is off.",
		fix:       "Add  ssl_stapling on; ssl_stapling_verify on; ssl_session_tickets off;  and a  resolver  directive, as the Mozilla generator produces.",
		verify:    "openssl s_client -connect 127.0.0.1:443 -servername <site> -status  should print OCSP Response Status: successful.",
		refs:      []check.Ref{refMozillaGen, refNginxSSL},
		std:       check.Standards{CWE: []string{"CWE-299", "CWE-326"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.2.4"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-8", "SC-17"}, CISTopic: "Certificate status checking and session resumption"},
		kind:      nginxKind,
		evaluate: func(c serverConf) (bool, []string) {
			if !nginxTLSConfigured(c) {
				return false, []string{"TLS is not configured in nginx; nothing to staple"}
			}
			bad := !c.has("ssl_stapling", on) || !c.has("ssl_session_tickets", off)
			ev := c.evidenceFor("ssl_stapling", "ssl_stapling_verify", "ssl_session_tickets")
			if !c.anyValue("ssl_stapling") {
				ev = append(ev, "ssl_stapling is not set; the default is off")
			}
			if !c.anyValue("ssl_session_tickets") {
				ev = append(ev, "ssl_session_tickets is not set; the default is on")
			}
			return bad, ev
		},
	})

	registerServerRule(serverRule{
		id: "WEB-NGX-006", title: "nginx Request Limits Not Configured", sev: check.Info, cat: check.CatConfig,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		summary:   "nginx sets no client_max_body_size, limit_req_zone or limit_conn_zone, so request size and rate rely on defaults alone.",
		rationale: "Explicit limits bound what one client can upload or how fast it can call login and search pages. They are an availability and brute-force control, informational here because the right values depend on the application.",
		detection: "Reads the configuration tree for client_max_body_size, limit_req_zone and limit_conn_zone. Reports Info when none is present.",
		fix:       "Set  client_max_body_size  to what the application needs (the default is 1m) and add  limit_req_zone  for login and API locations with a sensible rate. See the nginx limit_req and limit_conn module documentation.",
		verify:    "nginx -T | grep -nE 'client_max_body_size|limit_(req|conn)_zone'",
		refs:      []check.Ref{{Title: "nginx documentation, ngx_http_limit_req_module", URL: "https://nginx.org/en/docs/http/ngx_http_limit_req_module.html"}, refNginxDocs},
		std:       check.Standards{CWE: []string{"CWE-770", "CWE-307"}, OWASP: []string{"A05:2021", "A07:2021"}, ASVS: []string{"11.1.4"}, NIST: []string{"SC-5", "AC-7"}, CISTopic: "Web server request limits"},
		kind:      nginxKind,
		evaluate: func(c serverConf) (bool, []string) {
			size := c.anyValue("client_max_body_size")
			rate := c.anyValue("limit_req_zone") || c.anyValue("limit_conn_zone")
			bad := !size && !rate
			ev := c.evidenceFor("client_max_body_size", "limit_req_zone", "limit_conn_zone")
			if bad {
				ev = []string{"no client_max_body_size, limit_req_zone or limit_conn_zone directive"}
			}
			return bad, ev
		},
		passMsg: "Request size or rate limits are configured",
	})

	registerServerRule(serverRule{
		id: "WEB-NGX-007", title: "nginx Serves Hidden Files and Folders", sev: check.Medium, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "No location block denies paths that begin with a dot, so .git, .env, .svn and .htaccess files under the document root are served if present.",
		rationale: "Dot files hold repository history, credentials and server rules. One deny rule for every path segment starting with a dot removes a whole class of leaks, including files deployed by mistake later.",
		detection: "Looks for a location block whose pattern matches a dot after a slash (for example  location ~ /\\.  ) in the nginx configuration tree. Fails when no such block exists and nginx serves files (a root or alias directive is present).",
		fix:       "Add to every server block:  location ~ /\\. { deny all; access_log off; log_not_found off; }  and keep .well-known reachable with a more specific  location ^~ /.well-known/  block before it.",
		verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/.git/HEAD  should print 403 or 404.",
		refs:      []check.Ref{refNginxDocs, {Title: "OWASP WSTG-CONF-04, Review Old Backup and Unreferenced Files", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/"}},
		std:       check.Standards{CWE: []string{"CWE-538", "CWE-200"}, OWASP: []string{"A05:2021"}, ASVS: []string{"12.5.1", "14.3.3"}, WSTG: []string{"WSTG-CONF-04"}, NIST: []string{"CM-7", "SC-28"}, CISTopic: "Web server access to hidden files"},
		kind:      nginxKind,
		evaluate: func(c serverConf) (bool, []string) {
			serves := c.anyValue("root") || c.anyValue("alias")
			if !serves {
				return false, []string{"nginx has no root or alias directive; it serves no files directly"}
			}
			denied := c.containsBlock("location", `/\.`) || c.containsBlock("location", `/\\.`) || c.containsBlock("location", `(^|/)\.`)
			if denied {
				return false, []string{"a location block matches dot paths"}
			}
			return true, []string{"no  location ~ /\\.  block found"}
		},
	})
}
