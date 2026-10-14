package web

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// WEB-APA: Apache HTTP Server hardening read from apache2.conf or httpd.conf
// and every Include under /etc/apache2 or /etc/httpd. Detection only.

var refApacheSecTips = check.Ref{Title: "Apache HTTP Server, Security Tips", URL: "https://httpd.apache.org/docs/2.4/misc/security_tips.html"}

func apacheTLSConfigured(c serverConf) bool {
	return c.has("sslengine", func(v string) bool { return v == "on" }) || c.anyValue("sslcertificatefile")
}

// optionsEnables reports whether an Options value turns the named option on,
// either as a plain token ("Indexes", "All") or with a plus ("+Indexes").
// A minus ("-Indexes") disables it.
func optionsEnables(value, opt string) bool {
	opt = strings.ToLower(opt)
	for _, tok := range strings.Fields(strings.ToLower(value)) {
		switch {
		case tok == opt || tok == "+"+opt || tok == "all" || tok == "+all":
			return true
		}
	}
	return false
}

func init() {
	on := func(v string) bool { return v == "on" }

	registerServerRule(serverRule{
		id: "WEB-APA-001", title: "Apache Reveals Version in Header and Footer", sev: check.Low, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "ServerTokens is not Prod or ServerSignature is On, so responses and error pages show the Apache version and modules.",
		rationale: "The Server header and the signature line on error pages tell an attacker the exact release and loaded modules. Hiding them removes a free hint; patching remains the real fix.",
		detection: "Reads the Apache configuration tree for ServerTokens and ServerSignature. Fails when ServerTokens is absent (default Full) or not Prod, or when ServerSignature is On or EMail.",
		fix:       "Set  ServerTokens Prod  and  ServerSignature Off  in apache2.conf or conf-enabled/security.conf (Debian) or httpd.conf (RHEL), then apachectl configtest and reload.",
		verify:    "curl -sI https://<site>/ | grep -i '^server:'  should print Server: Apache with nothing after it.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, ServerTokens directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"}, refWSTGFinger},
		std:       check.Standards{CWE: []string{"CWE-497"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.3"}, WSTG: []string{"WSTG-INFO-02"}, NIST: []string{"CM-6", "SI-11"}, CISTopic: "Web server banner and version disclosure"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			prod := c.has("servertokens", func(v string) bool { return v == "prod" || v == "productonly" })
			sigOn := c.has("serversignature", func(v string) bool { return v == "on" || v == "email" })
			ev := c.evidenceFor("servertokens", "serversignature")
			if !c.anyValue("servertokens") {
				ev = append(ev, "ServerTokens is not set; the default is Full")
			}
			return !prod || sigOn, ev
		},
	})

	registerServerRule(serverRule{
		id: "WEB-APA-002", title: "Apache TRACE Method Enabled", sev: check.Low, cat: check.CatConfig,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "TraceEnable is not set to Off, so the HTTP TRACE method echoes requests back to the client.",
		rationale: "TRACE reflects request headers, including cookies and authorisation, which older cross-site tracing attacks used to read them from the browser. No production site needs it.",
		detection: "Reads the Apache configuration tree for TraceEnable. Fails when the directive is absent (default On) or set to On or Extended.",
		fix:       "Add  TraceEnable Off  to the server configuration and reload.",
		verify:    "curl -s -o /dev/null -w '%{http_code}' -X TRACE https://<site>/  should print 405.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, TraceEnable directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#traceenable"}, {Title: "OWASP WSTG-CONF-06, Test HTTP Methods", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods/"}},
		std:       check.Standards{CWE: []string{"CWE-1188", "CWE-749"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.5.1"}, WSTG: []string{"WSTG-CONF-06"}, NIST: []string{"CM-7"}, CISTopic: "HTTP methods allowed by the web server"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			off := c.has("traceenable", func(v string) bool { return v == "off" })
			ev := c.evidenceFor("traceenable")
			if len(ev) == 0 {
				ev = []string{"TraceEnable is not set; the default is On"}
			}
			return !off, ev
		},
	})

	registerServerRule(serverRule{
		id: "WEB-APA-003", title: "Apache Directory Indexes Enabled in Configuration", sev: check.Medium, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "An Options directive enables Indexes (or All), so folders without an index page list their files.",
		rationale: "Directory listings publish uploads, backups and scripts that were never linked. Debian ships Indexes on in the default /var/www block, so a fresh install fails this until changed.",
		detection: "Reads every Options directive in the Apache configuration tree and flags values that enable Indexes as a plain token, +Indexes or All.",
		fix:       "Change the block to  Options -Indexes +FollowSymLinks  (or remove Indexes). Where a listing is wanted, protect that Directory with Require.",
		verify:    "apachectl -t -D DUMP_CONFIG 2>/dev/null | grep -n Options  should show no Indexes except with a leading minus.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, Options directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#options"}},
		std:       check.Standards{CWE: []string{"CWE-548"}, OWASP: []string{"A01:2021", "A05:2021"}, ASVS: []string{"4.3.2"}, WSTG: []string{"WSTG-CONF-04"}, NIST: []string{"CM-7", "AC-3"}, CISTopic: "Web server directory listing"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			var ev []string
			for _, l := range c.directive("options") {
				if optionsEnables(l.Value, "indexes") {
					ev = append(ev, l.File+": "+l.Raw)
				}
			}
			return len(ev) > 0, ev
		},
		passMsg: "No Options directive enables Indexes",
	})

	registerServerRule(serverRule{
		id: "WEB-APA-004", title: "Apache AllowOverride All Permits .htaccess Control", sev: check.Low, cat: check.CatConfig,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "A Directory block sets AllowOverride All, so any .htaccess file under it can change handlers, options and access rules.",
		rationale: "With AllowOverride All, whoever can write a file into the document root (an upload bug, a compromised CMS) can turn images into executable scripts or lift access controls. Limiting overrides keeps those decisions in root-owned configuration.",
		detection: "Reads every AllowOverride directive in the Apache configuration tree and flags the value All. None or a short explicit list passes.",
		fix:       "Set  AllowOverride None  and move needed rules into the vhost, or allow only what the application needs, for example  AllowOverride FileInfo Indexes Limit  for WordPress permalinks.",
		verify:    "grep -rn AllowOverride /etc/apache2 /etc/httpd 2>/dev/null  should show no All.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, AllowOverride directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#allowoverride"}, refApacheSecTips},
		std:       check.Standards{CWE: []string{"CWE-15", "CWE-1188"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.1.1"}, WSTG: []string{"WSTG-CONF-05"}, NIST: []string{"CM-6", "CM-7"}, CISTopic: "Web server per-directory override scope"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			var ev []string
			for _, l := range c.directive("allowoverride") {
				if strings.EqualFold(strings.TrimSpace(l.Value), "all") {
					ev = append(ev, l.File+": "+l.Raw)
				}
			}
			return len(ev) > 0, ev
		},
		passMsg: "No AllowOverride All is set",
	})

	registerServerRule(serverRule{
		id: "WEB-APA-005", title: "Apache Allows TLS 1.0 or 1.1", sev: check.High, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		summary:   "SSLProtocol permits SSLv3, TLSv1 or TLSv1.1, or is not set on a TLS-enabled server (the default  all -SSLv3  allows TLS 1.0 and 1.1).",
		rationale: "TLS 1.0 and 1.1 are deprecated by RFC 8996 and lack the protections of TLS 1.2 and 1.3. Apache's default still allows them, so an explicit SSLProtocol is required. The directive is not the last word: mod_ssl uses the system OpenSSL, and when its configuration already sets a floor of TLS 1.2 (MinProtocol in openssl.cnf on Debian 12 and Ubuntu 22.04 and later, or a crypto policy of DEFAULT, FUTURE or FIPS on the RHEL family) the old versions cannot be negotiated whatever the directive lists. In that case the check reports Pass and names the floor, because rating a server High for a line that has no effect would contradict the live handshake checks (WEB-TLS). The directive is still worth tidying so the configuration says what it does.",
		detection: "Reads every SSLProtocol directive and expands  all , + and - tokens. Any resulting version below TLSv1.2 fails, as does an absent SSLProtocol when SSLEngine on or SSLCertificateFile is present, unless /etc/crypto-policies/config or openssl.cnf (with its .include files) shows the system library already refuses TLS 1.0 and 1.1, in which case the result is Pass with the floor as evidence.",
		fix:       "Set  SSLProtocol -all +TLSv1.2 +TLSv1.3  (Mozilla intermediate) in mods-enabled/ssl.conf or ssl.conf, then apachectl configtest and reload.",
		verify:    "openssl s_client -connect 127.0.0.1:443 -servername <site> -tls1_1  should fail to connect.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, SSLProtocol directive", URL: "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslprotocol"}, refMozillaTLS, refNISTTLS, refOpenSSLConfig},
		std:       check.Standards{CWE: []string{"CWE-326", "CWE-327"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.1.3"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "TLS protocol versions"},
		kind:      apacheKind,
		wantFloor: true,
		evaluate: func(c serverConf) (bool, []string) {
			ev := weakProtocolLines(c, "sslprotocol")
			if !c.anyValue("sslprotocol") && apacheTLSConfigured(c) {
				ev = append(ev, "SSLProtocol is not set; the default  all -SSLv3  allows TLS 1.0 and 1.1")
			}
			if len(ev) > 0 {
				if floorOverrides(c) {
					return false, append(ev, c.tlsFloor.Evidence)
				}
				return true, ev
			}
			ev = c.evidenceFor("sslprotocol")
			if c.tlsFloor.Known {
				ev = append(ev, c.tlsFloor.Evidence)
			}
			return false, ev
		},
		passMsg: "SSLProtocol allows only TLS 1.2 or newer",
		pass: func(c serverConf) string {
			if len(weakProtocolLines(c, "sslprotocol")) > 0 || (!c.anyValue("sslprotocol") && apacheTLSConfigured(c)) {
				return floorPassMsg
			}
			return "SSLProtocol allows only TLS 1.2 or newer"
		},
	})

	registerServerRule(serverRule{
		id: "WEB-APA-006", title: "Apache Cipher Suite Includes Weak Suites", sev: check.High, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		summary:   "SSLCipherSuite includes NULL, export, DES or 3DES, RC4, MD5, anonymous or other legacy suites, or SSLHonorCipherOrder forces a legacy order.",
		rationale: "Weak suites allow recorded traffic to be decrypted or sessions to be hijacked. The Mozilla guidelines give a short explicit list that modern clients all support.",
		detection: "Reads every SSLCipherSuite directive and flags OpenSSL tokens naming NULL, EXPORT, DES, RC4, MD5, aNULL, ADH, AECDH, PSK, SRP, IDEA, SEED or CAMELLIA, and bare ALL or DEFAULT. Tokens excluded with ! or - are ignored. SSLHonorCipherOrder on is reported as evidence.",
		fix:       "Use the Mozilla intermediate list for SSLCipherSuite and set  SSLHonorCipherOrder off , as the Mozilla SSL Configuration Generator produces for Apache.",
		verify:    "Run the nmap ssl-enum-ciphers script against 127.0.0.1 port 443 under your own test plan; it should list only grade A suites.",
		refs:      []check.Ref{refMozillaGen, {Title: "Apache HTTP Server, SSLCipherSuite directive", URL: "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslciphersuite"}, {Title: "RFC 7525, Recommendations for Secure Use of TLS and DTLS", URL: "https://www.rfc-editor.org/rfc/rfc7525.html"}},
		std:       check.Standards{CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.1.2"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "TLS cipher suites"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			var ev []string
			bad := false
			for _, l := range c.directive("sslciphersuite") {
				if w := weakCiphers(l.Value); len(w) > 0 {
					bad = true
					ev = append(ev, l.File+": weak tokens "+strings.Join(w, ", "))
				}
			}
			if c.has("sslhonorcipherorder", on) {
				ev = append(ev, "SSLHonorCipherOrder on (Mozilla recommends off for modern and intermediate profiles)")
			}
			return bad, ev
		},
		passMsg: "No weak cipher token is listed",
	})

	registerServerRule(serverRule{
		id: "WEB-APA-007", title: "Apache OCSP Stapling Not Enabled", sev: check.Low, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "A TLS-enabled Apache does not set SSLUseStapling on.",
		rationale: "Without stapling, every browser asks the certificate authority whether the certificate is revoked, which slows the handshake and reveals the visited site to the CA. Stapling lets the server attach a fresh signed status itself.",
		detection: "When SSLEngine on or SSLCertificateFile is present, reads SSLUseStapling and SSLStaplingCache. Fails unless SSLUseStapling is on.",
		fix:       "Add  SSLUseStapling On  inside the vhost and  SSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"  outside it, as the Mozilla generator produces.",
		verify:    "openssl s_client -connect 127.0.0.1:443 -servername <site> -status  should print OCSP Response Status: successful.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, SSLUseStapling directive", URL: "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslusestapling"}, refMozillaGen},
		std:       check.Standards{CWE: []string{"CWE-299"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.2.4"}, WSTG: []string{"WSTG-CRYP-01"}, NIST: []string{"SC-8", "SC-17"}, CISTopic: "Certificate status checking"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			if !apacheTLSConfigured(c) {
				return false, []string{"TLS is not configured in Apache; nothing to staple"}
			}
			bad := !c.has("sslusestapling", on)
			ev := c.evidenceFor("sslusestapling", "sslstaplingcache")
			if !c.anyValue("sslusestapling") {
				ev = append(ev, "SSLUseStapling is not set; the default is off")
			}
			return bad, ev
		},
	})

	registerServerRule(serverRule{
		id: "WEB-APA-008", title: "Apache Has No Request Filtering Module", sev: check.Info, cat: check.CatConfig,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		summary:   "Neither mod_security (ModSecurity) nor mod_evasive is loaded, so Apache has no request filtering or flood control in front of the application.",
		rationale: "A web application firewall or flood limiter is a defence-in-depth layer, not a requirement, and a misconfigured one breaks sites. The result is informational so you can decide with the application owner.",
		detection: "Looks for LoadModule security2_module or evasive20_module in the configuration tree, or security2.load and evasive.load under mods-enabled.",
		fix:       "Consider ModSecurity with the OWASP Core Rule Set in detection-only mode first, or mod_evasive for simple rate limiting, and tune before blocking.",
		verify:    "apachectl -M 2>/dev/null | grep -E 'security2|evasive'",
		refs:      []check.Ref{{Title: "OWASP ModSecurity Core Rule Set", URL: "https://coreruleset.org/docs/"}, refApacheSecTips},
		std:       check.Standards{CWE: []string{"CWE-1188"}, OWASP: []string{"A05:2021"}, ASVS: []string{"11.1.4"}, NIST: []string{"SC-5", "SI-10"}, CISTopic: "Web application filtering"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			var ev []string
			for _, l := range c.directive("loadmodule") {
				v := strings.ToLower(l.Value)
				if strings.Contains(v, "security2_module") || strings.Contains(v, "evasive20_module") || strings.Contains(v, "evasive_module") {
					ev = append(ev, l.File+": "+l.Raw)
				}
			}
			for _, p := range c.Paths {
				base := strings.ToLower(p)
				if strings.HasSuffix(base, "/security2.load") || strings.HasSuffix(base, "/evasive.load") {
					ev = append(ev, p)
				}
			}
			if len(ev) == 0 {
				return true, []string{"no security2_module or evasive20_module is loaded"}
			}
			return false, ev
		},
		passMsg: "A request filtering module is loaded",
	})

	registerServerRule(serverRule{
		id: "WEB-APA-009", title: "Apache ETag Reveals Inode Numbers", sev: check.Low, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "FileETag includes INode (or All), so ETag headers leak filesystem inode numbers of served files.",
		rationale: "Inode numbers help distinguish servers behind a load balancer and have been used to infer file identity across hosts (CVE-2003-1418). The Apache 2.4 default of MTime Size does not include them.",
		detection: "Reads every FileETag directive and flags values containing INode or All.",
		fix:       "Set  FileETag MTime Size  or  FileETag None  and reload.",
		verify:    "curl -sI https://<site>/robots.txt | grep -i etag  should show a two-part value, not three.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, FileETag directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#fileetag"}, {Title: "CVE-2003-1418, Apache inode disclosure in ETag", URL: "https://www.cve.org/CVERecord?id=CVE-2003-1418"}},
		std:       check.Standards{CWE: []string{"CWE-497"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.3"}, WSTG: []string{"WSTG-INFO-02"}, NIST: []string{"SI-11", "CM-6"}, CISTopic: "Web server information disclosure in headers"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			var ev []string
			for _, l := range c.directive("fileetag") {
				v := strings.ToLower(l.Value)
				if (strings.Contains(v, "inode") && !strings.Contains(v, "-inode")) || strings.Contains(v, "all") {
					ev = append(ev, l.File+": "+l.Raw)
				}
			}
			return len(ev) > 0, ev
		},
		passMsg: "FileETag does not include inode numbers",
	})

	registerServerRule(serverRule{
		id: "WEB-APA-010", title: "Apache Serves Repository and Environment Files", sev: check.Low, cat: check.CatExposure,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "No DirectoryMatch, FilesMatch or RedirectMatch rule denies .git, .svn, .hg or .env paths, so they are served if present under a document root.",
		rationale: "Repository folders rebuild the source code and its history; .env files hold database passwords and application keys. Debian's default only protects .ht* files. One rule for every dot path removes the whole class, including files deployed by mistake later. The rating is Low because this is a missing safety net, not an exposure: when such a file is actually present under a document root, WEB-APP-009 and WEB-DOC-001 report it at their own higher severity, and when none is present the check passes and only notes the missing rule.",
		detection: "Looks for a block or rule whose pattern covers dot-prefixed names: DirectoryMatch or LocationMatch with a dot pattern, FilesMatch starting with ^\\. , or RedirectMatch for .git or .env. When none exists, checks each configured document root (metadata only, symlinks not followed) for a .git, .svn, .hg, .env or .env.* entry; Fails at Low when one is found and the rule is missing, Passes with a note when none is found.",
		fix:       "Add to the server configuration:  <DirectoryMatch \"/\\.(git|svn|hg)\"> Require all denied </DirectoryMatch>  and  <FilesMatch \"^\\.(env|git|svn)\"> Require all denied </FilesMatch> , then reload.",
		verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/.git/HEAD  should print 403 or 404.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, DirectoryMatch directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#directorymatch"}, {Title: "OWASP WSTG-CONF-04, Review Old Backup and Unreferenced Files", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/"}},
		std:       check.Standards{CWE: []string{"CWE-538", "CWE-527"}, OWASP: []string{"A05:2021"}, ASVS: []string{"12.5.1", "14.3.3"}, WSTG: []string{"WSTG-CONF-04"}, NIST: []string{"CM-7", "SC-28"}, CISTopic: "Web server access to hidden files"},
		kind:      apacheKind,
		evaluateSys: func(ctx context.Context, s sys.System, c serverConf) (bool, []string) {
			for _, l := range c.Lines {
				if dotRuleCovers(l.Raw) {
					return false, []string{l.File + ": " + l.Raw}
				}
			}
			roots := collect.DocRoots(ctx, s)
			var present []string
			for _, root := range roots {
				for _, name := range []string{".git", ".svn", ".hg", ".env"} {
					if collect.Exists(s, root+"/"+name) {
						present = append(present, root+"/"+name)
					} else if m, _ := s.Glob(root + "/" + name + "/*"); len(m) > 0 {
						present = append(present, root+"/"+name)
					}
				}
				if m, _ := s.Glob(root + "/.env.*"); len(m) > 0 {
					sort.Strings(m)
					present = append(present, m...)
				}
			}
			if len(present) > 0 {
				return true, append([]string{"no DirectoryMatch, FilesMatch or RedirectMatch rule covers .git, .svn or .env, and these exist under a document root:"}, present...)
			}
			return false, []string{fmt.Sprintf("no deny rule for dot paths, but none of .git, .svn, .hg or .env exists under the %d configured document root(s); add the rule as a safety net", len(roots))}
		},
		passMsg: "Repository and environment paths are either denied by a rule or absent from every document root",
	})
}

// dotRuleCovers reports whether one Apache line is a match rule whose pattern
// covers repository or environment files: a DirectoryMatch, LocationMatch,
// FilesMatch or RedirectMatch naming .git, .svn, .hg or .env, or a generic
// dot-file pattern. Debian's default  <FilesMatch "^\.ht">  protects only
// .htaccess and .htpasswd, so a pattern that stops at .ht does not count.
func dotRuleCovers(raw string) bool {
	l := strings.ToLower(raw)
	if !strings.Contains(l, "directorymatch") && !strings.Contains(l, "locationmatch") && !strings.Contains(l, "filesmatch") && !strings.Contains(l, "redirectmatch") {
		return false
	}
	for _, name := range []string{"git", "svn", "hg", "env"} {
		if strings.Contains(l, name) {
			return true
		}
	}
	// A generic "any dot-prefixed name" pattern, with the .ht-only Debian
	// default excluded.
	generic := strings.Contains(l, `^\.`) || strings.Contains(l, `/\.`) || strings.Contains(l, `(^|/)\.`)
	return generic && !strings.Contains(l, `\.ht`)
}
