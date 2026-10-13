package web

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "WEB-HDR-001",
		Title:     "Missing HTTP Strict Transport Security (HSTS)",
		Domain:    check.DomainWeb,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
		Summary:   "Checks that HTTPS sites tell browsers to always use HTTPS, for at least six months.",
		Rationale: "Without HSTS, the first visit or any typed http:// link can be intercepted and downgraded to plain HTTP (SSL stripping) on public Wi-Fi.",
		Detection: "Reads the Strict-Transport-Security header from each HTTPS site's home page, including a redirect response, because browsers honour HSTS on any HTTPS response. Plain HTTP responses are not evaluated. Missing, or max-age below 15552000 seconds (180 days), fails.",
		Fix:       "Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\" . nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always; . Only add 'preload' once every subdomain supports HTTPS.",
		Verify:    "curl -sI https://<site>/ | grep -i strict-transport-security",
		Refs:      []check.Ref{{Title: "RFC 6797, HTTP Strict Transport Security", URL: "https://www.rfc-editor.org/rfc/rfc6797"}, refHTTPHeadersCS, refMDN("Strict-Transport-Security")},
		Standards: check.Standards{CWE: []string{"CWE-319", "CWE-523"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.4.5"}, WSTG: []string{"WSTG-CONF-07"}, NIST: []string{"SC-8"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				// Browsers honour HSTS on any HTTPS response, redirects
				// included (RFC 6797 section 8.1), so a 3xx is evaluated too.
				if !st.HTTPS {
					return check.SkipR(st.Name, "Site not served over HTTPS (see WEB-TLS-001)")
				}
				h := st.Home.Header.Get("Strict-Transport-Security")
				if h == "" {
					return check.FailR(st.Name, "Strict-Transport-Security header is missing")
				}
				n, ok := hstsMaxAge(h)
				if !ok {
					return check.FailR(st.Name, "HSTS max-age is missing, duplicated or invalid", h)
				}
				if n < 15552000 {
					return check.FailR(st.Name, "HSTS max-age is shorter than 180 days", h)
				}
				return check.PassR(st.Name, "HSTS is set", h)
			})
		},
	})

	check.Register(&check.Check{
		ID:        "WEB-HDR-002",
		Title:     "Missing Content Security Policy",
		Domain:    check.DomainWeb,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		Summary:   "Checks that each site sends a Content-Security-Policy header.",
		Rationale: "A CSP limits where scripts may load from, turning many cross-site scripting (XSS) bugs from account takeover into a blocked request.",
		Detection: "Reads Content-Security-Policy from each site's home page. Missing fails. A policy containing 'unsafe-inline' in script-src (without a nonce or hash) or a bare * source is reported as weak.",
		Fix:       "Start with a report-only policy to find what the site loads, then enforce, for example: Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
		Verify:    "curl -sI https://<site>/ | grep -i content-security-policy",
		Refs:      []check.Ref{{Title: "OWASP Content Security Policy Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"}, {Title: "W3C Content Security Policy Level 3", URL: "https://www.w3.org/TR/CSP3/"}},
		Standards: check.Standards{CWE: []string{"CWE-1021", "CWE-79"}, OWASP: []string{"A03:2021", "A05:2021"}, ASVS: []string{"14.4.3"}, WSTG: []string{"WSTG-CONF-12"}, NIST: []string{"SI-10"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				if r, skip := st.Redirected(); skip {
					return r
				}
				h := st.Home.Header.Get("Content-Security-Policy")
				if h == "" {
					return check.FailR(st.Name, "Content-Security-Policy header is missing")
				}
				if reason := weakCSP(h); reason != "" {
					return check.FailR(st.Name, reason, h)
				}
				return check.PassR(st.Name, "Content-Security-Policy is set", h)
			})
		},
	})

	check.Register(&check.Check{
		ID:        "WEB-HDR-003",
		Title:     "Site Can Be Framed (Clickjacking)",
		Domain:    check.DomainWeb,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
		Summary:   "Checks that each site forbids being embedded in other sites' frames.",
		Rationale: "If a page can be framed, an attacker can overlay it invisibly and trick users into clicking buttons (clickjacking), such as 'delete' or 'transfer'.",
		Detection: "Passes if the CSP frame-ancestors directive restricts framing (a * or scheme-only source fails), or, without frame-ancestors, X-Frame-Options is DENY or SAMEORIGIN (repeated identical values are accepted; conflicting values fail).",
		Fix:       "Send  Content-Security-Policy: frame-ancestors 'self'  (modern) and  X-Frame-Options: SAMEORIGIN  (older browsers).",
		Verify:    "curl -sI https://<site>/ | grep -Ei 'x-frame-options|frame-ancestors'",
		Refs:      []check.Ref{{Title: "OWASP Clickjacking Defense Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"}, refMDN("X-Frame-Options")},
		Standards: check.Standards{CWE: []string{"CWE-1021"}, OWASP: []string{"A04:2021"}, ASVS: []string{"14.4.7"}, WSTG: []string{"WSTG-CLNT-09"}, NIST: []string{"SC-18"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				if r, skip := st.Redirected(); skip {
					return r
				}
				ok, why := framingRestricted(st.Home.Header)
				if ok {
					return check.PassR(st.Name, "Framing is restricted", why)
				}
				return check.FailR(st.Name, why)
			})
		},
	})

	simpleHeader := func(id, title, header, want, summary, rationale, fix string, sev check.Severity, std check.Standards) {
		check.Register(&check.Check{
			ID: id, Title: title, Domain: check.DomainWeb, Severity: sev,
			CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			Summary:   summary,
			Rationale: rationale,
			Detection: "Reads the " + header + " header from each site's home page and checks that it is present" + map[bool]string{true: " with the value " + want, false: ""}[want != ""] + ".",
			Fix:       fix,
			Verify:    "curl -sI https://<site>/ | grep -i " + strings.ToLower(header),
			Refs:      []check.Ref{refSecureHeaders, refMDN(header)},
			Standards: std,
			Run: func(ctx context.Context, s sys.System) []check.Result {
				return ForEachSite(ctx, s, func(st Site) check.Result {
					if r, skip := st.Redirected(); skip {
						return r
					}
					v := st.Home.Header.Get(header)
					if v == "" || (want != "" && !strings.EqualFold(strings.TrimSpace(v), want)) {
						return check.FailR(st.Name, header+" is missing or not '"+want+"'", v)
					}
					if header == "Referrer-Policy" && unsafeReferrer(st.Home.Header.Values(header)) {
						return check.FailR(st.Name, "Referrer-Policy unsafe-url sends the full URL to every site", v)
					}
					return check.PassR(st.Name, header+" is set", v)
				})
			},
		})
	}
	simpleHeader("WEB-HDR-004", "Missing X-Content-Type-Options", "X-Content-Type-Options", "nosniff",
		"Checks that browsers are told not to guess (sniff) content types.",
		"Without nosniff, a browser may execute an uploaded text or image file as script or HTML, enabling XSS through file uploads.",
		"Send  X-Content-Type-Options: nosniff  on every response (Apache: Header always set X-Content-Type-Options nosniff; nginx: add_header X-Content-Type-Options nosniff always;).",
		check.Low, check.Standards{CWE: []string{"CWE-430"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.4.4"}, NIST: []string{"CM-6"}})
	simpleHeader("WEB-HDR-005", "Missing Referrer-Policy", "Referrer-Policy", "",
		"Checks that each site limits what URL information is leaked to other sites in the Referer header.",
		"Full URLs can contain session tokens, password-reset links or personal data, which would otherwise be sent to every third-party resource and outbound link.",
		"Send  Referrer-Policy: strict-origin-when-cross-origin  (or no-referrer). Never use unsafe-url.",
		check.Low, check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.4.6"}, NIST: []string{"CM-6"}})
	simpleHeader("WEB-HDR-006", "Missing Permissions-Policy", "Permissions-Policy", "",
		"Checks that each site restricts powerful browser features (camera, microphone, geolocation) it does not use.",
		"Restricting features limits what injected or third-party scripts can do in your visitors' browsers.",
		"Send, for example,  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()  adjusted to the features the site really uses.",
		check.Low, check.Standards{CWE: []string{"CWE-1188"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-6", "CM-7"}})

	check.Register(&check.Check{
		ID:        "WEB-HDR-007",
		Title:     "Server Software Version Disclosed",
		Domain:    check.DomainWeb,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks whether response headers reveal exact web server, PHP or framework versions.",
		Rationale: "Exact versions let attackers match the site against public exploit lists in seconds. Hiding them does not fix vulnerabilities but removes free reconnaissance.",
		Detection: "Looks for a version number in the Server header and for the X-Powered-By, X-AspNet-Version and X-Generator headers.",
		Fix:       "Apache: ServerTokens Prod and ServerSignature Off . nginx: server_tokens off; . PHP: expose_php = Off in php.ini . Remove X-Powered-By in the application or proxy.",
		Verify:    "curl -sI https://<site>/ | grep -Ei '^(server|x-powered-by)'",
		Refs:      []check.Ref{refHTTPHeadersCS, {Title: "Apache HTTP Server, ServerTokens directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"}},
		Standards: check.Standards{CWE: []string{"CWE-200", "CWE-497"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.3"}, WSTG: []string{"WSTG-INFO-02"}, NIST: []string{"CM-7", "SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			ver := regexp.MustCompile(`\d+\.\d+`)
			return ForEachSite(ctx, s, func(st Site) check.Result {
				if r, skip := st.Redirected(); skip {
					return r
				}
				var ev []string
				if v := st.Home.Header.Get("Server"); ver.MatchString(v) {
					ev = append(ev, "Server: "+v)
				}
				for _, h := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
					if v := st.Home.Header.Get(h); v != "" {
						ev = append(ev, h+": "+v)
					}
				}
				if len(ev) > 0 {
					return check.FailR(st.Name, "Software versions are disclosed in headers", ev...)
				}
				return check.PassR(st.Name, "No version details in headers")
			})
		},
	})
}

func hstsMaxAge(h string) (uint64, bool) {
	var value string
	for _, part := range strings.Split(h, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "max-age") {
			if value != "" {
				return 0, false
			}
			value = strings.TrimSpace(kv[1])
		}
	}
	// RFC 6797 allows max-age as a token or a quoted string.
	if len(value) >= 2 && strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		value = value[1 : len(value)-1]
	}
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return n, err == nil
}

func weakCSP(h string) string {
	dirs := map[string][]string{}
	for _, raw := range strings.Split(strings.ToLower(h), ";") {
		f := strings.Fields(raw)
		if len(f) > 0 {
			dirs[f[0]] = f[1:]
		}
	}
	script := dirs["script-src"]
	if len(script) == 0 {
		script = dirs["default-src"]
	}
	for _, src := range script {
		if src == "*" || src == "data:" || strings.HasPrefix(src, "http:") {
			return "CSP permits an unsafe script source"
		}
		if src == "'unsafe-eval'" {
			return "CSP allows unsafe script evaluation"
		}
		if src == "'unsafe-inline'" && !hasNonceOrHash(script) {
			return "CSP allows inline scripts without a nonce or hash"
		}
	}
	if _, ok := dirs["object-src"]; !ok {
		return "CSP does not restrict object-src"
	}
	return ""
}
func hasNonceOrHash(src []string) bool {
	for _, s := range src {
		if strings.HasPrefix(s, "'nonce-") || strings.HasPrefix(s, "'sha256-") || strings.HasPrefix(s, "'sha384-") || strings.HasPrefix(s, "'sha512-") {
			return true
		}
	}
	return false
}

// framingRestricted evaluates CSP frame-ancestors first (browsers ignore
// X-Frame-Options when it is present), then X-Frame-Options.
func framingRestricted(h http.Header) (bool, string) {
	for _, csp := range h.Values("Content-Security-Policy") {
		for _, raw := range strings.Split(strings.ToLower(csp), ";") {
			f := strings.Fields(raw)
			if len(f) == 0 || f[0] != "frame-ancestors" {
				continue
			}
			for _, src := range f[1:] {
				if src == "*" || src == "http:" || src == "https:" || src == "*:" {
					return false, "CSP frame-ancestors allows any site to frame the page (" + strings.Join(f[1:], " ") + ")"
				}
			}
			if len(f) == 1 {
				return false, "CSP frame-ancestors has no source list"
			}
			return true, "frame-ancestors " + strings.Join(f[1:], " ")
		}
	}
	var vals []string
	for _, v := range h.Values("X-Frame-Options") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.ToUpper(strings.TrimSpace(p)); p != "" {
				vals = append(vals, p)
			}
		}
	}
	if len(vals) == 0 {
		return false, "Neither X-Frame-Options nor CSP frame-ancestors is set"
	}
	for _, v := range vals[1:] {
		if v != vals[0] {
			return false, "X-Frame-Options has conflicting values (" + strings.Join(vals, ", ") + "), which browsers ignore"
		}
	}
	if vals[0] == "DENY" || vals[0] == "SAMEORIGIN" {
		return true, "X-Frame-Options " + vals[0]
	}
	return false, "X-Frame-Options value " + vals[0] + " is not DENY or SAMEORIGIN"
}

// unsafeReferrer reports whether the effective Referrer-Policy (the last
// recognised token, per the W3C Referrer Policy specification) is unsafe-url.
func unsafeReferrer(vals []string) bool {
	last := ""
	for _, v := range vals {
		for _, t := range strings.Split(v, ",") {
			switch t = strings.ToLower(strings.TrimSpace(t)); t {
			case "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url":
				last = t
			}
		}
	}
	return last == "unsafe-url"
}
