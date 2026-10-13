package web

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "WEB-TLS-001",
		Title:     "Site Available Over Plain HTTP Without Redirect",
		Domain:    check.DomainWeb,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
		Summary:   "Checks that every site redirects http:// requests to https://.",
		Rationale: "Pages served over plain HTTP can be read and changed by anyone on the network path, including injected malware and stolen session cookies.",
		Detection: "Requests http://<site>/ through 127.0.0.1 without following redirects. A 301/302/307/308 to an https:// URL passes; any other response fails.",
		Fix:       "Apache: in the port 80 vhost add  Redirect permanent / https://<site>/ . nginx: return 301 https://$host$request_uri; . Get a free certificate with certbot if HTTPS is not set up yet.",
		Verify:    "curl -sI http://<site>/  should show a 301 with Location: https://...",
		Refs:      []check.Ref{{Title: "OWASP Transport Layer Security Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"}},
		Standards: check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.1.1"}, NIST: []string{"SC-8"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				r, err := s.HTTP(ctx, "http", st.Name, "/")
				if err != nil {
					return check.PassR(st.Name, "Plain HTTP is not served")
				}
				loc := r.Header.Get("Location")
				if r.Status >= 300 && r.Status < 400 && strings.HasPrefix(strings.ToLower(loc), "https://") {
					return check.PassR(st.Name, "HTTP redirects to HTTPS", loc)
				}
				return check.FailR(st.Name, "Site content is served over plain HTTP", "HTTP status "+itoa(r.Status))
			})
		},
	})

	check.Register(&check.Check{
		ID:        "WEB-CK-001",
		Title:     "Cookies Missing Secure, HttpOnly or SameSite",
		Domain:    check.DomainWeb,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
		Summary:   "Checks the security flags on cookies the home page sets.",
		Rationale: "Without Secure, cookies leak over plain HTTP. Without HttpOnly, any XSS bug can steal sessions. Without SameSite, cross-site request forgery is easier.",
		Detection: "Inspects every Set-Cookie header on each site's home page for the Secure (HTTPS sites), HttpOnly and SameSite attributes. Cookie values are never recorded.",
		Fix:       "PHP: session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax in php.ini . Frameworks have equivalent settings (e.g. Laravel config/session.php). Use HttpOnly for every cookie JavaScript does not need to read.",
		Verify:    "curl -sI https://<site>/ | grep -i set-cookie",
		Refs:      []check.Ref{{Title: "OWASP Session Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"}, {Title: "RFC 6265, HTTP State Management Mechanism", URL: "https://www.rfc-editor.org/rfc/rfc6265"}},
		Standards: check.Standards{CWE: []string{"CWE-614", "CWE-1004", "CWE-1275"}, OWASP: []string{"A05:2021", "A07:2021"}, ASVS: []string{"3.4.1", "3.4.2", "3.4.3"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				if len(st.Home.Cookies) == 0 {
					return check.PassR(st.Name, "Home page sets no cookies")
				}
				var bad []string
				for _, c := range st.Home.Cookies {
					var miss []string
					if st.HTTPS && !c.Secure {
						miss = append(miss, "Secure")
					}
					if !c.HttpOnly {
						miss = append(miss, "HttpOnly")
					}
					if c.SameSite == 0 {
						miss = append(miss, "SameSite")
					}
					if len(miss) > 0 {
						bad = append(bad, c.Name+": missing "+strings.Join(miss, ", "))
					}
				}
				if len(bad) > 0 {
					return check.FailR(st.Name, "Cookies are missing security flags", bad...)
				}
				return check.PassR(st.Name, "All cookies carry Secure, HttpOnly and SameSite")
			})
		},
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
