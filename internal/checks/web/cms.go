package web

import (
	"context"
	"regexp"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func today() string { return time.Now().UTC().Format("2006-01-02") }

func init() {
	check.Register(&check.Check{
		ID:        "WEB-CMS-001",
		Title:     "WordPress Version Disclosed",
		Domain:    check.DomainWeb,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks whether WordPress sites reveal their exact version in the page or in readme.html.",
		Rationale: "The version number lets automated tools pick matching exploits for outdated cores and plugins.",
		Detection: "Looks for the WordPress generator meta tag on the home page and requests /readme.html for the version line.",
		Fix:       "Keep WordPress updated (automatic minor updates on). Remove the generator tag (remove_action('wp_head','wp_generator')) and delete readme.html after each update, or block it at the web server.",
		Verify:    "curl -s https://<site>/ | grep -i 'name=\"generator\"'",
		Refs:      []check.Ref{{Title: "WordPress Developer Resources, Hardening WordPress", URL: "https://developer.wordpress.org/advanced-administration/security/hardening/"}},
		Standards: check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021", "A06:2021"}, ASVS: []string{"14.3.3"}, WSTG: []string{"WSTG-INFO-08"}, NIST: []string{"CM-7", "SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			gen := regexp.MustCompile(`(?i)<meta name="generator" content="WordPress ([\d.]+)"`)
			return ForEachSite(ctx, s, func(st Site) check.Result {
				var ev []string
				if m := gen.FindStringSubmatch(st.Home.Body); m != nil {
					ev = append(ev, "generator tag: WordPress "+m[1])
				}
				if r, err := st.Get(ctx, s, "/readme.html"); err == nil && r.Status == 200 && regexp.MustCompile(`(?i)wordpress`).MatchString(r.Body) {
					ev = append(ev, "/readme.html is public")
				}
				if len(ev) > 0 {
					return check.FailR(st.Name, "WordPress version is disclosed", ev...)
				}
				return check.PassR(st.Name, "No WordPress version disclosure found")
			})
		},
	})

	check.Register(&check.Check{
		ID:        "WEB-CMS-002",
		Title:     "WordPress XML-RPC Interface Enabled",
		Domain:    check.DomainWeb,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
		Summary:   "Checks whether xmlrpc.php answers on WordPress sites.",
		Rationale: "XML-RPC allows many password guesses in one request (system.multicall) and is abused for pingback amplification. Few sites still need it.",
		Detection: "Sends one GET to /xmlrpc.php; the standard reply 'XML-RPC server accepts POST requests only.' confirms it is enabled. No XML-RPC call is made.",
		Fix:       "Block it at the web server (<Files xmlrpc.php> Require all denied </Files>) or disable it with a security plugin, unless Jetpack or the mobile app needs it.",
		Verify:    "curl -s https://<site>/xmlrpc.php  should return 403 or 404.",
		Refs:      []check.Ref{{Title: "WordPress Developer Resources, Brute Force Attacks (XML-RPC)", URL: "https://developer.wordpress.org/advanced-administration/security/brute-force/"}},
		Standards: check.Standards{CWE: []string{"CWE-307"}, OWASP: []string{"A07:2021"}, NIST: []string{"AC-7", "CM-7"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				r, err := st.Get(ctx, s, "/xmlrpc.php")
				if err == nil && regexp.MustCompile(`XML-RPC server accepts POST`).MatchString(r.Body) {
					return check.FailR(st.Name, "xmlrpc.php is enabled")
				}
				return check.PassR(st.Name, "xmlrpc.php is not reachable")
			})
		},
	})
}
