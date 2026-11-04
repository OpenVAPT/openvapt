package web

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Deeper CMS checks (WEB-CMS-012 and later): Drupal and Joomla lifecycle and
// settings, Magento and Ghost modes, and two more WordPress exposures. Files
// are found through the local web roots and read without following
// symlinks; only version numbers and setting names reach the report.

var (
	refDrupalSettings = check.Ref{Title: "Drupal.org, Trusted Host settings", URL: "https://www.drupal.org/docs/getting-started/installing-drupal/trusted-host-settings"}
	refDrupalCoreEOL  = check.Ref{Title: "Drupal.org, Drupal core release cycle and end of life", URL: "https://www.drupal.org/about/core/policies/core-release-cycles/schedule"}
	refDrupalUpdate   = check.Ref{Title: "Drupal.org, Running update.php (update_free_access)", URL: "https://www.drupal.org/docs/updating-drupal/update-core-via-drush-or-manually"}
	refJoomlaEOL      = check.Ref{Title: "Joomla Documentation, Joomla Release and Support Cycle", URL: "https://docs.joomla.org/Joomla!_CMS_versions"}
	refMagentoModes   = check.Ref{Title: "Adobe Commerce documentation, Set the Magento mode", URL: "https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/cli/set-mode"}
	refGhostConfig    = check.Ref{Title: "Ghost documentation, Configuration (url)", URL: "https://ghost.org/docs/config/"}
	refWPCron         = check.Ref{Title: "WordPress Developer Resources, Hooking WP-Cron Into the System Task Scheduler", URL: "https://developer.wordpress.org/plugins/cron/hooking-wp-cron-into-the-system-task-scheduler/"}
	refWPBrute        = check.Ref{Title: "WordPress Developer Resources, Brute Force Attacks", URL: "https://developer.wordpress.org/advanced-administration/security/brute-force/"}
)

// drupalEOL is the end of security coverage for each Drupal major, from the
// Drupal core release schedule. Majors not listed are treated as supported.
var drupalEOL = map[int]string{7: "2025-01-05", 8: "2020-11-02", 9: "2023-11-01"}

// joomlaEOL is the end of security support for each Joomla series.
var joomlaEOL = map[string]string{"1.5": "2012-09-27", "1.6": "2011-08-19", "1.7": "2012-02-24", "2.5": "2014-12-31", "3": "2023-08-17", "4": "2025-10-17"}

// noFollowText reads a file under a web root without following a symlink.
func noFollowText(ctx context.Context, s sys.System, p string) (string, bool) {
	r, err := sys.ReadFileNoFollow(ctx, s, p)
	if err != nil || !r.Complete {
		return "", false
	}
	return string(r.Data), true
}

// perRoot runs judge for every document root that has the CMS, or skips.
// judge returns (result, true) when the CMS is present under root.
func perRoot(ctx context.Context, s sys.System, judge func(root string) (check.Result, bool), skipMsg string) []check.Result {
	var out []check.Result
	for _, root := range collect.DocRoots(ctx, s) {
		if r, ok := judge(root); ok {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return []check.Result{check.SkipR("web roots", skipMsg)}
	}
	return out
}

func init() {
	check.Register(&check.Check{
		ID: "WEB-CMS-012", Title: "Drupal Core Past End of Life", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatPatch, Effort: check.EffortHigh,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Reads the installed Drupal core version from disk and compares its major release with the Drupal security coverage dates.",
		Rationale: "Drupal 7, 8 and 9 no longer receive security advisories from the Drupal Security Team. Drupalgeddon (CVE-2014-3704) and Drupalgeddon 2 (CVE-2018-7600) showed how quickly unpatched Drupal sites are taken over at scale.",
		Detection: "Reads core/lib/Drupal.php (const VERSION) or includes/bootstrap.inc (define('VERSION')) under each local web root and fails when the major release's end-of-life date has passed: 7 (2025-01-05), 8 (2020-11-02), 9 (2023-11-01).",
		Fix:       "Upgrade to a supported Drupal major with composer (drupal/core-recommended), run drush updatedb and test the site; for Drupal 7, migrate with the Migrate module or commission a rebuild.",
		Verify:    "drush status --field=drupal-version  or  grep VERSION core/lib/Drupal.php",
		Refs:      []check.Ref{refDrupalCoreEOL, {Title: "NVD, CVE-2018-7600", URL: "https://nvd.nist.gov/vuln/detail/cve-2018-7600"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, ASVS: []string{"14.2.1"}, NIST: []string{"SI-2", "SA-22"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			d8 := regexp.MustCompile(`const VERSION = '(\d+)\.[\d.]+[^']*'`)
			d7 := regexp.MustCompile(`define\('VERSION', '(\d+)\.[\d.]+[^']*'\)`)
			return perRoot(ctx, s, func(root string) (check.Result, bool) {
				var m []string
				if t, ok := noFollowText(ctx, s, root+"/core/lib/Drupal.php"); ok {
					m = d8.FindStringSubmatch(t)
				} else if t, ok := noFollowText(ctx, s, root+"/includes/bootstrap.inc"); ok {
					m = d7.FindStringSubmatch(t)
				} else {
					return check.Result{}, false
				}
				if m == nil {
					return check.IncompleteR(root, "Drupal is installed but its version line was not recognised"), true
				}
				major, _ := strconv.Atoi(m[1])
				eol, known := drupalEOL[major]
				if known && eol <= today() {
					return check.FailR(root, "Drupal "+m[1]+" reached end of life on "+eol), true
				}
				if !known && major < 7 {
					return check.FailR(root, "Drupal "+m[1]+" is older than every supported release"), true
				}
				return check.PassR(root, "Drupal "+m[1]+" is a supported major release"), true
			}, "No Drupal installation found in the local web roots")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-013", Title: "Drupal Trusted Host Patterns Not Set", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatWebApp, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
		Summary:   "Checks Drupal settings.php for the trusted_host_patterns setting.",
		Rationale: "Without trusted_host_patterns Drupal builds absolute links, including password reset links, from whatever Host header the request carries. An attacker who sends a crafted Host header can poison caches and redirect reset links to a domain they control.",
		Detection: "Reads each sites/*/settings.php found through the web roots (comments removed) and fails when $settings['trusted_host_patterns'] is not assigned.",
		Fix:       "Add to settings.php:  $settings['trusted_host_patterns'] = ['^www\\.example\\.com$', '^example\\.com$'];  then clear caches (drush cr). The status report page should no longer warn about trusted hosts.",
		Verify:    "drush status-report | grep -i 'trusted host'",
		Refs:      []check.Ref{refDrupalSettings, {Title: "OWASP WSTG-INPV-17, Testing for Host Header Injection", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection/"}},
		Standards: check.Standards{CWE: []string{"CWE-644", "CWE-346"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.4.1"}, WSTG: []string{"WSTG-INPV-17"}, NIST: []string{"CM-6", "SI-10"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			trusted := regexp.MustCompile(`\$settings\[\s*['"]trusted_host_patterns['"]\s*\]\s*=`)
			return cmsCheck(ctx, s, "Drupal", func(c collect.CMSConfig) []string {
				if !trusted.MatchString(phpComment.ReplaceAllString(c.Text, "$1")) {
					return []string{"$settings['trusted_host_patterns'] is not set"}
				}
				return nil
			}, "Drupal accepts any Host header")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-014", Title: "Joomla Core Past End of Life", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatPatch, Effort: check.EffortHigh,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Reads the installed Joomla version from administrator/manifests/files/joomla.xml on disk and compares it with the Joomla support dates.",
		Rationale: "Joomla 3 left security support in August 2023 and Joomla 4 in October 2025. Sites on those series receive no fixes for new core vulnerabilities, while the exact version remains easy to fingerprint.",
		Detection: "Reads <version> from administrator/manifests/files/joomla.xml under each local web root and fails when the series' end-of-support date has passed (1.5, 1.6, 1.7, 2.5, 3.x, 4.x). Joomla 5 and later pass.",
		Fix:       "Update to the current Joomla series through the Joomla Update component (back up first, check extension compatibility, then update), and keep the one-click updater enabled.",
		Verify:    "grep '<version>' administrator/manifests/files/joomla.xml",
		Refs:      []check.Ref{refJoomlaEOL, {Title: "Joomla Documentation, Security Checklist", URL: "https://docs.joomla.org/Security_Checklist"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, ASVS: []string{"14.2.1"}, NIST: []string{"SI-2", "SA-22"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			ver := regexp.MustCompile(`<version>\s*(\d+)\.(\d+)[^<]*</version>`)
			return perRoot(ctx, s, func(root string) (check.Result, bool) {
				t, ok := noFollowText(ctx, s, root+"/administrator/manifests/files/joomla.xml")
				if !ok {
					return check.Result{}, false
				}
				m := ver.FindStringSubmatch(collect.StripXMLComments(t))
				if m == nil {
					return check.IncompleteR(root, "Joomla manifest found but no version element"), true
				}
				v := m[1] + "." + m[2]
				eol, known := joomlaEOL[v]
				if !known {
					eol, known = joomlaEOL[m[1]]
				}
				if known && eol <= today() {
					return check.FailR(root, "Joomla "+v+" left security support on "+eol), true
				}
				return check.PassR(root, "Joomla "+v+" is a supported series"), true
			}, "No Joomla installation found in the local web roots")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-015", Title: "Magento Not in Production Mode", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks app/etc/env.php for a MAGE_MODE other than production.",
		Rationale: "Developer and default modes show exceptions with stack traces and file paths to shoppers, disable static file signing and compile code on the fly. Adobe documents production as the only mode for a live store.",
		Detection: "Reads app/etc/env.php in each local web root and its parent folder (Magento serves from pub/) and fails when 'MAGE_MODE' is developer or default.",
		Fix:       "bin/magento deploy:mode:set production  (which also deploys static content and compiles DI), then clear caches. Keep developer mode for staging only.",
		Verify:    "bin/magento deploy:mode:show  prints production.",
		Refs:      []check.Ref{refMagentoModes, {Title: "Adobe Commerce documentation, Security best practices", URL: "https://experienceleague.adobe.com/en/docs/commerce-admin/systems/security/security-best-practices"}},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-209"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}, WSTG: []string{"WSTG-CONF-02", "WSTG-ERRH-01"}, NIST: []string{"CM-6", "SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			mode := regexp.MustCompile(`['"]MAGE_MODE['"]\s*=>\s*['"]([a-z]+)['"]`)
			seen := map[string]bool{}
			return perRoot(ctx, s, func(root string) (check.Result, bool) {
				for _, p := range []string{root + "/app/etc/env.php", strings.TrimSuffix(root, "/pub") + "/app/etc/env.php"} {
					if seen[p] {
						continue
					}
					t, ok := noFollowText(ctx, s, p)
					if !ok {
						continue
					}
					seen[p] = true
					m := mode.FindStringSubmatch(phpComment.ReplaceAllString(t, "$1"))
					switch {
					case m == nil:
						return check.FailR(p, "MAGE_MODE is not set (default mode shows errors)"), true
					case m[1] != "production":
						return check.FailR(p, "MAGE_MODE is "+m[1]), true
					}
					return check.PassR(p, "MAGE_MODE is production"), true
				}
				return check.Result{}, false
			}, "No Magento installation found in the local web roots")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-016", Title: "Ghost Configured With a Plain HTTP Site URL", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatWebApp, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
		Summary:   "Checks Ghost config.production.json for a url that starts with http://.",
		Rationale: "Ghost builds every link, including the admin login and member sign-in links, from the configured url. With http:// the admin session and members' tokens travel in the clear even when HTTPS is available, and browsers see mixed content.",
		Detection: "Finds config.production.json files in the project folders that look like Ghost configuration (database and server keys) and fails when url begins with http://.",
		Fix:       "ghost config url https://<your-domain>  (or edit config.production.json), set up TLS with ghost setup ssl or your reverse proxy, then ghost restart.",
		Verify:    "ghost config get url  prints an https:// address.",
		Refs:      []check.Ref{refGhostConfig, {Title: "OWASP Transport Layer Security Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"}},
		Standards: check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021", "A05:2021"}, ASVS: []string{"9.1.1"}, WSTG: []string{"WSTG-CRYP-03"}, NIST: []string{"SC-8", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			urlRe := regexp.MustCompile(`"url"\s*:\s*"(https?)://`)
			paths := collect.ProjectFiles(ctx, s, "config.production.json")
			var out []check.Result
			for _, p := range paths {
				t, ok := noFollowText(ctx, s, p)
				if !ok || !strings.Contains(t, `"database"`) || !strings.Contains(t, `"server"`) {
					continue
				}
				m := urlRe.FindStringSubmatch(t)
				switch {
				case m == nil:
					out = append(out, check.IncompleteR(p, "No url setting found"))
				case m[1] == "http":
					out = append(out, check.FailR(p, "Ghost url uses plain http://"))
				default:
					out = append(out, check.PassR(p, "Ghost url uses https://"))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("projects", "No Ghost production configuration found")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-017", Title: "WordPress Cron Reachable by Visitors", Domain: check.DomainWeb,
		Severity: check.Info, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		Summary:   "Reports whether /wp-cron.php answers to anonymous requests on WordPress sites. Informational.",
		Rationale: "WP-Cron runs scheduled tasks when visitors load pages, and wp-cron.php can be requested directly. On busy or targeted sites that lets anyone make the server do work on demand, and it is a frequent target for resource exhaustion; a system cron job is the documented production setup.",
		Detection: "Sends one GET for /wp-cron.php on each local site and reports a 200 response with an empty or non-HTML body (what wp-cron.php returns). Sites whose wp-config.php sets DISABLE_WP_CRON to true and block the file pass.",
		Fix:       "Add define('DISABLE_WP_CRON', true); to wp-config.php, run  */5 * * * * www-data php /var/www/<site>/wp-cron.php  from the system cron (or curl the URL from cron), and deny direct requests to wp-cron.php at the web server.",
		Verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/wp-cron.php  prints 403 or 404.",
		Refs:      []check.Ref{refWPCron, refWPHardening},
		Standards: check.Standards{CWE: []string{"CWE-770"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-CONF-05"}, NIST: []string{"CM-7", "SC-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				r, err := st.Get(ctx, s, "/wp-cron.php")
				if err == nil && r.Status == 200 && (strings.TrimSpace(r.Body) == "" || !HTML(r)) {
					return check.FailR(st.Name, "wp-cron.php answers anonymous requests")
				}
				return check.PassR(st.Name, "wp-cron.php is not reachable")
			})
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-018", Title: "WordPress Author Archive Reveals Login Names", Domain: check.DomainWeb,
		Severity: check.Low, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks whether /?author=1 redirects to an author archive, which exposes the first account's login name in the address.",
		Rationale: "The author archive address contains the user's slug, which by default equals the login name. Together with the REST API listing (WEB-CMS-003) this gives attackers the administrator's user name for password guessing without touching the login form.",
		Detection: "Sends one GET for /?author=1 and fails on a 301 or 302 whose Location header contains /author/. The name itself is not written to the report.",
		Fix:       "Return 404 for author queries by id (a small redirect rule or a security plugin's user enumeration protection), and give administrators a nickname and display name that differ from the login name.",
		Verify:    "curl -sI https://<site>/?author=1 | grep -i location  prints nothing or a 404 page.",
		Refs:      []check.Ref{refWPBrute, refWPHardening},
		Standards: check.Standards{CWE: []string{"CWE-204"}, OWASP: []string{"A07:2021"}, WSTG: []string{"WSTG-IDNT-04"}, NIST: []string{"CM-6", "SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				r, err := st.Get(ctx, s, "/?author=1")
				if err == nil && (r.Status == 301 || r.Status == 302) && strings.Contains(r.Header.Get("Location"), "/author/") {
					return check.FailR(st.Name, "/?author=1 redirects to the author archive", "Location: .../author/<login-name>/")
				}
				return check.PassR(st.Name, "/?author=1 does not redirect to an archive")
			})
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-019", Title: "Drupal update.php Open Without Authentication", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
		Summary:   "Checks Drupal settings.php for $settings['update_free_access'] = TRUE.",
		Rationale: "update_free_access lets anyone run update.php, which executes database update hooks as the site. It exists for one-off maintenance and Drupal's own status report warns when it is left on.",
		Detection: "Reads each sites/*/settings.php found through the web roots (comments removed) and fails when update_free_access is TRUE.",
		Fix:       "Set $settings['update_free_access'] = FALSE; in settings.php (the default) and run updates as user 1 or with drush updatedb.",
		Verify:    "grep update_free_access sites/default/settings.php  shows FALSE.",
		Refs:      []check.Ref{refDrupalUpdate, {Title: "Drupal.org, Securing file permissions and ownership", URL: "https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-file-permissions-and-ownership"}},
		Standards: check.Standards{CWE: []string{"CWE-306"}, OWASP: []string{"A01:2021", "A05:2021"}, ASVS: []string{"4.3.2"}, WSTG: []string{"WSTG-CONF-05"}, NIST: []string{"AC-3", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			free := regexp.MustCompile(`(?i)\$settings\[\s*['"]update_free_access['"]\s*\]\s*=\s*TRUE`)
			return cmsCheck(ctx, s, "Drupal", func(c collect.CMSConfig) []string {
				if free.MatchString(phpComment.ReplaceAllString(c.Text, "$1")) {
					return []string{"$settings['update_free_access'] is TRUE"}
				}
				return nil
			}, "Drupal update.php runs without authentication")
		},
	})
}
