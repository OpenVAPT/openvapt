package web

import (
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

var refWSTGConf04 = check.Ref{Title: "OWASP WSTG-CONF-04, Review Old Backup and Unreferenced Files for Sensitive Information", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"}
var refWSTGInfo02 = check.Ref{Title: "OWASP WSTG-INFO-02, Fingerprint Web Server", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"}
var refWSTGErrh = check.Ref{Title: "OWASP WSTG-ERRH-01, Testing for Improper Error Handling", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"}

// statusWith returns a marker that requires HTTP 200 and one of the strings.
func statusWith(subs ...string) func(sys.HTTPResponse) bool { return bodyHas(subs...) }

// jsonWith requires a 200 JSON-looking body containing every string.
func jsonWith(all ...string) func(sys.HTTPResponse) bool {
	return func(r sys.HTTPResponse) bool {
		if r.Status != 200 || HTML(r) {
			return false
		}
		for _, a := range all {
			if !strings.Contains(r.Body, a) {
				return false
			}
		}
		return true
	}
}

func init() {
	for _, r := range []exposureRule{
		exposureRule{
			id: "WEB-EXP-007", title: "Other Version Control Metadata Exposed", sev: check.High, cat: check.CatExposure, effort: check.EffortLow,
			cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			summary:   "Checks for exposed Subversion, Mercurial and Bazaar metadata folders.",
			rationale: "Like .git, these folders let anyone reconstruct source code and history, including secrets that were committed by mistake.",
			detection: "Requests /.svn/entries, /.svn/wc.db, /.hg/requires and /.bzr/README; a 200 response with the tool's characteristic content confirms exposure.",
			fix:       "Block dot-folders at the web server and deploy without version control metadata in the web root. Rotate any secret ever committed.",
			verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/.svn/entries  should print 403 or 404.",
			refs:      []check.Ref{refWSTGConf04},
			std:       check.Standards{CWE: []string{"CWE-527"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}, WSTG: []string{"WSTG-CONF-04"}},
			probes: []probe{{"/.svn/entries", statusWith("dir\n", "svn:")}, {"/.svn/wc.db", statusWith("SQLite format")},
				{"/.hg/requires", statusWith("revlogv1", "store")}, {"/.bzr/README", statusWith("Bazaar")}},
		},
		exposureRule{
			id: "WEB-EXP-008", title: "Log Files Downloadable From the Website", sev: check.High, cat: check.CatExposure, effort: check.EffortLow,
			cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			summary:   "Checks for application and debug logs published under the web root.",
			rationale: "Logs expose file paths, SQL queries, user data, session identifiers and sometimes credentials or API keys.",
			detection: "Requests /error_log, /debug.log, /wp-content/debug.log, /storage/logs/laravel.log and /logs/error.log; a non-HTML 200 response containing typical log markers confirms exposure.",
			fix:       "Move logs outside the web root, deny access to *.log at the web server, disable WP_DEBUG_LOG in production, and review the exposed logs for leaked secrets.",
			verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/wp-content/debug.log  should print 403 or 404.",
			refs:      []check.Ref{refWSTGConf04, {Title: "OWASP Logging Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"}},
			std:       check.Standards{CWE: []string{"CWE-532", "CWE-538"}, OWASP: []string{"A09:2021", "A05:2021"}, ASVS: []string{"7.1.1"}, WSTG: []string{"WSTG-CONF-04"}},
			probes: []probe{{"/error_log", statusWith("PHP ", "[error]")}, {"/debug.log", statusWith("PHP ", "Stack trace", "ERROR")},
				{"/wp-content/debug.log", statusWith("PHP ", "WordPress")}, {"/storage/logs/laravel.log", statusWith("local.ERROR", "production.ERROR")},
				{"/logs/error.log", statusWith("[error]", "ERROR")}},
		},
		exposureRule{
			id: "WEB-EXP-009", title: "Dependency Manifests Exposed", sev: check.Low, cat: check.CatExposure, effort: check.EffortLow,
			cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
			summary:   "Checks whether package manifests and lock files are downloadable.",
			rationale: "Lock files list exact library versions, giving attackers a ready list to match against public vulnerabilities, and often reveal internal package names.",
			detection: "Requests /composer.json, /composer.lock, /package.json, /package-lock.json, /yarn.lock and /Gemfile.lock; a non-HTML 200 response with the file's characteristic structure confirms exposure.",
			fix:       "Keep manifests outside the public web root (for example serve only a public/ subfolder), or deny them at the web server.",
			verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/composer.lock  should print 403 or 404.",
			refs:      []check.Ref{refWSTGConf04},
			std:       check.Standards{CWE: []string{"CWE-200", "CWE-538"}, OWASP: []string{"A05:2021", "A06:2021"}, WSTG: []string{"WSTG-CONF-04"}},
			probes: []probe{{"/composer.json", jsonWith(`"require"`)}, {"/composer.lock", jsonWith(`"packages"`)}, {"/package.json", jsonWith(`"dependencies"`)},
				{"/package-lock.json", jsonWith(`"lockfileVersion"`)}, {"/yarn.lock", statusWith("# yarn lockfile")}, {"/Gemfile.lock", statusWith("GEM\n", "BUNDLED WITH")}},
		},
		exposureRule{
			id: "WEB-EXP-010", title: "Default Web Server Page Served", sev: check.Low, cat: check.CatExposure, effort: check.EffortLow,
			cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
			summary:   "Checks whether a site shows the web server's default installation page.",
			rationale: "Default pages reveal the server software and suggest an unmaintained or forgotten virtual host, which attackers prioritise.",
			detection: "Inspects each site's home page for the default page markers of Apache (It works!, Apache2 Default Page), nginx (Welcome to nginx!), LiteSpeed and IIS.",
			fix:       "Remove the default site or replace its index page, and disable unused virtual hosts.",
			verify:    "Open the site in a browser; the default page should not appear.",
			refs:      []check.Ref{refWSTGInfo02},
			std:       check.Standards{CWE: []string{"CWE-1188", "CWE-200"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-INFO-02", "WSTG-CONF-02"}},
			probes:    []probe{{"/", statusWith("<h1>It works!</h1>", "Apache2 Default Page", "Apache2 Ubuntu Default Page", "Welcome to nginx!", "Test Page for the Apache HTTP Server", "Congratulations! Your LiteSpeed Web Server")}},
		},
		exposureRule{
			id: "WEB-EXP-011", title: "Database Administration Tool Exposed", sev: check.Medium, cat: check.CatExposure, effort: check.EffortLow,
			cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
			summary:   "Checks whether phpMyAdmin or Adminer login pages are publicly reachable.",
			rationale: "Database admin tools are among the most attacked paths on the internet: they invite password guessing and their own vulnerabilities give direct database access.",
			detection: "Requests /phpmyadmin/, /pma/, /phpMyAdmin/ and /adminer.php; a 200 page containing the tool's name confirms exposure. No login is attempted.",
			fix:       "Remove the tool, or restrict it to administrators by IP allow-list, VPN or an extra authentication layer, and keep it updated.",
			verify:    "From outside your network, the paths should return 403 or 404.",
			refs:      []check.Ref{{Title: "OWASP WSTG-CONF-05, Enumerate Infrastructure and Application Admin Interfaces", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"}},
			std:       check.Standards{CWE: []string{"CWE-1188", "CWE-306"}, OWASP: []string{"A05:2021", "A07:2021"}, WSTG: []string{"WSTG-CONF-05"}},
			probes: []probe{{"/phpmyadmin/", statusWith("phpMyAdmin")}, {"/pma/", statusWith("phpMyAdmin")}, {"/phpMyAdmin/", statusWith("phpMyAdmin")},
				{"/adminer.php", statusWith("Adminer")}},
		},
		exposureRule{
			id: "WEB-EXP-012", title: "Framework Debug Pages Exposed", sev: check.High, cat: check.CatExposure, effort: check.EffortLow,
			cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
			summary:   "Checks for development debug tools and verbose error pages left enabled in production.",
			rationale: "Debug pages such as the Symfony profiler, Laravel's Whoops/Ignition pages or Django's debug 404 reveal source code, configuration, environment variables and sometimes allow code execution.",
			detection: "Requests /_profiler/ and a random non-existent path (/openvapt-probe-404-x7q) and looks for framework debug markers (Symfony Profiler, Whoops, Ignition, Django URLconf debug text, Werkzeug debugger).",
			fix:       "Disable debug mode in production (APP_DEBUG=false, DEBUG = False, APP_ENV=prod), remove profiler routes, and show generic error pages.",
			verify:    "Re-run this check; no debug pages should be detected.",
			refs:      []check.Ref{refWSTGErrh},
			std:       check.Standards{CWE: []string{"CWE-489", "CWE-209"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2", "7.4.1"}, WSTG: []string{"WSTG-ERRH-01", "WSTG-CONF-02"}},
			probes: []probe{{"/_profiler/", statusWith("Symfony Profiler")},
				{"/openvapt-probe-404-x7q", func(r sys.HTTPResponse) bool {
					for _, m := range []string{"Whoops! There was an error", "Ignition", "Using the URLconf defined in", "Werkzeug Debugger", "Traceback (most recent call last)"} {
						if strings.Contains(r.Body, m) {
							return true
						}
					}
					return false
				}}},
		},
		exposureRule{
			id: "WEB-CMS-003", title: "WordPress User Accounts Enumerable", sev: check.Low, cat: check.CatExposure, effort: check.EffortLow,
			cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
			summary:   "Checks whether the WordPress REST API lists user accounts to anonymous visitors.",
			rationale: "A list of login names halves the work of password guessing and phishing against administrators.",
			detection: "Requests /wp-json/wp/v2/users and fails when it returns a JSON array with user slugs. No login is attempted.",
			fix:       "Restrict the users endpoint to authenticated requests with a security plugin or a small rest_endpoints filter, and use login names that differ from public display names.",
			verify:    "curl -s https://<site>/wp-json/wp/v2/users  should return 401, 403 or 404.",
			refs:      []check.Ref{{Title: "WordPress Developer Resources, REST API Users endpoint", URL: "https://developer.wordpress.org/rest-api/reference/users/"}},
			std:       check.Standards{CWE: []string{"CWE-200", "CWE-204"}, OWASP: []string{"A01:2021"}, WSTG: []string{"WSTG-IDNT-04"}},
			probes:    []probe{{"/wp-json/wp/v2/users", jsonWith(`"slug"`, `"id"`)}},
		},
	} {
		registerExposure(r)
	}
}
