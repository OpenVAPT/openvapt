package web

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// probe describes a fixed path to request and how to recognise a real hit.
// Requiring a content marker avoids false positives from sites that answer
// 200 with an HTML page for every path ("soft 404").
type probe struct {
	path   string
	marker func(sys.HTTPResponse) bool
}

func bodyHas(subs ...string) func(sys.HTTPResponse) bool {
	return func(r sys.HTTPResponse) bool {
		if r.Status != 200 {
			return false
		}
		for _, s := range subs {
			if strings.Contains(r.Body, s) {
				return true
			}
		}
		return false
	}
}

// binaryHit: a 200 response that is not an HTML page, for archive and dump files.
func binaryHit(r sys.HTTPResponse) bool { return r.Status == 200 && !HTML(r) && len(r.Body) > 0 }

type exposureRule struct {
	id, title, summary, rationale, detection, fix, verify string
	sev                                                   check.Severity
	cvss                                                  string
	refs                                                  []check.Ref
	std                                                   check.Standards
	probes                                                []probe
}

var exposureRules = []exposureRule{
	{
		id: "WEB-EXP-001", title: "Git Repository Exposed on the Website", sev: check.High,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "Checks whether the .git folder can be downloaded from each site.",
		rationale: "An exposed .git folder lets anyone rebuild the full source code and history, often including passwords, API keys and database credentials committed by mistake.",
		detection: "Requests /.git/HEAD and /.git/config. A 200 response containing 'ref:' or '[core]' confirms exposure.",
		fix:       "Block dot-folders in the web server (Apache: RedirectMatch 404 /\\.git ; nginx: location ~ /\\.(?!well-known) { deny all; }) and deploy without the .git folder in the web root. Rotate any secret that was ever committed.",
		verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/.git/HEAD  should print 403 or 404.",
		refs:      []check.Ref{{Title: "OWASP WSTG, Review Old Backup and Unreferenced Files (WSTG-CONF-04)", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"}},
		std:       check.Standards{CWE: []string{"CWE-527", "CWE-538"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}},
		probes:    []probe{{"/.git/HEAD", bodyHas("ref:")}, {"/.git/config", bodyHas("[core]")}},
	},
	{
		id: "WEB-EXP-002", title: "Environment or Secrets File Exposed", sev: check.Critical,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		summary:   "Checks whether .env and similar configuration files can be downloaded.",
		rationale: "Framework .env files hold database passwords, mail credentials, encryption keys and API tokens. Downloading one usually means full compromise of the application and its data.",
		detection: "Requests /.env, /.env.production, /config.php.bak and /wp-config.php.bak. A non-HTML 200 response containing typical key=value secrets (DB_, APP_KEY, DB_PASSWORD) confirms exposure. Contents are redacted in the report.",
		fix:       "Move secrets out of the web root, block dot-files at the web server, delete backup copies, then rotate every secret in the file because it must be treated as leaked.",
		verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/.env  should print 403 or 404.",
		refs:      []check.Ref{{Title: "OWASP Secrets Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}},
		std:       check.Standards{CWE: []string{"CWE-538", "CWE-200"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2", "2.10.4"}},
		probes: []probe{{"/.env", bodyHas("DB_", "APP_KEY", "PASSWORD=")}, {"/.env.production", bodyHas("DB_", "APP_KEY", "PASSWORD=")},
			{"/wp-config.php.bak", bodyHas("DB_PASSWORD")}, {"/config.php.bak", bodyHas("password", "PASSWORD")}},
	},
	{
		id: "WEB-EXP-003", title: "PHP Information Page Exposed", sev: check.Medium,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "Checks for phpinfo() pages left on the site.",
		rationale: "phpinfo() reveals PHP and module versions, file paths, environment variables and sometimes credentials, giving attackers a detailed map of the server.",
		detection: "Requests /phpinfo.php, /info.php, /php_info.php and /test.php; a 200 response containing the 'PHP Version' heading of phpinfo() confirms it.",
		fix:       "Delete the file. Never leave diagnostic pages on a production server.",
		verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/phpinfo.php  should print 404.",
		refs:      []check.Ref{{Title: "PHP manual, phpinfo()", URL: "https://www.php.net/manual/en/function.phpinfo.php"}},
		std:       check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}},
		probes: []probe{{"/phpinfo.php", bodyHas("<title>PHP ", "phpinfo()")}, {"/info.php", bodyHas("<title>PHP ", "phpinfo()")},
			{"/php_info.php", bodyHas("<title>PHP ", "phpinfo()")}, {"/test.php", bodyHas("<title>PHP ", "phpinfo()")}},
	},
	{
		id: "WEB-EXP-004", title: "Backup or Database Dump Files Downloadable", sev: check.High,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "Checks for common backup archives and SQL dumps left in the web root.",
		rationale: "Backups contain the whole site and often the whole database, including customer data and password hashes.",
		detection: "Requests a short fixed list of common names (backup.zip, backup.tar.gz, site.zip, db.sql, dump.sql, database.sql). A 200 response that is not an HTML page is reported. Only the first 64 KiB are read.",
		fix:       "Move backups outside the web root (for example /home/<user>/deploy-backups/ with mode 700), delete the exposed copies and treat their contents as leaked.",
		verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/backup.zip  should print 404.",
		refs:      []check.Ref{{Title: "OWASP WSTG-CONF-04, Review Old Backup and Unreferenced Files", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"}},
		std:       check.Standards{CWE: []string{"CWE-530"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}},
		probes: []probe{{"/backup.zip", binaryHit}, {"/backup.tar.gz", binaryHit}, {"/site.zip", binaryHit},
			{"/db.sql", bodyHas("CREATE TABLE", "INSERT INTO")}, {"/dump.sql", bodyHas("CREATE TABLE", "INSERT INTO")}, {"/database.sql", bodyHas("CREATE TABLE", "INSERT INTO")}},
	},
	{
		id: "WEB-EXP-005", title: "Directory Listing Enabled", sev: check.Medium,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "Checks whether the web server lists folder contents when there is no index page.",
		rationale: "Directory listings reveal every file in a folder, including backups, uploads and scripts never meant to be linked.",
		detection: "Requests /, /uploads/, /images/, /files/, /backup/ and /wp-content/uploads/ and looks for the auto-index page markers of Apache ('Index of /'), nginx and LiteSpeed.",
		fix:       "Apache: Options -Indexes . nginx: autoindex off; (the default). Add an empty index.html to folders that must stay browsable-free.",
		verify:    "curl -s https://<site>/uploads/ | grep -i 'index of'  should print nothing.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, Options directive", URL: "https://httpd.apache.org/docs/2.4/mod/core.html#options"}},
		std:       check.Standards{CWE: []string{"CWE-548"}, OWASP: []string{"A01:2021", "A05:2021"}, ASVS: []string{"4.3.2"}},
		probes: []probe{{"/", bodyHas("<title>Index of /")}, {"/uploads/", bodyHas("<title>Index of /")}, {"/images/", bodyHas("<title>Index of /")},
			{"/files/", bodyHas("<title>Index of /")}, {"/backup/", bodyHas("<title>Index of /")}, {"/wp-content/uploads/", bodyHas("<title>Index of /")}},
	},
	{
		id: "WEB-EXP-006", title: "Web Server Status Page Exposed", sev: check.Medium,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		summary:   "Checks whether Apache server-status/server-info or nginx stub_status are reachable for each site.",
		rationale: "Status pages show live requests (including URLs with tokens), client IPs, virtual hosts and modules.",
		detection: "Requests /server-status, /server-info and /nginx_status for each site through 127.0.0.1. Note: these pages are often allowed from localhost only, so a hit is confirmed only when the web server configuration does not restrict by IP; review the result manually.",
		fix:       "Restrict to administrators: <Location /server-status> Require local </Location> (Apache), or allow 127.0.0.1; deny all; (nginx). Remove the module if unused.",
		verify:    "From another machine: curl -s -o /dev/null -w '%{http_code}' https://<site>/server-status  should print 403 or 404.",
		refs:      []check.Ref{{Title: "Apache HTTP Server, mod_status", URL: "https://httpd.apache.org/docs/2.4/mod/mod_status.html"}},
		std:       check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}},
		probes: []probe{{"/server-status", bodyHas("Apache Server Status")}, {"/server-info", bodyHas("Apache Server Information")},
			{"/nginx_status", bodyHas("Active connections:")}},
	},
}

func init() {
	for _, r := range exposureRules {
		r := r
		check.Register(&check.Check{
			ID: r.id, Title: r.title, Domain: check.DomainWeb, Severity: r.sev, CVSS: r.cvss,
			Summary: r.summary, Rationale: r.rationale, Detection: r.detection, Fix: r.fix, Verify: r.verify,
			Refs: r.refs, Standards: r.std,
			Run: func(ctx context.Context, s sys.System) []check.Result {
				return ForEachSite(ctx, s, func(st Site) check.Result {
					var hits []string
					for _, p := range r.probes {
						resp, err := st.Get(ctx, s, p.path)
						if err == nil && p.marker(resp) {
							hits = append(hits, p.path+" (HTTP 200)")
						}
					}
					if len(hits) > 0 {
						return check.FailR(st.Name, "Exposed: "+strings.Join(hits, ", "), hits...)
					}
					return check.PassR(st.Name, "Not exposed")
				})
			},
		})
	}
}
