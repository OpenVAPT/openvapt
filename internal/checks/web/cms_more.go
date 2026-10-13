package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Deeper WordPress, Joomla and Drupal checks. Configuration files are found
// through the local web roots and read for a few settings only; they hold
// database passwords, so nothing but the path and the setting name is ever
// reported. HTTP checks send one GET for a fixed public file.

var refWPHardening = check.Ref{Title: "WordPress Developer Resources, Hardening WordPress", URL: "https://developer.wordpress.org/advanced-administration/security/hardening/"}
var refWPConfig = check.Ref{Title: "WordPress Developer Resources, Editing wp-config.php", URL: "https://developer.wordpress.org/advanced-administration/wordpress/wp-config/"}

// phpComment removes PHP comments (// ..., # ..., /* ... */) so a
// commented-out define() is never read as active configuration.
var phpComment = regexp.MustCompile(`(?s:/\*.*?\*/)|(?m:(^|[^:])//[^\n]*)|(?m:^[ \t]*#[^\n]*)`)

// wpDefine returns the value of the first active define('NAME', value):
// PHP keeps the first definition of a constant and ignores later ones.
func wpDefine(text, name string) (string, bool) {
	text = phpComment.ReplaceAllString(text, "$1")
	re := regexp.MustCompile(`(?i)define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*(.+?)\s*\)\s*;`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	return strings.ToLower(strings.Trim(m[1], `'" `)), true
}

func cmsCheck(ctx context.Context, s sys.System, cms string, judge func(collect.CMSConfig) []string, failMsg string) []check.Result {
	var out []check.Result
	for _, c := range collect.CMSConfigs(ctx, s) {
		if cms != "" && c.CMS != cms {
			continue
		}
		if bad := judge(c); len(bad) > 0 {
			out = append(out, check.FailR(c.Path, failMsg, bad...))
		} else {
			out = append(out, check.PassR(c.Path, "No issue found"))
		}
	}
	if len(out) == 0 {
		name := cms
		if name == "" {
			name = "WordPress, Joomla or Drupal"
		}
		return []check.Result{check.SkipR("web roots", "No "+name+" configuration found in the local web roots")}
	}
	return out
}

func modeCheck(s sys.System, c collect.CMSConfig, mask uint32, what string) []string {
	st, err := s.Stat(c.Path)
	if err != nil {
		return nil
	}
	if uint32(st.Mode.Perm())&mask != 0 {
		return []string{fmt.Sprintf("%s configuration has mode %04o (%s)", c.CMS, st.Mode.Perm(), what)}
	}
	return nil
}

func init() {
	check.Register(&check.Check{
		ID: "WEB-CMS-004", Title: "CMS Configuration Readable by All Users", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks whether wp-config.php, Joomla configuration.php or Drupal settings.php can be read by every local user.",
		Rationale: "These files hold the database password and the keys that sign logins. If every account on the machine can read them, any other site, user or compromised process on the server can take over the CMS and its data.",
		Detection: "Finds the configuration files through the local web roots (WordPress also one folder above the root) and reads their permission bits. Fails when the world-read bit is set.",
		Fix:       "chmod 640 <file> and chown it to the site owner with the web server's group (for example chown deploy:www-data wp-config.php); on PHP-FPM pools that run as the site user, 600 or 400 also works. Rotate the database password if other people have shell access.",
		Verify:    "stat -c '%a %U:%G %n' <file>  shows 640, 600 or 400.",
		Refs:      []check.Ref{refWPHardening, {Title: "Drupal.org, Securing file permissions and ownership", URL: "https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-file-permissions-and-ownership"}},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-260"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-CONF-09"}, NIST: []string{"AC-3", "SC-28"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return cmsCheck(ctx, s, "", func(c collect.CMSConfig) []string { return modeCheck(s, c, 0o004, "readable by all users") }, "CMS configuration is readable by all users")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-005", Title: "CMS Configuration Writable by Other Users", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether wp-config.php, Joomla configuration.php or Drupal settings.php is group- or world-writable.",
		Rationale: "These files are PHP code that runs on every request. Whoever can write them can add a backdoor that runs as the web server, which is how many shared-hosting compromises spread from one site to the next.",
		Detection: "Finds the configuration files through the local web roots and fails when the group-write or world-write permission bit is set.",
		Fix:       "chmod 640 (or 440) <file>. Drupal also expects sites/default to be 555 after installation. Review the file for code you did not add.",
		Verify:    "stat -c '%a %n' <file>  shows no write bit for group or others.",
		Refs:      []check.Ref{refWPHardening, {Title: "Drupal.org, Securing file permissions and ownership", URL: "https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-file-permissions-and-ownership"}},
		Standards: check.Standards{CWE: []string{"CWE-732"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-CONF-09"}, NIST: []string{"AC-3", "CM-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return cmsCheck(ctx, s, "", func(c collect.CMSConfig) []string { return modeCheck(s, c, 0o022, "writable by group or others") }, "CMS configuration is writable by other users")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-006", Title: "WordPress Shows Debug Output to Visitors", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks wp-config.php for WP_DEBUG enabled without WP_DEBUG_DISPLAY set to false.",
		Rationale: "With WP_DEBUG on and display not turned off, PHP notices and errors are printed into pages, revealing server paths, plugin names and sometimes database details to anyone browsing the site.",
		Detection: "Reads define('WP_DEBUG', ...) and define('WP_DEBUG_DISPLAY', ...) from each wp-config.php found through the web roots.",
		Fix:       "In production set define('WP_DEBUG', false);. If you need logs, use define('WP_DEBUG_LOG', '/path/outside/webroot/wp-debug.log'); together with define('WP_DEBUG_DISPLAY', false);.",
		Verify:    "grep -E \"WP_DEBUG(_DISPLAY)?'\" wp-config.php",
		Refs:      []check.Ref{{Title: "WordPress Developer Resources, Debugging in WordPress", URL: "https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/"}},
		Standards: check.Standards{CWE: []string{"CWE-209", "CWE-489"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-ERRH-01"}, NIST: []string{"SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return cmsCheck(ctx, s, "WordPress", func(c collect.CMSConfig) []string {
				dbg, _ := wpDefine(c.Text, "WP_DEBUG")
				disp, set := wpDefine(c.Text, "WP_DEBUG_DISPLAY")
				if dbg == "true" && (!set || disp == "true" || disp == "1") {
					return []string{"WP_DEBUG is true and WP_DEBUG_DISPLAY is not false"}
				}
				return nil
			}, "WordPress displays debug output")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-007", Title: "WordPress Dashboard File Editor Enabled", Domain: check.DomainWeb,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks whether wp-config.php leaves the built-in theme and plugin file editor enabled.",
		Rationale: "The editor lets any administrator account change PHP files from the browser. A stolen or phished admin session then becomes code execution on the server in one step.",
		Detection: "Reads each wp-config.php found through the web roots and fails unless DISALLOW_FILE_EDIT or DISALLOW_FILE_MODS is defined as true.",
		Fix:       "Add define('DISALLOW_FILE_EDIT', true); to wp-config.php above the line that says to stop editing.",
		Verify:    "The Theme File Editor and Plugin File Editor menus disappear from the dashboard.",
		Refs:      []check.Ref{refWPHardening, refWPConfig},
		Standards: check.Standards{CWE: []string{"CWE-94", "CWE-1188"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-7", "AC-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return cmsCheck(ctx, s, "WordPress", func(c collect.CMSConfig) []string {
				for _, k := range []string{"DISALLOW_FILE_EDIT", "DISALLOW_FILE_MODS"} {
					if v, ok := wpDefine(c.Text, k); ok && (v == "true" || v == "1") {
						return nil
					}
				}
				return []string{"DISALLOW_FILE_EDIT is not set to true"}
			}, "WordPress file editor is enabled")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-008", Title: "WordPress Automatic Updates Disabled", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatPatch, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks whether wp-config.php turns off WordPress background updates, including security releases.",
		Rationale: "WordPress ships security fixes as automatic minor updates. Turning the updater off means the site stays vulnerable until someone remembers to update by hand, which is how most compromised WordPress sites fall behind.",
		Detection: "Reads each wp-config.php found through the web roots and fails when AUTOMATIC_UPDATER_DISABLED is true or WP_AUTO_UPDATE_CORE is false.",
		Fix:       "Remove those lines, or set define('WP_AUTO_UPDATE_CORE', 'minor'); so at least security releases install automatically. Keep backups and enable plugin auto-updates where practical.",
		Verify:    "Dashboard, Updates shows that automatic updates for maintenance and security releases are on.",
		Refs:      []check.Ref{{Title: "WordPress Developer Resources, Configuring Automatic Background Updates", URL: "https://developer.wordpress.org/advanced-administration/upgrade/upgrading/#configuring-automatic-background-updates"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return cmsCheck(ctx, s, "WordPress", func(c collect.CMSConfig) []string {
				var bad []string
				if v, ok := wpDefine(c.Text, "AUTOMATIC_UPDATER_DISABLED"); ok && (v == "true" || v == "1") {
					bad = append(bad, "AUTOMATIC_UPDATER_DISABLED is true")
				}
				if v, ok := wpDefine(c.Text, "WP_AUTO_UPDATE_CORE"); ok && v == "false" {
					bad = append(bad, "WP_AUTO_UPDATE_CORE is false")
				}
				return bad
			}, "WordPress automatic updates are disabled")
		},
	})

	joomlaVar := func(text, name string) string {
		m := regexp.MustCompile(`(?m)public\s+\$` + name + `\s*=\s*['"]?([^'";]*)`).FindStringSubmatch(text)
		if m == nil {
			return ""
		}
		return strings.ToLower(m[1])
	}
	check.Register(&check.Check{
		ID: "WEB-CMS-009", Title: "Joomla Debug or Verbose Error Reporting Enabled", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks Joomla configuration.php for debug mode or maximum/development error reporting.",
		Rationale: "Joomla's debug console and verbose error reporting print queries, file paths and configuration details into pages that visitors can see.",
		Detection: "Reads configuration.php found through the web roots and fails when $debug is 1 or $error_reporting is maximum or development.",
		Fix:       "In System, Global Configuration set Debug System to No and Error Reporting to None (or System Default), or set public $debug = false; and public $error_reporting = 'none'; in configuration.php.",
		Verify:    "grep -E 'debug|error_reporting' configuration.php",
		Refs:      []check.Ref{{Title: "Joomla Documentation, Security Checklist: Site Administration", URL: "https://docs.joomla.org/Security_Checklist/Site_Administration"}},
		Standards: check.Standards{CWE: []string{"CWE-209", "CWE-489"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-ERRH-01"}, NIST: []string{"SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return cmsCheck(ctx, s, "Joomla", func(c collect.CMSConfig) []string {
				var bad []string
				if v := joomlaVar(c.Text, "debug"); v == "1" || v == "true" {
					bad = append(bad, "$debug is enabled")
				}
				if v := joomlaVar(c.Text, "error_reporting"); v == "maximum" || v == "development" {
					bad = append(bad, "$error_reporting is "+v)
				}
				return bad
			}, "Joomla debug output is enabled")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-010", Title: "Joomla Version Disclosed", Domain: check.DomainWeb,
		Severity: check.Low, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks whether a Joomla site serves its version manifest at /administrator/manifests/files/joomla.xml.",
		Rationale: "The manifest gives the exact Joomla version, which lets automated tools pick exploits for known vulnerabilities, such as the unauthenticated information disclosure CVE-2023-23752.",
		Detection: "Sends one GET for /administrator/manifests/files/joomla.xml and fails on a 200 response that contains a <version> element.",
		Fix:       "Block the folder at the web server (Apache: <Directory \"/path/administrator/manifests\"> Require all denied </Directory>; nginx: location ^~ /administrator/manifests/ { deny all; }) and keep Joomla updated.",
		Verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/administrator/manifests/files/joomla.xml  prints 403 or 404.",
		Refs:      []check.Ref{{Title: "Joomla Documentation, Security Checklist", URL: "https://docs.joomla.org/Security_Checklist"}, {Title: "NVD, CVE-2023-23752", URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-23752"}},
		Standards: check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021", "A06:2021"}, WSTG: []string{"WSTG-INFO-08"}, NIST: []string{"SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			ver := regexp.MustCompile(`<version>([^<]+)</version>`)
			return ForEachSite(ctx, s, func(st Site) check.Result {
				r, err := st.Get(ctx, s, "/administrator/manifests/files/joomla.xml")
				if err == nil && r.Status == 200 {
					if m := ver.FindStringSubmatch(r.Body); m != nil && strings.Contains(r.Body, "oomla") {
						return check.FailR(st.Name, "Joomla version manifest is public", "version "+m[1])
					}
				}
				return check.PassR(st.Name, "No Joomla version manifest is served")
			})
		},
	})

	check.Register(&check.Check{
		ID: "WEB-CMS-011", Title: "Drupal Version Disclosed by Changelog", Domain: check.DomainWeb,
		Severity: check.Low, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks whether a Drupal site serves CHANGELOG.txt, which names the exact Drupal version.",
		Rationale: "The changelog tells attackers precisely which Drupal security advisories apply, as was used at scale for Drupalgeddon 2 (CVE-2018-7600).",
		Detection: "Sends one GET each for /CHANGELOG.txt and /core/CHANGELOG.txt and fails on a 200 response that mentions Drupal.",
		Fix:       "Delete the changelog files after each update, or deny *.txt files in the Drupal root and core folders at the web server, and keep Drupal updated.",
		Verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/core/CHANGELOG.txt  prints 403 or 404.",
		Refs:      []check.Ref{{Title: "Drupal.org, Security advisories", URL: "https://www.drupal.org/security"}, {Title: "NVD, CVE-2018-7600", URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"}},
		Standards: check.Standards{CWE: []string{"CWE-200"}, OWASP: []string{"A05:2021", "A06:2021"}, WSTG: []string{"WSTG-INFO-08"}, NIST: []string{"SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				for _, p := range []string{"/CHANGELOG.txt", "/core/CHANGELOG.txt"} {
					if r, err := st.Get(ctx, s, p); err == nil && r.Status == 200 && strings.Contains(r.Body, "Drupal") && !HTML(r) {
						line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(r.Body), "\n", 2)[0])
						return check.FailR(st.Name, "Drupal changelog is public", p+": "+line)
					}
				}
				return check.PassR(st.Name, "No Drupal changelog is served")
			})
		},
	})
}
