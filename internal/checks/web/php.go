package web

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

var refPHPIni = check.Ref{Title: "PHP manual, php.ini directives", URL: "https://www.php.net/manual/en/ini.list.php"}

// phpIni asks the PHP CLI for configuration values using only echo ini_get(),
// which is enforced by the sys allow-list. Note: the CLI may use a different
// php.ini from PHP-FPM; the evidence says which binary was asked.
func phpIni(ctx context.Context, s sys.System, keys ...string) (map[string]string, bool) {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString("echo ini_get('" + k + "'),\"\\n\";")
	}
	out, err := s.Run(ctx, "php", "-r", b.String())
	if err != nil {
		return nil, false
	}
	vals := strings.Split(out, "\n")
	m := map[string]string{}
	for i, k := range keys {
		if i < len(vals) {
			m[k] = strings.TrimSpace(vals[i])
		}
	}
	return m, true
}

func on(v string) bool {
	v = strings.ToLower(v)
	return v == "1" || v == "on" || v == "yes" || v == "true" || v == "stdout" || v == "stderr"
}

// phpEOL: end of security support per https://www.php.net/supported-versions.php
var phpEOL = map[string]string{
	"5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06",
	"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31", "8.5": "2029-12-31",
}

func init() {
	iniRule := func(id, title, key, summary, rationale, fix string, sev check.Severity, cvss string, std check.Standards, bad func(string) bool) {
		check.Register(&check.Check{
			ID: id, Title: title, Domain: check.DomainWeb, Severity: sev,
			CVSS:      cvss,
			Summary:   summary,
			Rationale: rationale,
			Detection: "Asks the PHP command-line binary for ini_get('" + key + "') (the only PHP code OpenVAPT may run). Web PHP-FPM pools can use a different php.ini; verify those too.",
			Fix:       fix,
			Verify:    "php -r \"echo ini_get('" + key + "');\"  and check the FPM pool's php.ini or php_admin_value settings.",
			Refs:      []check.Ref{refPHPIni, {Title: "OWASP PHP Configuration Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html"}},
			Standards: std,
			Run: func(ctx context.Context, s sys.System) []check.Result {
				m, ok := phpIni(ctx, s, key)
				if !ok {
					return []check.Result{check.SkipR("php", "PHP command-line binary not found")}
				}
				if bad(m[key]) {
					return []check.Result{check.FailR("php", key+" = "+m[key])}
				}
				return []check.Result{check.PassR("php", key+" = "+orOff(m[key]))}
			},
		})
	}
	iniRule("WEB-PHP-001", "PHP Displays Errors to Visitors", "display_errors",
		"Checks whether PHP prints error messages into web pages.",
		"Error messages reveal file paths, SQL queries and code structure, and can leak data. They help attackers turn a small bug into a working exploit.",
		"In php.ini set  display_errors = Off  and  log_errors = On , then restart PHP-FPM or the web server.", check.Medium, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", check.Standards{CWE: []string{"CWE-209"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}, WSTG: []string{"WSTG-ERRH-01"}, NIST: []string{"SI-11", "CM-6"}}, on)
	iniRule("WEB-PHP-002", "PHP Version Exposed in Headers", "expose_php",
		"Checks whether PHP adds an X-Powered-By header with its version.",
		"The header advertises the exact PHP version to every visitor and scanner.",
		"In php.ini set  expose_php = Off  and restart PHP.", check.Low, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", check.Standards{CWE: []string{"CWE-497"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.3"}, WSTG: []string{"WSTG-INFO-02"}, NIST: []string{"CM-7", "SI-11"}}, on)
	iniRule("WEB-PHP-003", "PHP Allows Remote File Inclusion", "allow_url_include",
		"Checks whether include() and require() may load code from URLs.",
		"With allow_url_include on, a single file-inclusion bug lets an attacker run their own PHP code from their own server (remote file inclusion).",
		"In php.ini set  allow_url_include = Off  (the default since PHP 5.2) and restart PHP.", check.High, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", check.Standards{CWE: []string{"CWE-98"}, OWASP: []string{"A03:2021", "A05:2021"}, ASVS: []string{"12.3.3"}, NIST: []string{"CM-6", "CM-7"}}, on)

	check.Register(&check.Check{
		ID:        "WEB-PHP-004",
		Title:     "PHP Version Past End of Security Support",
		Domain:    check.DomainWeb,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether the installed PHP branch still receives security fixes from the PHP project.",
		Rationale: "Unsupported PHP versions never get fixes for newly found vulnerabilities, some of which allow remote code execution.",
		Detection: "Runs php -v, extracts the major.minor version and compares it with the PHP project's published end-of-security-support dates. Distribution vendors may backport fixes; the evidence notes this.",
		Fix:       "Upgrade to a supported PHP branch (see php.net/supported-versions) and test the applications, or confirm your distribution still backports security fixes to this version.",
		Verify:    "php -v",
		Refs:      []check.Ref{{Title: "PHP, Supported Versions", URL: "https://www.php.net/supported-versions.php"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, ASVS: []string{"14.2.1"}, NIST: []string{"SI-2"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			out, err := s.Run(ctx, "php", "-v")
			if err != nil {
				return []check.Result{check.SkipR("php", "PHP command-line binary not found")}
			}
			m := regexp.MustCompile(`PHP (\d+\.\d+)\.(\d+)`).FindStringSubmatch(out)
			if m == nil {
				return []check.Result{check.SkipR("php", "PHP version not recognised")}
			}
			end, ok := phpEOL[m[1]]
			if !ok && phpOlderThanTable(m[1]) {
				return []check.Result{check.FailR("php", "PHP "+m[1]+" is older than every branch in the support table (oldest 5.6, ended 2018-12-31)", "Check whether your distribution backports security fixes to this version")}
			}
			if !ok {
				return []check.Result{check.SkipR("php", "PHP "+m[1]+" not in the support table")}
			}
			if end < today() {
				return []check.Result{check.FailR("php", "PHP "+m[1]+" security support ended on "+end, "Check whether your distribution backports security fixes to this version")}
			}
			return []check.Result{check.PassR("php", "PHP "+m[1]+" supported until "+end)}
		},
	})
}

func orOff(v string) string {
	if v == "" {
		return "Off"
	}
	return v
}

func init() {
	check.Register(&check.Check{
		ID: "WEB-PHP-005", Title: "PHP Session Cookies Not Hardened", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatWebApp, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
		Summary:   "Checks PHP's session settings: HttpOnly and SameSite cookies and strict session id mode.",
		Rationale: "Session cookies are the keys to logged-in accounts. Without HttpOnly any XSS bug can steal them; without strict mode PHP accepts attacker-chosen session ids (session fixation).",
		Detection: "Asks the PHP command-line binary for ini_get('session.cookie_httponly'), ini_get('session.use_strict_mode') and ini_get('session.cookie_samesite'). PHP-FPM pools may use a different php.ini; verify those too.",
		Fix:       "In php.ini set  session.cookie_httponly = 1 ,  session.use_strict_mode = 1 ,  session.cookie_samesite = Lax  and, for HTTPS sites,  session.cookie_secure = 1 , then restart PHP-FPM.",
		Verify:    "php -r \"echo ini_get('session.cookie_httponly'), ini_get('session.use_strict_mode'), ini_get('session.cookie_samesite');\"",
		Refs:      []check.Ref{refPHPIni, {Title: "PHP manual, Session security", URL: "https://www.php.net/manual/en/session.security.php"}},
		Standards: check.Standards{CWE: []string{"CWE-1004", "CWE-384"}, OWASP: []string{"A07:2021"}, ASVS: []string{"3.4.2", "3.2.1"}, WSTG: []string{"WSTG-SESS-02", "WSTG-SESS-03"}, NIST: []string{"SC-23", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			m, ok := phpIni(ctx, s, "session.cookie_httponly", "session.use_strict_mode", "session.cookie_samesite")
			if !ok {
				return []check.Result{check.SkipR("php", "PHP command-line binary not found")}
			}
			var bad []string
			if !on(m["session.cookie_httponly"]) {
				bad = append(bad, "session.cookie_httponly = "+orOff(m["session.cookie_httponly"]))
			}
			if !on(m["session.use_strict_mode"]) {
				bad = append(bad, "session.use_strict_mode = "+orOff(m["session.use_strict_mode"]))
			}
			if strings.TrimSpace(m["session.cookie_samesite"]) == "" {
				bad = append(bad, "session.cookie_samesite is empty")
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("php", "PHP session cookies are not hardened", bad...)}
			}
			return []check.Result{check.PassR("php", "PHP session cookies are hardened")}
		},
	})
}

// phpOlderThanTable reports a major.minor version below 5.6, the oldest row
// of phpEOL; every such branch is long past end of support.
func phpOlderThanTable(v string) bool {
	maj, min, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	if err1 != nil || err2 != nil {
		return false
	}
	return a < 5 || a == 5 && b < 6
}
