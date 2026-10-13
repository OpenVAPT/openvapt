package web

import (
	"context"
	"regexp"
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
	"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31",
}

func init() {
	iniRule := func(id, title, key, summary, rationale, fix string, sev check.Severity, cwe string, bad func(string) bool) {
		check.Register(&check.Check{
			ID: id, Title: title, Domain: check.DomainWeb, Severity: sev,
			CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Summary:   summary,
			Rationale: rationale,
			Detection: "Asks the PHP command-line binary for ini_get('" + key + "') (the only PHP code OpenVAPT may run). Web PHP-FPM pools can use a different php.ini; verify those too.",
			Fix:       fix,
			Verify:    "php -r \"echo ini_get('" + key + "');\"  and check the FPM pool's php.ini or php_admin_value settings.",
			Refs:      []check.Ref{refPHPIni, {Title: "OWASP PHP Configuration Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html"}},
			Standards: check.Standards{CWE: []string{cwe}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}},
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
		"In php.ini set  display_errors = Off  and  log_errors = On , then restart PHP-FPM or the web server.", check.Medium, "CWE-209", on)
	iniRule("WEB-PHP-002", "PHP Version Exposed in Headers", "expose_php",
		"Checks whether PHP adds an X-Powered-By header with its version.",
		"The header advertises the exact PHP version to every visitor and scanner.",
		"In php.ini set  expose_php = Off  and restart PHP.", check.Low, "CWE-200", on)
	iniRule("WEB-PHP-003", "PHP Allows Remote File Inclusion", "allow_url_include",
		"Checks whether include() and require() may load code from URLs.",
		"With allow_url_include on, a single file-inclusion bug lets an attacker run their own PHP code from their own server (remote file inclusion).",
		"In php.ini set  allow_url_include = Off  (the default since PHP 5.2) and restart PHP.", check.High, "CWE-98", on)

	check.Register(&check.Check{
		ID:        "WEB-PHP-004",
		Title:     "PHP Version Past End of Security Support",
		Domain:    check.DomainWeb,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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
