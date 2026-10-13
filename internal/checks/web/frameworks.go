package web

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Application framework configuration checks (WEB-APP). Laravel, Symfony,
// Rails, Spring Boot and Flask projects are found through the same project
// folders as the Django checks (collect.ProjectFiles). Configuration files
// hold secrets, so only the path and the name of the setting are reported,
// never a value; files under writable project folders are read without
// following symlinks.

var (
	refLaravelDeploy = check.Ref{Title: "Laravel documentation, Deployment", URL: "https://laravel.com/docs/12.x/deployment"}
	refLaravelConfig = check.Ref{Title: "Laravel documentation, Configuration (debug mode, environment files)", URL: "https://laravel.com/docs/12.x/configuration"}
	refSymfonyEnv    = check.Ref{Title: "Symfony documentation, Configuring Symfony (environments)", URL: "https://symfony.com/doc/current/configuration.html"}
	refRailsSecurity = check.Ref{Title: "Ruby on Rails Guides, Securing Rails Applications", URL: "https://guides.rubyonrails.org/security.html"}
	refRailsConfig   = check.Ref{Title: "Ruby on Rails Guides, Configuring Rails Applications", URL: "https://guides.rubyonrails.org/configuring.html"}
	refSpringAct     = check.Ref{Title: "Spring Boot documentation, Actuator endpoints", URL: "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html"}
	refFlaskDebug    = check.Ref{Title: "Flask documentation, Debug mode", URL: "https://flask.palletsprojects.com/en/stable/quickstart/#debug-mode"}
	refASVSV14       = check.Ref{Title: "OWASP ASVS 4.0.3, V14 Configuration", URL: "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x22-V14-Config.md"}
	refWSTGConf02    = check.Ref{Title: "OWASP WSTG-CONF-02, Test Application Platform Configuration", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration/"}
	refSecretsCS     = check.Ref{Title: "OWASP Secrets Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}
	refOWASPDepCheck = check.Ref{Title: "OWASP Vulnerable Dependency Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html"}
)

// envFile is one dotenv file found in a project folder.
type envFile struct {
	path string
	vars map[string]string // upper-cased key -> value, comments removed
	mode sys.FileInfo
}

// parseDotenv reads KEY=value lines. Quotes are stripped; values are kept
// only in memory for comparisons and never reported.
func parseDotenv(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		t = strings.TrimPrefix(t, "export ")
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if q := v[:min(len(v), 1)]; q == `"` || q == `'` {
			// Quoted value: keep everything up to the closing quote.
			if end := strings.Index(v[1:], q); end >= 0 {
				v = v[1 : end+1]
			} else {
				v = strings.Trim(v, q)
			}
		} else if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		out[strings.ToUpper(strings.TrimSpace(k))] = v
	}
	return out
}

// envFiles returns every .env file in the project folders that contains at
// least one of the marker keys (so a Laravel check never reads a Symfony
// file as Laravel and vice versa).
func envFiles(ctx context.Context, s sys.System, markers ...string) []envFile {
	var out []envFile
	for _, p := range collect.ProjectFiles(ctx, s, ".env") {
		r, err := sys.ReadFileNoFollow(ctx, s, p)
		if err != nil {
			continue
		}
		vars := parseDotenv(string(r.Data))
		hit := len(markers) == 0
		for _, m := range markers {
			if _, ok := vars[m]; ok {
				hit = true
			}
		}
		if !hit {
			continue
		}
		st, _ := s.Stat(p)
		out = append(out, envFile{path: p, vars: vars, mode: st})
	}
	return out
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// unreadable is the verdict a judge returns when its file could not be read;
// perFile reports it as Incomplete rather than Fail.
const unreadable = "could not be read"

// perFile turns per-path verdicts into results, or a Skip when nothing was found.
func perFile(paths []string, judge func(string) []string, failMsg, skipMsg string) []check.Result {
	if len(paths) == 0 {
		return []check.Result{check.SkipR("projects", skipMsg)}
	}
	var out []check.Result
	for _, p := range paths {
		if bad := judge(p); len(bad) == 1 && bad[0] == unreadable {
			out = append(out, check.IncompleteR(p, "File could not be read"))
		} else if len(bad) > 0 {
			out = append(out, check.FailR(p, failMsg, bad...))
		} else {
			out = append(out, check.PassR(p, "No issue found"))
		}
	}
	return out
}

func init() {
	check.Register(&check.Check{
		ID: "WEB-APP-001", Title: "Laravel Debug Mode On or Application Key Missing", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks Laravel .env files for APP_DEBUG=true or an empty APP_KEY.",
		Rationale: "With APP_DEBUG on, Laravel's error page prints the environment, including database and mail passwords, to any visitor who triggers an error. APP_KEY encrypts sessions and cookies; with it empty or default the application refuses to run or signs nothing.",
		Detection: "Finds .env files in /srv, /opt, /var/www, home folders and web roots (three folders deep) that contain APP_KEY (the Laravel marker) and fails when APP_DEBUG is true or APP_KEY is empty. Values are never reported.",
		Fix:       "Set APP_DEBUG=false and APP_ENV=production in .env, run php artisan key:generate if APP_KEY is empty, then php artisan config:cache. Keep .env outside the web root (Laravel's public/ folder) and readable only by the application user.",
		Verify:    "grep -E '^APP_(DEBUG|KEY)=' .env  shows APP_DEBUG=false and a base64 key.",
		Refs:      []check.Ref{refLaravelDeploy, refLaravelConfig, refASVSV14},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-209", "CWE-321"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2", "2.10.4"}, WSTG: []string{"WSTG-CONF-02", "WSTG-ERRH-01"}, NIST: []string{"CM-6", "SI-11", "IA-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files := envFiles(ctx, s, "APP_KEY")
			var paths []string
			byPath := map[string]envFile{}
			for _, f := range files {
				paths = append(paths, f.path)
				byPath[f.path] = f
			}
			return perFile(paths, func(p string) []string {
				f := byPath[p]
				var bad []string
				if truthy(f.vars["APP_DEBUG"]) {
					bad = append(bad, "APP_DEBUG is true")
				}
				if strings.TrimSpace(f.vars["APP_KEY"]) == "" {
					bad = append(bad, "APP_KEY is empty")
				}
				return bad
			}, "Laravel runs in debug mode or without an application key", "No Laravel .env files found")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-002", Title: "Application .env File Readable by All Users", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks the permission bits of framework .env files for world-read access.",
		Rationale: ".env files hold database passwords, API tokens and signing keys in plain text. A world-readable .env hands every account on the server, including other websites' PHP-FPM pools, the keys to this application.",
		Detection: "Stats each .env file found in the project folders (metadata only) and fails when the 'other read' permission bit is set.",
		Fix:       "chmod 640 .env && chown <app-user>:<web-group> .env  (or 600 when the application runs as its own user). Rotate the secrets if other people have had shell access.",
		Verify:    "stat -c '%a %U:%G %n' .env  shows 640 or 600.",
		Refs:      []check.Ref{refSecretsCS, refASVSV14},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-312"}, OWASP: []string{"A05:2021", "A02:2021"}, ASVS: []string{"14.1.3"}, WSTG: []string{"WSTG-CONF-09"}, NIST: []string{"AC-3", "SC-28"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files := envFiles(ctx, s)
			var paths []string
			byPath := map[string]envFile{}
			for _, f := range files {
				paths = append(paths, f.path)
				byPath[f.path] = f
			}
			return perFile(paths, func(p string) []string {
				if byPath[p].mode.Mode.Perm()&0o004 != 0 {
					return []string{fmt.Sprintf("mode %04o is readable by all users", byPath[p].mode.Mode.Perm())}
				}
				return nil
			}, ".env file is readable by all users", "No .env files found in the project folders")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-003", Title: "Symfony Running in the Development Environment", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks Symfony .env files for APP_ENV=dev or APP_DEBUG=1.",
		Rationale: "The dev environment enables the web profiler and debug toolbar, which show requests, queries, configuration, the container and sometimes credentials to any visitor, and it skips the caches that production relies on.",
		Detection: "Finds .env files that contain APP_SECRET (the Symfony marker) and fails when APP_ENV is dev or test, or APP_DEBUG is 1 or true. A .env.local or .env.prod override is not evaluated, so confirm the final value on the server.",
		Fix:       "Set APP_ENV=prod and APP_DEBUG=0 in .env (or .env.local), run composer dump-env prod, clear the cache (php bin/console cache:clear) and remove the web profiler bundle from production.",
		Verify:    "php bin/console about  shows Environment prod and Debug false.",
		Refs:      []check.Ref{refSymfonyEnv, {Title: "Symfony documentation, How to Deploy a Symfony Application", URL: "https://symfony.com/doc/current/deployment.html"}, refASVSV14},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-215"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}, WSTG: []string{"WSTG-CONF-02", "WSTG-ERRH-01"}, NIST: []string{"CM-6", "SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files := envFiles(ctx, s, "APP_SECRET")
			var paths []string
			byPath := map[string]envFile{}
			for _, f := range files {
				paths = append(paths, f.path)
				byPath[f.path] = f
			}
			return perFile(paths, func(p string) []string {
				f := byPath[p]
				var bad []string
				if e := strings.ToLower(f.vars["APP_ENV"]); e == "dev" || e == "test" {
					bad = append(bad, "APP_ENV is "+e)
				}
				if truthy(f.vars["APP_DEBUG"]) {
					bad = append(bad, "APP_DEBUG is on")
				}
				return bad
			}, "Symfony runs in the development environment", "No Symfony .env files found")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-004", Title: "Rails Master Key or Secrets File Exposed", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks Rails config/master.key, credentials key files and secrets.yml for world-read permissions or a location inside a web root.",
		Rationale: "master.key decrypts credentials.yml.enc, which holds every production secret, and secrets.yml holds the secret_key_base that signs sessions. Anyone who reads them can forge sessions and read the database password. Both are meant to stay out of version control and out of any public folder.",
		Detection: "Finds config/master.key, config/credentials/*.key and config/secrets.yml in the project folders and fails when the file is readable by others or sits inside a web document root. Contents are never read.",
		Fix:       "chmod 600 config/master.key config/credentials/*.key; keep them out of git (.gitignore) and out of public/; load the key from RAILS_MASTER_KEY in the environment on servers. Rotate the credentials if the key was ever exposed.",
		Verify:    "stat -c '%a %n' config/master.key  shows 600, and git ls-files config/master.key  prints nothing.",
		Refs:      []check.Ref{refRailsSecurity, {Title: "Ruby on Rails Guides, Custom Credentials", URL: "https://guides.rubyonrails.org/security.html#custom-credentials"}, refSecretsCS},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-312", "CWE-321"}, OWASP: []string{"A02:2021", "A05:2021"}, ASVS: []string{"2.10.4", "14.1.3"}, WSTG: []string{"WSTG-CONF-09"}, NIST: []string{"AC-3", "SC-28", "IA-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			paths := collect.ProjectFiles(ctx, s, "config/master.key", "config/credentials/*.key", "config/secrets.yml")
			roots := collect.DocRoots(ctx, s)
			return perFile(paths, func(p string) []string {
				var bad []string
				if st, err := s.Stat(p); err == nil && st.Mode.Perm()&0o004 != 0 {
					bad = append(bad, fmt.Sprintf("mode %04o is readable by all users", st.Mode.Perm()))
				}
				for _, r := range roots {
					if strings.HasPrefix(p, r+"/") {
						bad = append(bad, "inside the web root "+r)
					}
				}
				return bad
			}, "Rails key or secrets file is exposed", "No Rails master.key or secrets.yml found")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-005", Title: "Rails Production Does Not Force HTTPS", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatWebApp, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
		Summary:   "Checks config/environments/production.rb for config.force_ssl = true.",
		Rationale: "force_ssl redirects plain HTTP to HTTPS, marks cookies Secure and sends Strict-Transport-Security. Without it a session cookie can travel over HTTP once and be read on the network, even when the site also works over HTTPS.",
		Detection: "Finds config/environments/production.rb in the project folders and fails when config.force_ssl is false or absent (comments removed). An assume_ssl-only setup still fails because cookies are not marked Secure.",
		Fix:       "Set config.force_ssl = true in config/environments/production.rb (and config.assume_ssl = true behind a TLS-terminating proxy), then restart the application.",
		Verify:    "grep -n force_ssl config/environments/production.rb  shows true, and curl -I http://<site>/ returns a 301 to https.",
		Refs:      []check.Ref{refRailsConfig, refRailsSecurity},
		Standards: check.Standards{CWE: []string{"CWE-319", "CWE-614"}, OWASP: []string{"A02:2021", "A05:2021"}, ASVS: []string{"9.1.1", "3.4.1"}, WSTG: []string{"WSTG-CRYP-03"}, NIST: []string{"SC-8", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			paths := collect.ProjectFiles(ctx, s, "config/environments/production.rb")
			forceOn := regexp.MustCompile(`(?m)^\s*config\.force_ssl\s*=\s*true\b`)
			rubyComment := regexp.MustCompile(`(?m)#[^\n]*`)
			return perFile(paths, func(p string) []string {
				r, err := sys.ReadFileNoFollow(ctx, s, p)
				if err != nil {
					return []string{unreadable}
				}
				if !forceOn.MatchString(rubyComment.ReplaceAllString(string(r.Data), "")) {
					return []string{"config.force_ssl is not true"}
				}
				return nil
			}, "Rails production does not force HTTPS", "No Rails production configuration found")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-006", Title: "Spring Boot Actuator Endpoints Fully Exposed", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks Spring Boot application properties for management.endpoints.web.exposure.include=* and probes the local site for an open /actuator/env.",
		Rationale: "Actuator's env, configprops, heapdump and threaddump endpoints print environment variables, configuration (including credentials) and process memory. Exposing them all over HTTP without authentication is one of the most common Java application leaks.",
		Detection: "Reads application.properties, application.yml and their -prod variants in the project folders for exposure.include set to * (or a list containing env, heapdump or configprops) with no management.server.port moving them off the public port. Also requests /actuator/env on each local site and fails on a JSON reply containing propertySources.",
		Fix:       "Set management.endpoints.web.exposure.include=health,info (and exclude env,heapdump,configprops), move management.server.port to a port that is not published, and require authentication for every actuator endpoint with Spring Security.",
		Verify:    "curl -s -o /dev/null -w '%{http_code}' https://<site>/actuator/env  prints 401, 403 or 404.",
		Refs:      []check.Ref{refSpringAct, {Title: "Spring Boot documentation, Securing HTTP endpoints", URL: "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html#actuator.endpoints.security"}, refWSTGConf02},
		Standards: check.Standards{CWE: []string{"CWE-200", "CWE-306"}, OWASP: []string{"A05:2021", "A01:2021"}, ASVS: []string{"14.3.2", "4.3.2"}, WSTG: []string{"WSTG-CONF-02", "WSTG-CONF-05"}, NIST: []string{"CM-7", "AC-3", "SI-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			paths := collect.ProjectFiles(ctx, s, "application.properties", "application.yml", "application.yaml",
				"application-prod.properties", "application-prod.yml", "config/application.properties", "config/application.yml")
			propAll := regexp.MustCompile(`(?m)^\s*management\.endpoints\.web\.exposure\.include\s*[=:]\s*["']?(\*|[^\n]*\b(env|heapdump|configprops)\b)`)
			yamlAll := regexp.MustCompile(`(?s)exposure:\s*\n\s*include:\s*["']?(\*|[^\n]*\b(env|heapdump|configprops)\b)`)
			mgmtPort := regexp.MustCompile(`(?m)^\s*management\.server\.port\s*[=:]|(?s)management:\s*\n(\s+.*\n)*?\s+server:\s*\n\s+port:`)
			out := perFile(paths, func(p string) []string {
				r, err := sys.ReadFileNoFollow(ctx, s, p)
				if err != nil {
					return []string{unreadable}
				}
				t := string(r.Data)
				if (propAll.MatchString(t) || yamlAll.MatchString(t)) && !mgmtPort.MatchString(t) {
					return []string{"management.endpoints.web.exposure.include exposes sensitive actuator endpoints on the application port"}
				}
				return nil
			}, "Spring Boot actuator endpoints are fully exposed", "No Spring Boot application properties found")
			var sites []check.Result
			for _, st := range Sites(ctx, s) {
				r, err := st.Get(ctx, s, "/actuator/env")
				if err == nil && r.Status == 200 && !HTML(r) && strings.Contains(r.Body, "propertySources") {
					sites = append(sites, check.FailR(st.Name, "/actuator/env answers without authentication"))
				}
			}
			if len(sites) > 0 {
				if len(out) == 1 && out[0].Status == check.Skip {
					return sites
				}
				return append(out, sites...)
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-007", Title: "Flask Debug Mode Enabled in Application Code", Domain: check.DomainWeb,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Looks for app.run(debug=True) or app.debug = True in Flask entry files. A heuristic; the service check WEB-PY-004 covers the environment switches.",
		Rationale: "Debug mode in code follows the application wherever it is deployed. If the file is ever run directly instead of through a WSGI server, the Werkzeug debugger and its code console come up for every visitor.",
		Detection: "Reads app.py, wsgi.py, run.py, main.py and server.py in the project folders (files that import flask) and flags debug=True inside app.run(...) or an app.debug = True assignment, ignoring commented lines. Rated Low because a production WSGI server ignores app.run().",
		Fix:       "Remove debug=True from app.run() and read it from the environment for local work only (app.run(debug=os.environ.get('FLASK_DEBUG') == '1')); serve production with Gunicorn or uWSGI, which never call app.run().",
		Verify:    "grep -n 'debug' app.py  shows no hard-coded True.",
		Refs:      []check.Ref{refFlaskDebug, {Title: "Flask documentation, Deploying to Production", URL: "https://flask.palletsprojects.com/en/stable/deploying/"}},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-215"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}, WSTG: []string{"WSTG-CONF-02"}, NIST: []string{"CM-6", "CM-7"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var paths []string
			texts := map[string]string{}
			flaskImport := regexp.MustCompile(`(?m)^\s*(from\s+flask\s+import|import\s+flask)`)
			for _, p := range collect.ProjectFiles(ctx, s, "app.py", "wsgi.py", "run.py", "main.py", "server.py") {
				r, err := sys.ReadFileNoFollow(ctx, s, p)
				if err != nil || !flaskImport.Match(r.Data) {
					continue
				}
				paths = append(paths, p)
				texts[p] = string(r.Data)
			}
			sort.Strings(paths)
			pyComment := regexp.MustCompile(`(?m)#[^\n]*`)
			runDebug := regexp.MustCompile(`\.run\s*\([^)]*\bdebug\s*=\s*True\b`)
			attrDebug := regexp.MustCompile(`(?m)^\s*\w+\.debug\s*=\s*True\b`)
			return perFile(paths, func(p string) []string {
				t := pyComment.ReplaceAllString(texts[p], "")
				var bad []string
				if runDebug.MatchString(t) {
					bad = append(bad, "app.run(debug=True)")
				}
				if attrDebug.MatchString(t) {
					bad = append(bad, "app.debug = True")
				}
				return bad
			}, "Flask debug mode is enabled in code", "No Flask entry files found")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-008", Title: "Dependency Lock Files Older Than a Year", Domain: check.DomainWeb,
		Severity: check.Info, Category: check.CatPatch, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		Summary:   "Reports composer.lock, package-lock.json, yarn.lock, Gemfile.lock and poetry.lock files not modified for 365 days or more (dependency freshness). Informational.",
		Rationale: "A lock file pins exact library versions. One untouched for a year means the application has had no dependency updates in that time, so every library vulnerability published since is still present. The check cannot tell whether a specific vulnerability applies; the known-vulnerability checks and composer audit or npm audit do that.",
		Detection: "Stats each lock file found in the project folders (metadata only) and reports those whose modification time is 365 days or older. Files whose time cannot be read are reported as incomplete.",
		Fix:       "Run composer update / npm update / bundle update / poetry update in a test environment, run the audit command of each ecosystem (composer audit, npm audit, bundle audit, pip-audit) and deploy. Schedule dependency updates at least quarterly.",
		Verify:    "stat -c '%y %n' composer.lock package-lock.json  shows a recent date.",
		Refs:      []check.Ref{refOWASPDepCheck, {Title: "OWASP Top 10 2021, A06 Vulnerable and Outdated Components", URL: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"}},
		Standards: check.Standards{CWE: []string{"CWE-1104", "CWE-1395"}, OWASP: []string{"A06:2021"}, ASVS: []string{"14.2.1"}, NIST: []string{"SI-2", "SA-22"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			paths := collect.ProjectFiles(ctx, s, "composer.lock", "package-lock.json", "yarn.lock", "Gemfile.lock", "poetry.lock")
			if len(paths) == 0 {
				return []check.Result{check.SkipR("projects", "No dependency lock files found in the project folders")}
			}
			cutoff := time.Now().Add(-365 * 24 * time.Hour)
			var out []check.Result
			for _, p := range paths {
				st, err := s.Stat(p)
				if err != nil || st.ModTime.IsZero() {
					out = append(out, check.IncompleteR(p, "Modification time could not be read"))
					continue
				}
				days := int(time.Since(st.ModTime).Hours() / 24)
				if st.ModTime.Before(cutoff) {
					out = append(out, check.FailR(p, fmt.Sprintf("Lock file last changed %d days ago", days)))
				} else {
					out = append(out, check.PassR(p, fmt.Sprintf("Lock file changed %d days ago", days)))
				}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-009", Title: "Git Repository Stored Inside a Web Root", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Looks on disk for a .git folder directly inside each web document root.",
		Rationale: "A .git folder in the document root is one web server rule away from being downloadable, which rebuilds the full source and its history, often with committed credentials. WEB-EXP-001 tests whether it is already reachable; this check finds it before a configuration change exposes it.",
		Detection: "Stats <docroot>/.git/HEAD for each local document root (metadata only). Fails when it exists, even if the web server currently blocks dot-folders.",
		Fix:       "Deploy from a build step that copies only the needed files (git archive, rsync --exclude .git, or a CI artefact), or point the document root at a public/ sub-folder as Laravel, Symfony and Rails expect. Remove the .git folder from the web root and rotate any secret ever committed.",
		Verify:    "ls -d <docroot>/.git  prints nothing.",
		Refs:      []check.Ref{{Title: "OWASP WSTG-CONF-04, Review Old Backup and Unreferenced Files", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/"}, refSecretsCS},
		Standards: check.Standards{CWE: []string{"CWE-527", "CWE-538"}, OWASP: []string{"A05:2021"}, ASVS: []string{"12.5.1"}, WSTG: []string{"WSTG-CONF-04"}, NIST: []string{"CM-7", "SC-28"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			roots := collect.DocRoots(ctx, s)
			if len(roots) == 0 {
				return []check.Result{check.SkipR("web roots", "No document roots found in the local web server configuration")}
			}
			var out []check.Result
			for _, root := range roots {
				if _, err := s.Stat(root + "/.git/HEAD"); err == nil {
					out = append(out, check.FailR(root, "A .git repository is stored inside the web root", root+"/.git"))
				} else {
					out = append(out, check.PassR(root, "No .git folder in the web root"))
				}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "WEB-APP-010", Title: "Framework Writable Folders Open to All Users", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L",
		Summary:   "Checks Laravel and Symfony cache, log and storage folders for world-write permission.",
		Rationale: "chmod -R 777 storage is a common fix for permission errors. Laravel's bootstrap/cache and Symfony's var/cache hold compiled PHP that the framework includes on every request, so any local user who can write there runs code as the web server. Logs and sessions in storage are readable and forgeable too.",
		Detection: "For each Laravel (.env with APP_KEY) or Symfony (.env with APP_SECRET) project, stats storage, storage/logs, storage/framework, bootstrap/cache, var/cache and var/log next to the .env file (metadata only) and fails when any has the 'other write' bit set.",
		Fix:       "chmod -R o-w storage bootstrap/cache var  and give the web server group write access instead: chgrp -R www-data storage bootstrap/cache && chmod -R g+w storage bootstrap/cache.",
		Verify:    "find storage bootstrap/cache var -perm -0002 -type d  prints nothing.",
		Refs:      []check.Ref{refLaravelDeploy, {Title: "Symfony documentation, Setting up or Fixing File Permissions", URL: "https://symfony.com/doc/current/setup/file_permissions.html"}, {Title: "OWASP WSTG-CONF-09, Test File Permission", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission/"}},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-94"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.1.3"}, WSTG: []string{"WSTG-CONF-09"}, NIST: []string{"AC-3", "AC-6", "CM-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files := envFiles(ctx, s, "APP_KEY", "APP_SECRET")
			var paths []string
			for _, f := range files {
				paths = append(paths, f.path)
			}
			return perFile(paths, func(p string) []string {
				dir := filepath.Dir(p)
				var bad []string
				for _, sub := range []string{"storage", "storage/logs", "storage/framework", "bootstrap/cache", "var/cache", "var/log"} {
					if st, err := s.Stat(dir + "/" + sub); err == nil && st.Mode.Perm()&0o002 != 0 {
						bad = append(bad, fmt.Sprintf("%04o %s", st.Mode.Perm(), dir+"/"+sub))
					}
				}
				return bad
			}, "Framework cache or storage folders are world-writable", "No Laravel or Symfony projects found")
		},
	})
}
