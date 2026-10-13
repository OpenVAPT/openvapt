package web

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Node.js and Python application checks. They read systemd service units
// (how the application is started), the Node.js version, and Django settings
// files. Settings files can hold secrets, so only file paths and setting
// names are reported, never values.

// nodeEOL is the end-of-life date of each Node.js major release, from the
// Node.js release schedule (https://github.com/nodejs/Release). Odd majors
// are short-lived "current" releases.
var nodeEOL = map[int]string{
	12: "2022-04-30", 14: "2023-04-30", 16: "2023-09-11", 17: "2022-06-01", 18: "2025-04-30", 19: "2023-06-01",
	20: "2026-04-30", 21: "2024-06-01", 22: "2027-04-30", 23: "2025-06-01", 24: "2028-04-30", 25: "2026-06-01",
	26: "2029-04-30",
}

var nodeVersion = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// unitCommand joins a unit's ExecStart= lines and Environment= values so
// that command-line flags and environment switches can be searched together.
func unitCommand(u collect.Unit) string {
	return strings.Join(u.All("service.execstart"), " ") + " " + strings.Join(u.All("service.environment"), " ")
}

var nodeRunner = regexp.MustCompile(`(^|[/\s])(node|nodejs|npm|npx|yarn|pnpm|pm2-runtime|pm2)(\s|$)`)

func runsNode(u collect.Unit) bool { return nodeRunner.MatchString(u.Get("service.execstart")) }

// unitResults runs fn over long-running service units, or skips if fn
// selects none.
func unitResults(ctx context.Context, s sys.System, applies func(collect.Unit) bool, judge func(collect.Unit) string, okMsg, failMsg string) []check.Result {
	var n int
	var bad []string
	for _, u := range collect.Units(ctx, s) {
		if !u.LongRunning() || !applies(u) {
			continue
		}
		n++
		if why := judge(u); why != "" {
			bad = append(bad, u.Name+": "+why)
		}
	}
	if n == 0 {
		return []check.Result{check.SkipR("systemd units", "No matching application services were found")}
	}
	if len(bad) > 0 {
		return []check.Result{check.FailR("systemd units", failMsg, bad...)}
	}
	return []check.Result{check.PassR("systemd units", okMsg)}
}

// --inspect-port only sets a port; it does not start the inspector.
var inspectFlag = regexp.MustCompile(`--inspect(-brk|-wait)?(=(\S+))?(\s|$)`)
var pyDevServer = regexp.MustCompile(`manage\.py\s+runserver|\bflask\s+run\b|-m\s+(http\.server|SimpleHTTPServer)\b|\buvicorn\b.*--reload|\bstreamlit\s+run\b`)
var flaskDebug = regexp.MustCompile(`(?i)\bFLASK_DEBUG=(1|true|yes|on)\b|\bFLASK_ENV=development\b|\bflask\b.*\s--debug\b|\bWERKZEUG_DEBUG_PIN=off\b`)

// django settings patterns; DEBUG/ALLOWED_HOSTS/SECRET_KEY assignments at
// the start of a line, as Django's own generated settings write them.
var (
	djDebugOn   = regexp.MustCompile(`(?m)^\s*DEBUG\s*=\s*True\b`)
	djDebugSafe = regexp.MustCompile(`^(False\b|os\.|env|config\(|bool\()`)
	djDebugAny  = regexp.MustCompile(`(?m)^\s*DEBUG\s*=\s*(.*)$`)
	djHostsAny  = regexp.MustCompile(`(?m)^\s*ALLOWED_HOSTS\s*=\s*[\[(]\s*['"]\*['"]`)
	djInsecure  = regexp.MustCompile(`(?m)^\s*SECRET_KEY\s*=\s*['"]django-insecure-`)
	djMarker    = regexp.MustCompile(`INSTALLED_APPS|ROOT_URLCONF|DJANGO_SETTINGS_MODULE|django`)
)

type djangoFile struct{ path, text string }

// djangoSettings returns Django settings files grouped by folder.
func djangoSettings(ctx context.Context, s sys.System) map[string][]djangoFile {
	out := map[string][]djangoFile{}
	for _, p := range collect.ProjectFiles(ctx, s, "settings.py", "settings/*.py") {
		// Project folders are writable by site users, who could replace
		// settings.py with a link to /etc/shadow, so links are refused.
		r, err := sys.ReadFileNoFollow(ctx, s, p)
		if err != nil || !djMarker.Match(r.Data) && !djDebugOn.Match(r.Data) {
			continue
		}
		dir := filepath.Dir(p)
		out[dir] = append(out[dir], djangoFile{p, string(r.Data)})
	}
	return out
}

func djangoCheck(ctx context.Context, s sys.System, judge func(dir []djangoFile) []string, failMsg string) []check.Result {
	dirs := djangoSettings(ctx, s)
	if len(dirs) == 0 {
		return []check.Result{check.SkipR("django", "No Django settings files found")}
	}
	keys := make([]string, 0, len(dirs))
	for k := range dirs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []check.Result
	for _, k := range keys {
		if bad := judge(dirs[k]); len(bad) > 0 {
			out = append(out, check.FailR(k, failMsg, bad...))
		} else {
			out = append(out, check.PassR(k, "No issue found"))
		}
	}
	return out
}

func matching(fs []djangoFile, re *regexp.Regexp, what string) []string {
	var out []string
	for _, f := range fs {
		if re.MatchString(f.text) {
			out = append(out, f.path+": "+what)
		}
	}
	return out
}

var refDjangoDeploy = check.Ref{Title: "Django documentation, Deployment checklist", URL: "https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/"}
var refNodeSec = check.Ref{Title: "OWASP Node.js Security Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html"}

func init() {
	check.Register(&check.Check{
		ID: "WEB-NODE-001", Title: "Node.js Version Past End of Life", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatPatch, Effort: check.EffortHigh,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether the installed Node.js runtime is a release line that no longer receives security fixes.",
		Rationale: "After end of life the Node.js project publishes no more security releases, so every later vulnerability in the runtime, its bundled OpenSSL or its HTTP parser stays open for good.",
		Detection: "Runs node --version (or nodejs --version), a read-only command, and compares the major version with the Node.js release schedule's end-of-life dates.",
		Fix:       "Move to an Active or Maintenance LTS release (even-numbered majors), for example with the NodeSource or distribution packages, test the application, then restart its service.",
		Verify:    "node --version  shows a supported LTS major.",
		Refs:      []check.Ref{{Title: "Node.js Release Working Group, release schedule", URL: "https://github.com/nodejs/Release"}, {Title: "endoflife.date, Node.js (community-maintained lifecycle data)", URL: "https://endoflife.date/nodejs"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2", "SA-22"}, CISTopic: "Use supported software"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			out, err := s.Run(ctx, "node", "--version")
			if err != nil {
				out, err = s.Run(ctx, "nodejs", "--version")
			}
			if err != nil {
				return []check.Result{check.SkipR("node", "Node.js is not installed")}
			}
			m := nodeVersion.FindStringSubmatch(out)
			if m == nil {
				return []check.Result{check.IncompleteR("node", "Could not read the Node.js version")}
			}
			major, _ := strconv.Atoi(m[1])
			eol, ok := nodeEOL[major]
			if !ok {
				if major < 12 {
					return []check.Result{check.FailR("node", "Node.js "+m[0]+" is long past end of life")}
				}
				return []check.Result{check.PassR("node", "Node.js "+m[0]+" is newer than the built-in schedule")}
			}
			if eol <= time.Now().UTC().Format("2006-01-02") {
				return []check.Result{check.FailR("node", fmt.Sprintf("Node.js %s reached end of life on %s", m[0], eol))}
			}
			return []check.Result{check.PassR("node", fmt.Sprintf("Node.js %s is supported until %s", m[0], eol))}
		},
	})

	check.Register(&check.Check{
		ID: "WEB-NODE-002", Title: "Node.js Debugger (Inspector) Enabled in a Service", Domain: check.DomainWeb,
		Severity: check.Critical, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether a Node.js service is started with --inspect, which opens the V8 debugger.",
		Rationale: "The inspector has no authentication: anyone who can connect to it can run any JavaScript inside the application, as the service's user. Bound to 0.0.0.0 that is remote code execution; even on 127.0.0.1 any local user or server-side request forgery bug can reach it.",
		Detection: "Reads ExecStart= and Environment= (including NODE_OPTIONS) of long-running services that run node, npm, yarn, pnpm or pm2, and flags --inspect, --inspect-brk and --inspect-wait. A network-reachable listener on port 9229 is also reported by NET-APP-001.",
		Fix:       "Remove --inspect from the service and from NODE_OPTIONS, run systemctl daemon-reload and restart. Debug on a development machine, or temporarily over an SSH tunnel to 127.0.0.1:9229.",
		Verify:    "systemctl show -p ExecStart,Environment <unit> | grep -c inspect  prints 0, and nothing listens on 9229.",
		Refs:      []check.Ref{{Title: "Node.js documentation, Debugging guide (security implications)", URL: "https://nodejs.org/learn/getting-started/debugging"}, refNodeSec},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-306"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-7", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return unitResults(ctx, s, runsNode, func(u collect.Unit) string {
				m := inspectFlag.FindStringSubmatch(unitCommand(u))
				if m == nil {
					return ""
				}
				if m[3] != "" && !strings.HasPrefix(m[3], "127.") && !strings.HasPrefix(m[3], "localhost") && strings.Contains(m[3], ":") {
					return "starts the inspector on a network address (" + m[0] + ")"
				}
				return "starts the inspector (" + m[0] + ")"
			}, "No Node.js service starts the inspector", "Node.js services start the debugger")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-NODE-003", Title: "Node.js Service Not Running in Production Mode", Domain: check.DomainWeb,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks whether Node.js services set NODE_ENV=production.",
		Rationale: "Express and many other frameworks treat a missing NODE_ENV as development: error pages then include stack traces with file paths, and caching and other production safeguards are off.",
		Detection: "For long-running services whose ExecStart= runs node, npm, yarn, pnpm or pm2, reads Environment= and fails when NODE_ENV is missing or not production. Variables loaded with EnvironmentFile= are read only for NODE_ENV.",
		Fix:       "Add Environment=NODE_ENV=production to the [Service] section (systemctl edit <unit>), run systemctl daemon-reload and restart the service.",
		Verify:    "systemctl show -p Environment <unit>  includes NODE_ENV=production.",
		Refs:      []check.Ref{{Title: "Express documentation, Production best practices: performance and reliability", URL: "https://expressjs.com/en/advanced/best-practice-performance/"}, refNodeSec},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-209"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return unitResults(ctx, s, runsNode, func(u collect.Unit) string {
				env := u.Env()
				v, ok := env["NODE_ENV"]
				if !ok {
					v, ok = envFileValue(ctx, s, u, "NODE_ENV")
				}
				switch {
				case !ok:
					return "NODE_ENV is not set"
				case v != "production":
					return "NODE_ENV=" + v
				}
				return ""
			}, "Node.js services run with NODE_ENV=production", "Node.js services are not in production mode")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-PY-001", Title: "Django Debug Mode Enabled", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks Django settings files for DEBUG = True with no production override.",
		Rationale: "With DEBUG on, every error page shows source code, local variables, SQL queries and most settings, and Django keeps every SQL query in memory. Attackers trigger errors on purpose to read them.",
		Detection: "Finds settings.py and settings/*.py files that look like Django settings in /srv, /opt, /var/www, home directories and web roots (three folders deep), and fails when a folder sets DEBUG = True and no file in the same folder sets DEBUG = False or reads it from the environment.",
		Fix:       "Set DEBUG = False in production, preferably from the environment (DEBUG = os.environ.get('DJANGO_DEBUG') == '1'), set ALLOWED_HOSTS, and restart the application. Run python manage.py check --deploy.",
		Verify:    "python manage.py check --deploy  reports no DEBUG warning.",
		Refs:      []check.Ref{refDjangoDeploy, {Title: "Django settings reference, DEBUG", URL: "https://docs.djangoproject.com/en/6.1/ref/settings/#debug"}},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-215"}, OWASP: []string{"A05:2021"}, ASVS: []string{"14.3.2"}, WSTG: []string{"WSTG-ERRH-01"}, NIST: []string{"CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return djangoCheck(ctx, s, func(fs []djangoFile) []string {
				// Python keeps the last assignment in a file. A folder is safe
				// when some file's final DEBUG is False or read from the
				// environment (a production module overriding a base one).
				var on []string
				for _, f := range fs {
					all := djDebugAny.FindAllStringSubmatch(f.text, -1)
					if len(all) == 0 {
						continue
					}
					last := strings.TrimSpace(all[len(all)-1][1])
					if djDebugSafe.MatchString(last) {
						return nil
					}
					if strings.HasPrefix(last, "True") {
						on = append(on, f.path+": DEBUG = True")
					}
				}
				return on
			}, "Django debug mode is on")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-PY-002", Title: "Django Accepts Any Host Header", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatWebApp, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
		Summary:   "Checks Django settings for ALLOWED_HOSTS = ['*'].",
		Rationale: "ALLOWED_HOSTS protects against Host header attacks. With a wildcard, an attacker can make Django build password-reset and other absolute links that point at the attacker's domain, and can poison shared caches.",
		Detection: "Reads the same Django settings files as WEB-PY-001 and flags an ALLOWED_HOSTS list or tuple that starts with '*'.",
		Fix:       "List the real domain names: ALLOWED_HOSTS = ['example.com', 'www.example.com'], and restart the application.",
		Verify:    "python manage.py check --deploy",
		Refs:      []check.Ref{refDjangoDeploy, {Title: "Django settings reference, ALLOWED_HOSTS", URL: "https://docs.djangoproject.com/en/6.1/ref/settings/#allowed-hosts"}},
		Standards: check.Standards{CWE: []string{"CWE-20"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-INPV-17"}, NIST: []string{"CM-6", "SI-10"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return djangoCheck(ctx, s, func(fs []djangoFile) []string { return matching(fs, djHostsAny, "ALLOWED_HOSTS allows any host") }, "Django accepts any Host header")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-PY-003", Title: "Django Uses the Generated Development Secret Key", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatCrypto, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks Django settings for a SECRET_KEY that starts with django-insecure-, the marker of the key generated by startproject.",
		Rationale: "SECRET_KEY signs sessions, password-reset tokens and other data. The generated key sits in source files that are usually copied into repositories and backups; anyone who has it can forge signed data and, with some session backends, take over accounts.",
		Detection: "Reads the same Django settings files as WEB-PY-001 and flags SECRET_KEY = 'django-insecure-...'. The key itself is never copied into the report.",
		Fix:       "Generate a new key (python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'), load it from the environment or a root-readable file (SECRET_KEY = os.environ['DJANGO_SECRET_KEY']), and restart. Changing the key logs all users out.",
		Verify:    "python manage.py check --deploy  reports no SECRET_KEY warning.",
		Refs:      []check.Ref{refDjangoDeploy, {Title: "Django settings reference, SECRET_KEY", URL: "https://docs.djangoproject.com/en/6.1/ref/settings/#secret-key"}},
		Standards: check.Standards{CWE: []string{"CWE-798", "CWE-321"}, OWASP: []string{"A02:2021", "A05:2021"}, ASVS: []string{"2.10.4"}, NIST: []string{"IA-5", "SC-12"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return djangoCheck(ctx, s, func(fs []djangoFile) []string {
				return matching(fs, djInsecure, "uses the generated django-insecure SECRET_KEY")
			}, "Django uses the generated development SECRET_KEY")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-PY-004", Title: "Python Interactive Debugger Enabled in a Service", Domain: check.DomainWeb,
		Severity: check.Critical, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether a service runs Flask or Werkzeug with the interactive debugger enabled.",
		Rationale: "The Werkzeug debugger lets a visitor run Python code from an error page. Its PIN has been bypassed and brute-forced in practice, and with WERKZEUG_DEBUG_PIN=off there is no protection at all: this is remote code execution.",
		Detection: "Reads ExecStart= and Environment= of long-running services and flags FLASK_DEBUG=1, FLASK_ENV=development, flask run --debug and WERKZEUG_DEBUG_PIN=off.",
		Fix:       "Remove the debug switches, run the application under a production WSGI server (Gunicorn, uWSGI or mod_wsgi) behind nginx or Apache, run systemctl daemon-reload and restart the service.",
		Verify:    "systemctl show -p ExecStart,Environment <unit>  shows no debug switches.",
		Refs:      []check.Ref{{Title: "Werkzeug documentation, Debugging Applications", URL: "https://werkzeug.palletsprojects.com/en/stable/debug/"}, {Title: "Flask documentation, Debug mode", URL: "https://flask.palletsprojects.com/en/stable/quickstart/#debug-mode"}},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-94"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-7", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return unitResults(ctx, s, func(collect.Unit) bool { return true }, func(u collect.Unit) string {
				if m := flaskDebug.FindString(unitCommand(u)); m != "" {
					return "enables the debugger (" + m + ")"
				}
				return ""
			}, "No service enables the Flask or Werkzeug debugger", "Services enable the Python interactive debugger")
		},
	})

	check.Register(&check.Check{
		ID: "WEB-PY-005", Title: "Python Development Server Used in a Service", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
		Summary:   "Checks whether a service runs a development web server such as manage.py runserver, flask run or python -m http.server.",
		Rationale: "Development servers are documented as unsuitable for production: they have not been security-audited, handle load and slow clients poorly and often run with debugging features. python -m http.server publishes a whole folder.",
		Detection: "Reads ExecStart= of long-running services and flags manage.py runserver, flask run, python -m http.server or SimpleHTTPServer, uvicorn --reload and streamlit run.",
		Fix:       "Serve the application with a production server (Gunicorn or uWSGI for WSGI, Uvicorn without --reload or Hypercorn for ASGI) bound to 127.0.0.1, behind nginx or Apache. Serve static files from the web server.",
		Verify:    "systemctl show -p ExecStart <unit>  shows a production server.",
		Refs:      []check.Ref{{Title: "Django documentation, django-admin runserver (not for production)", URL: "https://docs.djangoproject.com/en/6.1/ref/django-admin/#runserver"}, {Title: "Flask documentation, Deploying to Production", URL: "https://flask.palletsprojects.com/en/stable/deploying/"}},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-1188"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-7"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return unitResults(ctx, s, func(collect.Unit) bool { return true }, func(u collect.Unit) string {
				if m := pyDevServer.FindString(u.Get("service.execstart")); m != "" {
					return "runs a development server (" + m + ")"
				}
				return ""
			}, "No service runs a Python development server", "Services run Python development servers")
		},
	})
}

// envFileValue reads one variable from a unit's EnvironmentFile= files. The
// files may hold secrets, so only the requested variable is extracted.
func envFileValue(ctx context.Context, s sys.System, u collect.Unit, name string) (string, bool) {
	for _, p := range u.All("service.environmentfile") {
		p = strings.TrimPrefix(strings.TrimSpace(p), "-")
		if !strings.HasPrefix(p, "/") {
			continue
		}
		r, err := s.ReadFile(ctx, p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(r.Data), "\n") {
			k, v, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "export "), "=")
			if ok && strings.TrimSpace(k) == name {
				return strings.Trim(strings.TrimSpace(v), `"'`), true
			}
		}
	}
	return "", false
}
