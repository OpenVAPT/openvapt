package host

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Checks on systemd service units: who services run as, how well they are
// sandboxed, whether their unit files and programs can be changed by other
// users, and whether secrets are written into them. Only unit files are
// read; no systemctl or systemd-analyze command is run.

var refSystemdExec = check.Ref{Title: "systemd.exec(5), execution environment configuration", URL: "https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html"}
var refSystemdUnit = check.Ref{Title: "systemd.unit(5), unit configuration", URL: "https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html"}

// unitsOrSkip returns the service units, or a Skip result when there are none.
func unitsOrSkip(ctx context.Context, s sys.System, filter func(collect.Unit) bool) ([]collect.Unit, []check.Result) {
	var out []collect.Unit
	for _, u := range collect.Units(ctx, s) {
		if filter(u) {
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, []check.Result{check.SkipR("systemd units", "No matching systemd service units were found")}
	}
	return out, nil
}

func customLongRunning(u collect.Unit) bool { return u.Custom && u.LongRunning() }

// sandbox lists the settings HOST-SYSD-002 expects and how to judge each.
var sandbox = []struct {
	key  string
	ok   func(string) bool
	hint string
}{
	{"service.nonewprivileges", collect.Truthy, "NoNewPrivileges=yes"},
	{"service.protectsystem", func(v string) bool { v = strings.ToLower(v); return v == "strict" || v == "full" || collect.Truthy(v) }, "ProtectSystem=strict"},
	{"service.privatetmp", collect.Truthy, "PrivateTmp=yes"},
	{"service.protecthome", func(v string) bool {
		v = strings.ToLower(v)
		return v == "read-only" || v == "tmpfs" || collect.Truthy(v)
	}, "ProtectHome=yes"},
}

// secretVar matches environment variable names that usually hold secrets.
var secretVar = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)`)

// unsafeDirs hold files any local user can create or replace.
var unsafeDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

func init() {
	check.Register(&check.Check{
		ID: "HOST-SYSD-001", Title: "Custom Services Run as Root", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks whether long-running services written by the administrator run as root instead of a dedicated user.",
		Rationale: "Application services (Node.js, Python, Java, custom daemons) are the code most exposed to attackers. If one runs as root, any bug in it gives the attacker full control of the machine instead of one unprivileged account.",
		Detection: "Reads every service unit in /etc/systemd/system (symlinks skipped) together with its drop-in files, keeps units that start a long-running process (Type is not oneshot), and flags those with no User= (or User=root) and no DynamicUser=yes.",
		Fix:       "Create a dedicated account (useradd --system --no-create-home --shell /usr/sbin/nologin <app>), give it ownership of only the folders the app writes to, then add User=<app> and Group=<app> to the [Service] section (or DynamicUser=yes). Run systemctl daemon-reload and restart the service. Ports below 1024 can be allowed with AmbientCapabilities=CAP_NET_BIND_SERVICE instead of root.",
		Verify:    "systemctl show -p User,DynamicUser <unit>  and  ps -o user= -p $(systemctl show -p MainPID --value <unit>)",
		Refs:      []check.Ref{refSystemdExec, {Title: "NIST SP 800-123, Guide to General Server Security (least privilege for services)", URL: "https://csrc.nist.gov/pubs/sp/800/123/final"}},
		Standards: check.Standards{CWE: []string{"CWE-250"}, NIST: []string{"AC-6", "CM-7"}, CISTopic: "Run services with least privilege"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			units, skip := unitsOrSkip(ctx, s, customLongRunning)
			if skip != nil {
				return skip
			}
			var bad []string
			for _, u := range units {
				if u.RunsAsRoot() {
					bad = append(bad, u.Name+": no User= or DynamicUser=, runs as root ("+u.Path+")")
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("systemd units", fmt.Sprintf("%d custom service(s) run as root", len(bad)), bad...)}
			}
			return []check.Result{check.PassR("systemd units", fmt.Sprintf("All %d custom long-running services run as a non-root user", len(units)))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SYSD-002", Title: "Custom Services Lack Sandboxing", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks whether custom long-running services use systemd's basic sandboxing options.",
		Rationale: "systemd can confine a service with a few lines: block privilege gain through setuid programs, mount the operating system read-only, give it a private /tmp and hide home directories. These limit what an attacker can do after exploiting the service, at almost no cost.",
		Detection: "For each long-running service unit in /etc/systemd/system, merges drop-ins and checks for NoNewPrivileges=yes, ProtectSystem=strict (or full/yes), PrivateTmp=yes and ProtectHome=yes (or read-only/tmpfs). Lists the missing settings per unit.",
		Fix:       "Add the missing lines with systemctl edit <unit> (a drop-in), for example NoNewPrivileges=yes, ProtectSystem=strict, ReadWritePaths=/var/lib/<app>, PrivateTmp=yes, ProtectHome=yes. Restart the service and test it; add ReadWritePaths= for every folder the app must write. systemd-analyze security <unit> suggests further options.",
		Verify:    "systemd-analyze security <unit>  shows a lower exposure score, and the service still works.",
		Refs:      []check.Ref{refSystemdExec, {Title: "systemd-analyze(1), security verb", URL: "https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html"}},
		Standards: check.Standards{CWE: []string{"CWE-250", "CWE-653"}, NIST: []string{"CM-6", "SC-39", "AC-6"}, CISTopic: "Service isolation"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			units, skip := unitsOrSkip(ctx, s, customLongRunning)
			if skip != nil {
				return skip
			}
			var bad []string
			for _, u := range units {
				var missing []string
				for _, sb := range sandbox {
					if !sb.ok(u.Get(sb.key)) {
						missing = append(missing, sb.hint)
					}
				}
				if len(missing) > 0 {
					bad = append(bad, u.Name+" is missing: "+strings.Join(missing, ", "))
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("systemd units", fmt.Sprintf("%d custom service(s) lack basic sandboxing", len(bad)), bad...)}
			}
			return []check.Result{check.PassR("systemd units", "Custom services use the basic sandboxing options")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SYSD-003", Title: "Service Unit Files Writable by Non-Root Users", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether any systemd service unit or drop-in file can be changed by a user other than root.",
		Rationale: "systemd starts services as root by default. Whoever can edit a unit file can change ExecStart= or User= and have their own program run as root at the next restart or reboot, a well-known privilege escalation and persistence technique.",
		Detection: "Reads the metadata of every service unit and drop-in in /etc/systemd/system, /lib/systemd/system and /usr/lib/systemd/system (symlinks skipped) and flags files that are group- or world-writable or not owned by root.",
		Fix:       "chown root:root <file> && chmod 644 <file> for each listed file, then review its contents for changes you did not make (ExecStart=, User=, ExecStartPre=) and run systemctl daemon-reload.",
		Verify:    "stat -c '%U %a %n' /etc/systemd/system/*.service  shows root and 644 (or stricter).",
		Refs:      []check.Ref{refSystemdUnit, {Title: "MITRE ATT&CK T1543.002, Create or Modify System Process: Systemd Service", URL: "https://attack.mitre.org/techniques/T1543/002/"}},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-3", "CM-5"}, CISTopic: "Protect service definitions"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			units, skip := unitsOrSkip(ctx, s, func(collect.Unit) bool { return true })
			if skip != nil {
				return skip
			}
			var bad []string
			for _, u := range units {
				for _, p := range append([]string{u.Path}, u.DropIns...) {
					st, err := s.Stat(p)
					if err != nil {
						continue
					}
					if st.Mode.Perm()&0o022 != 0 || st.UID != 0 {
						bad = append(bad, fmt.Sprintf("%s mode %04o uid %d", p, st.Mode.Perm(), st.UID))
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("systemd units", "Service unit files can be changed by non-root users", bad...)}
			}
			return []check.Result{check.PassR("systemd units", fmt.Sprintf("All %d service units are owned by root and not writable by others", len(units)))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SYSD-004", Title: "Service Programs in Writable Locations", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether a service starts a program from a temporary folder, or a program file that other users can replace.",
		Rationale: "If the program a root service starts lives in /tmp or is writable by other users, any local user (or a compromised web application) can replace it and gain root the next time the service restarts.",
		Detection: "Takes the program path of each long-running service's ExecStart= line and flags paths under /tmp, /var/tmp or /dev/shm, program files that are world-writable, and, for services running as root, program files not owned by root.",
		Fix:       "Install the program in a root-owned location (/usr/local/bin or /opt/<app>), chown root:root and chmod 755 it, point ExecStart= at it, then systemctl daemon-reload and restart the service.",
		Verify:    "stat -c '%U %a %n' $(systemctl show -p ExecStart --value <unit> | awk '{print $2}' | sed 's/path=//;s/;//')",
		Refs:      []check.Ref{refSystemdExec, {Title: "MITRE ATT&CK T1574.010, Hijack Execution Flow: Services File Permissions Weakness", URL: "https://attack.mitre.org/techniques/T1574/010/"}},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-427"}, NIST: []string{"AC-3", "CM-5"}, CISTopic: "Protect service executables"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			units, skip := unitsOrSkip(ctx, s, collect.Unit.LongRunning)
			if skip != nil {
				return skip
			}
			var bad []string
			for _, u := range units {
				prog := u.Program()
				if !strings.HasPrefix(prog, "/") {
					continue
				}
				unsafe := false
				for _, d := range unsafeDirs {
					if strings.HasPrefix(prog, d) {
						bad = append(bad, u.Name+": starts "+prog+" from a temporary folder")
						unsafe = true
						break
					}
				}
				if unsafe {
					continue
				}
				st, err := s.Stat(prog)
				if err != nil {
					continue
				}
				switch {
				case st.Mode.Perm()&0o002 != 0:
					bad = append(bad, fmt.Sprintf("%s: %s is world-writable (mode %04o)", u.Name, prog, st.Mode.Perm()))
				case u.RunsAsRoot() && st.UID != 0:
					bad = append(bad, fmt.Sprintf("%s: runs as root but %s is owned by uid %d", u.Name, prog, st.UID))
				}
			}
			sort.Strings(bad)
			if len(bad) > 0 {
				return []check.Result{check.FailR("systemd units", "Services start programs that other users can replace", bad...)}
			}
			return []check.Result{check.PassR("systemd units", "Service programs are in protected locations")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SYSD-005", Title: "Secrets Written Into Service Unit Files", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks whether passwords, tokens or keys are set with Environment= in systemd unit files.",
		Rationale: "Unit files are normally readable by every user, and systemctl show prints a service's Environment= values to any local user. A database password or API token placed there is effectively public on the machine.",
		Detection: "Reads Environment= lines of every service unit and its drop-ins and flags variables whose names suggest a secret (PASSWORD, SECRET, TOKEN, API_KEY, PRIVATE_KEY, CREDENTIAL, AUTH). Only the variable names are reported; values are never copied.",
		Fix:       "Move secrets to a root-owned file readable only by root (chmod 600) and load it with EnvironmentFile=, or better use LoadCredential=/SetCredentialEncrypted= so the secret is only visible to the service. Then rotate every secret that was exposed.",
		Verify:    "systemctl show -p Environment <unit>  should show no secret values.",
		Refs:      []check.Ref{refSystemdExec, {Title: "systemd, System and Service Credentials", URL: "https://systemd.io/CREDENTIALS/"}},
		Standards: check.Standards{CWE: []string{"CWE-526", "CWE-312"}, OWASP: []string{"A05:2021"}, NIST: []string{"IA-5", "SC-28"}, CISTopic: "Protect stored credentials"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			units, skip := unitsOrSkip(ctx, s, func(collect.Unit) bool { return true })
			if skip != nil {
				return skip
			}
			var bad []string
			for _, u := range units {
				var names []string
				for k := range u.Env() {
					if secretVar.MatchString(k) {
						names = append(names, k)
					}
				}
				sort.Strings(names)
				if len(names) > 0 {
					bad = append(bad, u.Name+" (values not shown): Environment= sets "+strings.Join(names, ", "))
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("systemd units", "Service unit files store secrets", bad...)}
			}
			return []check.Result{check.PassR("systemd units", "No Environment= setting names look like secrets")}
		},
	})
}
