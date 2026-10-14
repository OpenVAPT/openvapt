package host

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Cross-cutting hygiene checks: secrets lying in world-readable files, SSH
// authorized_keys options, cron jobs that run writable programs, PATH
// hijacking for root's cron, group and account file consistency and home
// directory permissions. Every file read here may contain secrets, so the
// report only ever names the file and the kind of pattern that matched; the
// engine redacts evidence again before it is written.

var (
	refNISTIA5       = check.Ref{Title: "NIST SP 800-53 Rev. 5, IA-5 Authenticator Management", URL: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"}
	refSecretsCheat  = check.Ref{Title: "OWASP Secrets Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}
	refSSHDAuthKeys  = check.Ref{Title: "sshd(8), AUTHORIZED_KEYS FILE FORMAT, OpenBSD manual pages", URL: "https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT"}
	refCrontab5      = check.Ref{Title: "crontab(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/crontab.5.html"}
	refAttackCron    = check.Ref{Title: "MITRE ATT&CK T1053.003, Scheduled Task/Job: Cron", URL: "https://attack.mitre.org/techniques/T1053/003/"}
	refAttackPath    = check.Ref{Title: "MITRE ATT&CK T1574.007, Hijack Execution Flow: Path Interception by PATH Environment Variable", URL: "https://attack.mitre.org/techniques/T1574/007/"}
	refGroup5        = check.Ref{Title: "group(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/group.5.html"}
	refPasswd5       = check.Ref{Title: "passwd(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/passwd.5.html"}
	refShadow5       = check.Ref{Title: "shadow(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/shadow.5.html"}
	refNIST800123Hyg = check.Ref{Title: "NIST SP 800-123, Guide to General Server Security", URL: "https://csrc.nist.gov/pubs/sp/800/123/final"}
)

// secretPatterns are matched against the contents of world-readable
// configuration files. Only the label is reported, never the match.
var secretPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"private key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----`)},
	{"AWS access key id", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"credential assignment", regexp.MustCompile(`(?im)^\s*(export\s+)?[A-Za-z0-9_.-]*(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)[A-Za-z0-9_.-]*[ \t]*[=:][ \t]*["']?[^\s"'#$%<{(]{6,}`)},
}

// secretCandidate reports whether a file name is worth reading for secrets.
func secretCandidate(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".env") || strings.HasPrefix(lower, "id_") {
		return true
	}
	for _, ext := range []string{".conf", ".cnf", ".ini", ".yml", ".yaml", ".json", ".toml", ".pem", ".key", ".properties", ".cfg", ".env", ".secret", ".secrets", ".credentials"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// cronCommands returns the command part of every job line in a crontab.
// system is true for files with a user field (/etc/crontab, /etc/cron.d).
func cronCommands(text string, system bool) (cmds []string, path string) {
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok && !strings.ContainsAny(k, " \t") {
			if strings.TrimSpace(k) == "PATH" {
				path = strings.Trim(strings.TrimSpace(v), `"'`)
			}
			continue
		}
		f := strings.Fields(t)
		n := 5
		if strings.HasPrefix(t, "@") {
			n = 1
		}
		if system {
			n++
		}
		if len(f) <= n {
			continue
		}
		cmds = append(cmds, strings.Join(f[n:], " "))
	}
	return cmds, path
}

// worldWritableDir reports whether a directory is writable by others
// without the sticky bit (anyone could replace files inside it).
func worldWritableDir(st sys.FileInfo) bool {
	return st.IsDir && st.Mode.Perm()&0o002 != 0 && st.Mode&fs.ModeSticky == 0
}

func init() {
	check.Register(&check.Check{
		ID: "HOST-SEC-001", Title: "Secrets in World-Readable Files", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatExposure, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
		Summary:   "Looks inside world-readable configuration files under /etc and the web roots for private keys, cloud access keys and password assignments.",
		Rationale: "A password or key in a file every local account can read is available to every website, service account and compromised process on the machine. Secrets found this way are the usual first step from a small web compromise to the database, the cloud account or root.",
		Detection: "Walks /etc and each web document root (metadata only, symlinks not followed), picks regular files that are readable by others and have a configuration-like name (.env*, *.conf, *.ini, *.yml, *.json, *.pem, *.key, id_*, up to 300 files of at most 256 KiB), reads them without following symlinks and matches private key headers, AWS access key ids and credential assignments (password, secret, API key or token settings with a literal value). The report names the file and the kind of match only; values are never copied.",
		Fix:       "chmod o-r each listed file (640 with the service's group, or 600). Move secrets into root-only files, systemd credentials or a secrets manager, and rotate every key or password that was readable.",
		Verify:    "find /etc /var/www -type f -perm -0004 -name '.env*' -o -type f -perm -0004 -name '*.key'  then re-run this check.",
		Refs:      []check.Ref{refSecretsCheat, refNISTIA5, refNIST800123Hyg},
		Standards: check.Standards{CWE: []string{"CWE-312", "CWE-732", "CWE-798"}, OWASP: []string{"A02:2021", "A05:2021"}, NIST: []string{"IA-5", "SC-28", "AC-3"}, CISTopic: "Protect credentials and keys at rest"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			roots := append([]string{"/etc"}, collect.DocRoots(ctx, s)...)
			var cands []sys.FileInfo
			complete := true
			for _, root := range roots {
				w, err := s.Walk(ctx, root, 20000)
				if err != nil && len(w.Files) == 0 {
					complete = false
					continue
				}
				if !w.Complete {
					complete = false
				}
				for _, f := range w.Files {
					if f.Mode.Perm()&0o004 != 0 && !f.IsDir && f.Size <= 256<<10 && secretCandidate(filepath.Base(f.Path)) {
						cands = append(cands, f)
					}
				}
			}
			sort.Slice(cands, func(i, j int) bool { return cands[i].Path < cands[j].Path })
			if len(cands) > 300 {
				cands = cands[:300]
				complete = false
			}
			var bad []string
			for _, f := range cands {
				r, err := sys.ReadFileNoFollow(ctx, s, f.Path)
				if err != nil {
					continue
				}
				var kinds []string
				for _, p := range secretPatterns {
					if p.re.Match(r.Data) {
						kinds = append(kinds, p.label)
					}
				}
				if len(kinds) > 0 {
					bad = append(bad, fmt.Sprintf("%s (mode %s): %s", f.Path, perm(f.Mode), strings.Join(kinds, ", ")))
				}
			}
			if len(bad) > 0 {
				if len(bad) > 30 {
					bad = append(bad[:30], fmt.Sprintf("... and %d more", len(bad)-30))
				}
				return []check.Result{check.FailR("filesystem", fmt.Sprintf("%d world-readable file(s) contain secrets", len(bad)), bad...)}
			}
			if !complete {
				return []check.Result{check.IncompleteR("filesystem", fmt.Sprintf("No credential patterns in %d world-readable files, but the walk was partial", len(cands)))}
			}
			return []check.Result{check.PassR("filesystem", fmt.Sprintf("No credential patterns in %d world-readable configuration files", len(cands)))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SSH-013", Title: "SSH Authorized Keys Without Restrictions or Protection", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks root's authorized_keys for keys without from= or command= options, and every authorized_keys file for permissive modes.",
		Rationale: "A key in root's authorized_keys is a root password that never expires. Restricting it with from= (allowed source addresses) or command= (one fixed command) limits what a stolen key can do. An authorized_keys file that others can write lets them add their own key; one that others can read tells them which keys to steal.",
		Detection: "Reads /root/.ssh/authorized_keys and lists key lines with neither from= nor command=; stats /root/.ssh/authorized_keys and /home/*/.ssh/authorized_keys (metadata only) and flags group or other write, and other read, permissions. Key material is never reported.",
		Fix:       "Prefix each root key with options, for example  from=\"203.0.113.0/24\",no-port-forwarding,no-agent-forwarding  or  command=\"/usr/local/bin/backup\",restrict ; chmod 600 ~/.ssh/authorized_keys and 700 ~/.ssh for every account. Prefer sudo from a personal account over direct root keys.",
		Verify:    "cut -c1-40 /root/.ssh/authorized_keys ; stat -c '%a %n' /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys",
		Refs:      []check.Ref{refSSHDAuthKeys, {Title: "NIST IR 7966, Security of Interactive and Automated Access Management Using Secure Shell (SSH)", URL: "https://csrc.nist.gov/pubs/ir/7966/final"}},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-250"}, NIST: []string{"IA-5", "AC-6", "AC-17"}, CISTopic: "SSH key management and file permissions"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files := []string{"/root/.ssh/authorized_keys"}
			more, _ := s.Glob("/home/*/.ssh/authorized_keys")
			sort.Strings(more)
			files = append(files, more...)
			var bad []string
			seen := 0
			for _, p := range files {
				st, err := s.Stat(p)
				if err != nil || st.IsDir {
					continue
				}
				seen++
				if st.Mode.Perm()&0o022 != 0 {
					bad = append(bad, perm(st.Mode)+" "+p+" is writable by group or others")
				} else if st.Mode.Perm()&0o004 != 0 {
					bad = append(bad, perm(st.Mode)+" "+p+" is readable by others")
				}
				if p != "/root/.ssh/authorized_keys" {
					continue
				}
				t, _, ok := readText(ctx, s, p)
				if !ok {
					bad = append(bad, p+" could not be read")
					continue
				}
				open := 0
				for _, line := range strings.Split(t, "\n") {
					l := strings.TrimSpace(line)
					if l == "" || strings.HasPrefix(l, "#") {
						continue
					}
					if !strings.Contains(l, "from=") && !strings.Contains(l, "command=") {
						open++
					}
				}
				if open > 0 {
					bad = append(bad, fmt.Sprintf("%s: %d root key(s) without from= or command= restrictions", p, open))
				}
			}
			if seen == 0 {
				return []check.Result{check.SkipR("authorized_keys", "No authorized_keys file exists")}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("authorized_keys", "SSH authorized keys lack restrictions or protection", bad...)}
			}
			return []check.Result{check.PassR("authorized_keys", fmt.Sprintf("%d authorized_keys file(s) are protected and root keys carry restrictions", seen))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CRON-001", Title: "Cron Jobs Run Programs Other Users Can Modify", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Resolves the programs and scripts that system and root cron jobs run and checks whether any is world-writable or sits in a world-writable folder.",
		Rationale: "HOST-FS-005 protects the cron tables themselves, but a root job that runs /usr/local/bin/backup.sh is only as trustworthy as that file. If any user can edit the script, or replace it in a writable folder, their code runs as root at the next scheduled minute.",
		Detection: "Parses /etc/crontab, /etc/cron.d/* and root's crontab in /var/spool/cron for job lines, stats every absolute path in each command (up to three per job) and every script in cron.hourly, cron.daily, cron.weekly and cron.monthly, and fails on a file with the 'other write' bit or a parent folder that is world-writable without the sticky bit.",
		Fix:       "chmod o-w <program> and its folder; move scripts out of /tmp or user-writable folders into /usr/local/sbin owned by root; have cron run only files owned by root (chown root:root).",
		Verify:    "for p in $(awk '/^[^#]/ && NF>6 {print $7}' /etc/crontab /etc/cron.d/*); do stat -c '%a %U %n' $p; done",
		Refs:      []check.Ref{refCrontab5, refAttackCron},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-426"}, NIST: []string{"AC-3", "AC-6", "CM-5"}, CISTopic: "Job schedulers: cron permissions"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			type job struct {
				src string
				cmd string
			}
			var jobs []job
			seen := 0
			sources := []string{"/etc/crontab"}
			more, _ := s.Glob("/etc/cron.d/*")
			sort.Strings(more)
			sources = append(sources, more...)
			for _, src := range sources {
				t, _, ok := readText(ctx, s, src)
				if !ok {
					continue
				}
				cmds, _ := cronCommands(t, true)
				for _, c := range cmds {
					jobs = append(jobs, job{src, c})
				}
			}
			for _, src := range []string{"/var/spool/cron/crontabs/root", "/var/spool/cron/root"} {
				t, _, ok := readText(ctx, s, src)
				if !ok {
					continue
				}
				cmds, _ := cronCommands(t, false)
				for _, c := range cmds {
					jobs = append(jobs, job{src, c})
				}
			}
			var targets []string
			for _, j := range jobs {
				n := 0
				for _, tok := range strings.Fields(j.cmd) {
					if strings.HasPrefix(tok, "/") && len(tok) > 1 {
						targets = append(targets, tok)
						if n++; n == 3 {
							break
						}
					}
				}
			}
			for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
				m, _ := s.Glob(dir + "/*")
				targets = append(targets, m...)
			}
			sort.Strings(targets)
			var bad []string
			checked := map[string]bool{}
			for _, p := range targets {
				if checked[p] {
					continue
				}
				checked[p] = true
				st, err := s.Stat(p)
				if err != nil || st.IsDir {
					continue
				}
				seen++
				if st.Mode.Perm()&0o002 != 0 {
					bad = append(bad, perm(st.Mode)+" "+p+" is world-writable")
				}
				if d, err := s.Stat(filepath.Dir(p)); err == nil && worldWritableDir(d) {
					bad = append(bad, perm(d.Mode)+" "+filepath.Dir(p)+" (folder of "+filepath.Base(p)+") is world-writable without the sticky bit")
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("cron", "Cron jobs run programs that other users can modify", bad...)}
			}
			if seen == 0 {
				return []check.Result{check.SkipR("cron", "No cron job programs with absolute paths were found")}
			}
			return []check.Result{check.PassR("cron", fmt.Sprintf("%d cron program(s) checked; none are modifiable by other users", seen))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CRON-002", Title: "World-Writable Directory in Cron's PATH", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks the PATH that system cron jobs search for commands for world-writable or relative entries.",
		Rationale: "A cron job that calls backup-db rather than /usr/local/sbin/backup-db runs whichever file of that name PATH finds first. If a folder on that PATH is world-writable, or the PATH contains an empty or relative entry, any user can plant a program that root runs on schedule (PATH interception).",
		Detection: "Reads PATH= from /etc/crontab (default /usr/bin:/bin when absent), /etc/cron.d/* and /etc/environment, stats every folder (metadata only) and fails on a world-writable folder without the sticky bit or on an empty, '.' or relative entry. Folders that cannot be stat'ed make the result incomplete.",
		Fix:       "Remove the writable folder from PATH in /etc/crontab (or chmod o-w it), delete relative entries, and call programs in cron jobs by absolute path.",
		Verify:    "grep ^PATH /etc/crontab /etc/cron.d/* ; for d in $(grep ^PATH /etc/crontab | cut -d= -f2 | tr : ' '); do stat -c '%a %n' $d; done",
		Refs:      []check.Ref{refAttackPath, refCrontab5},
		Standards: check.Standards{CWE: []string{"CWE-426", "CWE-427"}, NIST: []string{"CM-6", "AC-6", "CM-7"}, CISTopic: "Root PATH integrity"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			paths := map[string]string{} // dir -> source
			var order []string
			add := func(src, p string) {
				for _, d := range strings.Split(p, ":") {
					if _, ok := paths[d]; !ok {
						paths[d] = src
						order = append(order, d)
					}
				}
			}
			found := false
			if t, _, ok := readText(ctx, s, "/etc/crontab"); ok {
				found = true
				if _, p := cronCommands(t, true); p != "" {
					add("/etc/crontab", p)
				} else {
					add("/etc/crontab (default)", "/usr/bin:/bin")
				}
			}
			more, _ := s.Glob("/etc/cron.d/*")
			sort.Strings(more)
			for _, src := range more {
				if t, _, ok := readText(ctx, s, src); ok {
					found = true
					if _, p := cronCommands(t, true); p != "" {
						add(src, p)
					}
				}
			}
			if t, _, ok := readText(ctx, s, "/etc/environment"); ok {
				for _, line := range strings.Split(t, "\n") {
					if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.TrimSpace(k) == "PATH" {
						add("/etc/environment", strings.Trim(strings.TrimSpace(v), `"'`))
					}
				}
			}
			if !found {
				return []check.Result{check.SkipR("cron", "No system crontab found")}
			}
			var bad []string
			unknown := 0
			for _, d := range order {
				if d == "" || d == "." || !strings.HasPrefix(d, "/") {
					bad = append(bad, fmt.Sprintf("%s: relative PATH entry %q", paths[d], d))
					continue
				}
				st, err := s.Stat(d)
				if err != nil {
					unknown++
					continue
				}
				if worldWritableDir(st) {
					bad = append(bad, fmt.Sprintf("%s: %s %s is world-writable without the sticky bit", paths[d], perm(st.Mode), d))
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("cron PATH", "Cron's PATH can be hijacked", bad...)}
			}
			if unknown > 0 {
				return []check.Result{check.IncompleteR("cron PATH", fmt.Sprintf("%d of %d PATH folders could not be checked", unknown, len(order)))}
			}
			return []check.Result{check.PassR("cron PATH", fmt.Sprintf("%d PATH folders are absolute and not world-writable", len(order)))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-USR-008", Title: "Duplicate Group IDs or Account Names", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
		Summary:   "Checks /etc/group for duplicate GIDs and group names, and /etc/passwd for duplicate user names.",
		Rationale: "Two groups with one GID are the same group to the kernel, so file permissions granted to one are granted to both. Duplicate names make tools and audit logs act on the wrong entry, and are a sign that the account files were edited by hand or by a broken script.",
		Detection: "Reads /etc/group and /etc/passwd and reports any GID, group name or user name that appears more than once (HOST-USR-004 covers duplicate UIDs).",
		Fix:       "groupmod -g <new-gid> <group>  for one of each duplicate pair, then fix file ownership (find / -xdev -gid <old-gid>); remove or rename the duplicate name entries with vigr and vipw, which lock the files while editing.",
		Verify:    "cut -d: -f3 /etc/group | sort | uniq -d ; cut -d: -f1 /etc/group /etc/passwd | sort | uniq -d  print nothing.",
		Refs:      []check.Ref{refGroup5, refPasswd5},
		Standards: check.Standards{CWE: []string{"CWE-286", "CWE-284"}, NIST: []string{"AC-2", "AC-3"}, CISTopic: "No duplicate GIDs, group names or user names"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			gt, _, okG := readText(ctx, s, "/etc/group")
			pt, _, okP := readText(ctx, s, "/etc/passwd")
			if !okG && !okP {
				return []check.Result{check.SkipR("/etc/group", "Account files not readable")}
			}
			dups := func(text string, field int, what string) []string {
				byKey := map[string][]string{}
				var order []string
				for _, line := range strings.Split(text, "\n") {
					f := strings.Split(line, ":")
					if len(f) <= field || f[0] == "" || strings.HasPrefix(f[0], "+") {
						continue
					}
					if _, seen := byKey[f[field]]; !seen {
						order = append(order, f[field])
					}
					byKey[f[field]] = append(byKey[f[field]], f[0])
				}
				var out []string
				for _, k := range order {
					if len(byKey[k]) > 1 {
						out = append(out, what+" "+k+": "+strings.Join(byKey[k], ", "))
					}
				}
				return out
			}
			var bad []string
			if okG {
				bad = append(bad, dups(gt, 2, "GID")...)
				bad = append(bad, dups(gt, 0, "group name")...)
			}
			if okP {
				bad = append(bad, dups(pt, 0, "user name")...)
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/etc/group", "Duplicate group ids or names in the account files", bad...)}
			}
			if !okG || !okP {
				return []check.Result{check.IncompleteR("/etc/group", "Only one of /etc/group and /etc/passwd could be read")}
			}
			return []check.Result{check.PassR("/etc/group", "GIDs, group names and user names are unique")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-USR-009", Title: "Password and Shadow Files Out of Step", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks that every /etc/passwd account has a /etc/shadow entry, that no password hash sits in /etc/passwd, and that /etc/shadow has no orphan entries.",
		Rationale: "A hash in the world-readable /etc/passwd can be cracked offline by any user. An account with 'x' in passwd but no shadow line has an undefined password state that differs between tools, and shadow lines for deleted accounts are leftovers of a removal that did not finish.",
		Detection: "Reads /etc/passwd and /etc/shadow (root only) and reports accounts missing from shadow, passwd password fields other than x, *, ! or empty, and shadow entries with no passwd account.",
		Fix:       "pwconv  moves hashes into /etc/shadow and creates missing entries; userdel or vipw/vigr removes orphan lines; run pwck and grpck to confirm the files are consistent.",
		Verify:    "pwck -r  reports no errors.",
		Refs:      []check.Ref{refShadow5, refPasswd5, {Title: "pwck(8), Linux man-pages", URL: "https://man7.org/linux/man-pages/man8/pwck.8.html"}},
		Standards: check.Standards{CWE: []string{"CWE-256", "CWE-522"}, NIST: []string{"IA-5", "AC-2"}, CISTopic: "passwd and shadow consistency"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			pt, _, okP := readText(ctx, s, "/etc/passwd")
			if !okP {
				return []check.Result{check.SkipR("/etc/passwd", "Not readable")}
			}
			st, _, okS := readText(ctx, s, "/etc/shadow")
			if !okS {
				return []check.Result{check.IncompleteR("/etc/shadow", "/etc/shadow is not readable (run as root)")}
			}
			users := map[string]bool{}
			var bad []string
			for _, line := range strings.Split(pt, "\n") {
				f := strings.Split(line, ":")
				if len(f) < 2 || f[0] == "" || strings.HasPrefix(f[0], "+") {
					continue
				}
				users[f[0]] = true
				switch f[1] {
				case "x", "*", "!", "!!", "":
				default:
					bad = append(bad, f[0]+": password field in /etc/passwd holds a hash or value instead of x")
				}
			}
			shadow := map[string]bool{}
			for _, line := range strings.Split(st, "\n") {
				f := strings.Split(line, ":")
				if len(f) < 2 || f[0] == "" || strings.HasPrefix(f[0], "+") {
					continue
				}
				shadow[f[0]] = true
				if !users[f[0]] {
					bad = append(bad, f[0]+": /etc/shadow entry has no /etc/passwd account")
				}
			}
			names := make([]string, 0, len(users))
			for u := range users {
				names = append(names, u)
			}
			sort.Strings(names)
			for _, u := range names {
				if !shadow[u] {
					bad = append(bad, u+": /etc/passwd account has no /etc/shadow entry")
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/etc/passwd", "Account files are inconsistent", bad...)}
			}
			return []check.Result{check.PassR("/etc/passwd", fmt.Sprintf("%d accounts match between passwd and shadow", len(users)))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-USR-010", Title: "Home Directories Accessible to Other Users", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that the home directory of each interactive account denies read, write and execute to others.",
		Rationale: "Home directories hold shell history, SSH keys, application configuration and downloads. With others allowed in, any account on the machine can read another user's history and keys or, with write access, plant a .bashrc that runs when that user logs in.",
		Detection: "Reads interactive accounts from /etc/passwd (UID at or above UID_MIN, a real shell), stats each home directory (metadata only) and fails when others have any permission bit. Missing home directories are noted but do not fail.",
		Fix:       "chmod 750 /home/<user>  for each listed account (700 if group access is not needed), and set HOME_MODE 0750 in /etc/login.defs or DIR_MODE=0750 in /etc/adduser.conf so new accounts start that way.",
		Verify:    "stat -c '%a %n' /home/*  shows 750 or 700.",
		Refs:      []check.Ref{refNIST800123Hyg, {Title: "login.defs(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/login.defs.5.html"}},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-276"}, NIST: []string{"AC-3", "AC-6"}, CISTopic: "Home directory permissions"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, _, ok := readText(ctx, s, "/etc/passwd")
			if !ok {
				return []check.Result{check.SkipR("/etc/passwd", "Not readable")}
			}
			uidMin := 1000
			if v, _, ok := collect.First(collect.ReadConfigs(ctx, s, "/etc/login.defs"), "uid_min"); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
					uidMin = n
				}
			}
			var bad, missing []string
			seen := 0
			for _, line := range strings.Split(text, "\n") {
				f := strings.Split(line, ":")
				if len(f) < 7 {
					continue
				}
				uid, err := strconv.Atoi(f[2])
				if err != nil || uid < uidMin || uid == 65534 || f[5] == "" || f[5] == "/" {
					continue
				}
				sh := f[6]
				if strings.HasSuffix(sh, "nologin") || strings.HasSuffix(sh, "/false") {
					continue
				}
				st, err := s.Stat(f[5])
				if err != nil {
					missing = append(missing, f[0]+": "+f[5]+" does not exist")
					continue
				}
				seen++
				if st.Mode.Perm()&0o007 != 0 {
					bad = append(bad, fmt.Sprintf("%s %s (%s) is accessible to others", perm(st.Mode), f[5], f[0]))
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/home", "Home directories are accessible to other users", bad...)}
			}
			if seen == 0 {
				if len(missing) > 0 {
					return []check.Result{check.IncompleteR("/home", "No home directory could be checked", missing...)}
				}
				return []check.Result{check.SkipR("/home", "No interactive accounts with home directories")}
			}
			return []check.Result{check.PassR("/home", fmt.Sprintf("%d home directories deny access to others", seen), missing...)}
		},
	})
}
