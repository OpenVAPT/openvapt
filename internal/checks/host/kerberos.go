package host

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

var (
	krbRef      = check.Ref{Title: "MIT Kerberos, krb5.conf", URL: "https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html"}
	krbWeakFlag = regexp.MustCompile(`(?i)^allow_weak_crypto\s*=\s*(true|yes|on|y|t|1)\b`)
	krbEnctypes = regexp.MustCompile(`(?i)^(default_tkt_enctypes|default_tgs_enctypes|permitted_enctypes)\s*=\s*(.*)$`)
	krbWeakType = regexp.MustCompile(`(?i)^(des|des3|rc4|arcfour)([a-z0-9-]*)$`)
)

// krbConfig reads krb5.conf and the files it includes, one level deep and at
// most 50 files, because distributions keep crypto policy in included files.
func krbConfig(ctx context.Context, s sys.System) (files map[string]string, complete, ok bool) {
	r, e := s.ReadFile(ctx, "/etc/krb5.conf")
	if e != nil {
		return nil, true, false
	}
	files = map[string]string{"/etc/krb5.conf": string(r.Data)}
	complete = r.Complete
	var more []string
	for _, line := range strings.Split(string(r.Data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !strings.HasPrefix(f[1], "/") {
			continue
		}
		switch f[0] {
		case "include":
			more = append(more, f[1])
		case "includedir":
			g, _ := s.Glob(strings.TrimRight(f[1], "/") + "/*")
			more = append(more, g...)
		}
	}
	sort.Strings(more)
	if len(more) > 50 {
		more, complete = more[:50], false
	}
	for _, p := range more {
		x, e := s.ReadFile(ctx, p)
		if e != nil || !x.Complete {
			complete = false
			continue
		}
		files[p] = string(x.Data)
	}
	return files, complete, true
}

// krbListsWeak reads an enctype list. A leading minus removes a type, so it
// is not a weakness.
func krbListsWeak(list string) bool {
	for _, t := range strings.FieldsFunc(list, func(c rune) bool { return c == ' ' || c == ',' || c == '\t' }) {
		if krbWeakType.MatchString(strings.TrimPrefix(t, "+")) {
			return true
		}
	}
	return false
}

func init() {
	check.Register(&check.Check{
		ID: "HOST-KRB-001", Title: "Kerberos Allows Weak Encryption", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatCrypto, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks the Kerberos client configuration for weak encryption types.",
		Rationale: "DES and RC4 tickets can be cracked offline, which can reveal account passwords.",
		Detection: "Reads /etc/krb5.conf and the files it includes, and looks for allow_weak_crypto set to true, or a DES, 3DES or RC4 type in an encryption type list. It skips the check when the file does not exist.",
		Fix:       "Remove allow_weak_crypto and list only AES types, for example aes256-cts-hmac-sha1-96, after confirming your Kerberos servers support them.",
		Verify:    "grep -E 'allow_weak_crypto|enctypes' /etc/krb5.conf should show no DES, 3DES or RC4 type.",
		Refs:      []check.Ref{krbRef},
		Standards: check.Standards{CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, NIST: []string{"SC-13", "IA-5"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files, complete, ok := krbConfig(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("/etc/krb5.conf", "Kerberos client configuration not found")}
			}
			var out []check.Result
			for path, text := range files {
				for _, line := range strings.Split(text, "\n") {
					t := strings.TrimSpace(line)
					if t == "" || t[0] == '#' || t[0] == ';' {
						continue
					}
					if krbWeakFlag.MatchString(t) {
						out = append(out, check.FailR(path, "allow_weak_crypto is enabled"))
					} else if m := krbEnctypes.FindStringSubmatch(t); m != nil && krbListsWeak(m[2]) {
						out = append(out, check.FailR(path, fmt.Sprintf("%s lists a weak type", m[1])))
					}
				}
			}
			if !complete {
				out = append(out, check.IncompleteR("/etc/krb5.conf", "Some Kerberos configuration could not be read"))
			}
			if len(out) == 0 {
				return []check.Result{check.PassR("/etc/krb5.conf", "No weak encryption type is configured")}
			}
			return out
		},
	})
	check.Register(&check.Check{
		ID: "HOST-KRB-002", Title: "Kerberos Keytab Readable by Others", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Checks the owner and permissions of the system Kerberos keytab.",
		Rationale: "A keytab holds long-term keys, so anyone who can read it can act as the host.",
		Detection: "Reads the metadata of /etc/krb5.keytab, never its contents. It fails when root does not own the file or when group or others have any access. It skips the check when the file does not exist.",
		Fix:       "Run chown root:root /etc/krb5.keytab and chmod 600 /etc/krb5.keytab. Replace the keys if unknown accounts may have read the file.",
		Verify:    "stat -c '%a %U' /etc/krb5.keytab should print 600 root.",
		Refs:      []check.Ref{krbRef},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-6", "IA-5"}},
		Run: func(_ context.Context, s sys.System) []check.Result {
			fi, e := s.Stat("/etc/krb5.keytab")
			if e != nil {
				return []check.Result{check.SkipR("/etc/krb5.keytab", "No system keytab found")}
			}
			if fi.UID != 0 || fi.Mode.Perm()&0o077 != 0 {
				return []check.Result{check.FailR("/etc/krb5.keytab", fmt.Sprintf("Mode %o, owner uid %d", fi.Mode.Perm(), fi.UID))}
			}
			return []check.Result{check.PassR("/etc/krb5.keytab", "Owned by root, with no group or other access")}
		},
	})
}
