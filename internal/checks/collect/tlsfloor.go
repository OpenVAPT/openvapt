package collect

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// TLSFloor is the lowest TLS version the system crypto library will
// negotiate, as read from its configuration. Server programs that use the
// system OpenSSL (nginx, Apache mod_ssl, Postfix, Dovecot) inherit this
// floor whatever their own protocol directive lists, so a directive that
// still names TLSv1 or TLSv1.1 is not reachable when the floor is TLS 1.2.
//
// Two sources are read, both plain files:
//   - /etc/crypto-policies/config (RHEL, Alma, Rocky, Fedora): the policy
//     name. DEFAULT, FUTURE and FIPS refuse TLS 1.0 and 1.1; LEGACY allows
//     them. A sub-policy suffix (DEFAULT:SHA1) keeps the base policy.
//   - openssl.cnf (/etc/ssl, /etc/pki/tls, /usr/lib/ssl) and the files it
//     pulls in with .include: an uncommented MinProtocol = TLSv1.2 or
//     TLSv1.3 line. Debian 12 and Ubuntu 22.04 and later ship this.
//
// Detection only. When neither source is readable, Known is false and the
// caller must judge from the directive alone.
type TLSFloor struct {
	Known    bool   // a floor setting was found
	Forbids  bool   // the floor refuses TLS 1.0 and 1.1
	Evidence string // "file: setting" for the report
}

var minProtocolRe = regexp.MustCompile(`(?i)^\s*MinProtocol\s*=\s*(TLSv1(?:\.[0-3])?|SSLv3|DTLSv1(?:\.2)?|None)\s*$`)

var opensslRoots = []string{"/etc/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf", "/usr/lib/ssl/openssl.cnf"}
var opensslPrefixes = []string{"/etc/ssl/", "/etc/pki/tls/", "/etc/crypto-policies/", "/usr/lib/ssl/"}

// SystemTLSFloor reads the system crypto policy and OpenSSL configuration
// and reports whether they already forbid TLS 1.0 and 1.1.
func SystemTLSFloor(ctx context.Context, s sys.System) TLSFloor {
	if r, err := s.ReadFile(ctx, "/etc/crypto-policies/config"); err == nil {
		for _, line := range strings.Split(string(r.Data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			base := strings.ToUpper(strings.SplitN(t, ":", 2)[0])
			switch base {
			case "DEFAULT", "FUTURE", "FIPS":
				return TLSFloor{Known: true, Forbids: true, Evidence: "/etc/crypto-policies/config: " + t + " (refuses TLS 1.0 and 1.1)"}
			case "LEGACY":
				return TLSFloor{Known: true, Forbids: false, Evidence: "/etc/crypto-policies/config: " + t + " (allows TLS 1.0 and 1.1)"}
			}
			break
		}
	}
	seen := map[string]bool{}
	var found []string
	forbids := true
	for _, root := range opensslRoots {
		readOpenSSLTree(ctx, s, root, seen, 0, &found, &forbids)
	}
	if len(found) == 0 {
		return TLSFloor{}
	}
	ev := found[len(found)-1]
	if forbids {
		ev += " (refuses TLS 1.0 and 1.1)"
	} else {
		ev += " (allows TLS 1.0 or 1.1)"
	}
	return TLSFloor{Known: true, Forbids: forbids, Evidence: ev}
}

// readOpenSSLTree reads one openssl.cnf file and follows its .include
// directives (a file or a directory of .cnf files) while they stay under the
// crypto configuration folders. Every MinProtocol line found is recorded;
// the floor forbids TLS 1.0 and 1.1 only when all of them do.
func readOpenSSLTree(ctx context.Context, s sys.System, path string, seen map[string]bool, depth int, found *[]string, forbids *bool) {
	if depth > 4 || seen[path] || len(seen) > 20 || !underCryptoPrefixes(path) {
		return
	}
	seen[path] = true
	r, err := s.ReadFile(ctx, path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(r.Data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if m := minProtocolRe.FindStringSubmatch(t); m != nil {
			*found = append(*found, path+": "+t)
			v := strings.ToLower(m[1])
			if v != "tlsv1.2" && v != "tlsv1.3" {
				*forbids = false
			}
			continue
		}
		if !strings.HasPrefix(t, ".include") {
			continue
		}
		target := strings.TrimSpace(strings.TrimPrefix(t, ".include"))
		target = strings.TrimSpace(strings.TrimPrefix(target, "="))
		target = strings.Trim(target, `"'`)
		if target == "" || strings.Contains(target, "..") {
			continue
		}
		if !strings.HasPrefix(target, "/") {
			target = path[:strings.LastIndex(path, "/")+1] + target
		}
		if !underCryptoPrefixes(target) {
			continue
		}
		if info, err := s.Stat(target); err == nil && info.IsDir {
			files, _ := s.Glob(strings.TrimSuffix(target, "/") + "/*.cnf")
			sort.Strings(files)
			for _, f := range files {
				readOpenSSLTree(ctx, s, f, seen, depth+1, found, forbids)
			}
			continue
		}
		readOpenSSLTree(ctx, s, target, seen, depth+1, found, forbids)
	}
}

func underCryptoPrefixes(p string) bool {
	for _, pre := range opensslPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}
