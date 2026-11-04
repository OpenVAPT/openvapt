package collect

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// DocRoots returns the document root folders configured for the local web
// servers (Apache DocumentRoot, nginx root, LiteSpeed docRoot). These are the
// folders whose files the web server can publish, so files in them deserve
// the same scrutiny as URLs. At most 30 roots are returned.
func DocRoots(ctx context.Context, s sys.System) []string {
	set := map[string]bool{}
	for _, pat := range vhostPatterns {
		files, _ := s.Glob(pat)
		for _, f := range files {
			// These are root-owned server configuration files, where links
			// are normal (nginx sites-enabled), so links are followed here.
			// Files found under the roots returned below are read with
			// sys.ReadFileNoFollow by their callers.
			r, err := s.ReadFile(ctx, f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(r.Data), "\n") {
				t := strings.TrimSpace(line)
				if t == "" || t[0] == '#' {
					continue
				}
				fields := strings.Fields(strings.TrimSuffix(t, ";"))
				if len(fields) < 2 {
					continue
				}
				switch strings.ToLower(fields[0]) {
				case "documentroot", "root", "docroot":
					p := strings.Trim(fields[1], `"';`)
					if strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "$*") && p != "/" {
						set[filepath.Clean(p)] = true
					}
				}
			}
		}
	}
	var out []string
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

// statusConfigPatterns are the files where Apache and nginx status pages
// are configured, in addition to the virtual host files.
var statusConfigPatterns = []string{"/etc/apache2/mods-enabled/status.conf", "/etc/apache2/conf-enabled/*.conf", "/etc/httpd/conf.d/*.conf", "/etc/httpd/conf.modules.d/*.conf"}

// StatusPageLocalOnly reports whether the web server configuration limits
// its status pages (/server-status, /server-info, /nginx_status, stub_status)
// to local clients: a <Location> or location block for them that carries
// Require local, Require ip 127..., or allow 127.0.0.1 with deny all. The
// scan itself requests from 127.0.0.1, so a status page that answers can
// still be invisible to every other machine; this is how a check tells the
// two apart. The restricting directive is returned as evidence.
func StatusPageLocalOnly(ctx context.Context, s sys.System) (string, bool) {
	seen := map[string]bool{}
	for _, pat := range append(append([]string{}, vhostPatterns...), statusConfigPatterns...) {
		files, _ := s.Glob(pat)
		for _, f := range files {
			if seen[f] {
				continue
			}
			seen[f] = true
			r, err := s.ReadFile(ctx, f)
			if err != nil {
				continue
			}
			if ev, ok := statusBlockLocalOnly(string(r.Data)); ok {
				return f + ": " + ev, true
			}
		}
	}
	return "", false
}

// statusBlockLocalOnly inspects every block that names a status page.
func statusBlockLocalOnly(text string) (string, bool) {
	lower := strings.ToLower(text)
	for _, marker := range []string{"server-status", "server-info", "nginx_status", "stub_status"} {
		from := 0
		for {
			i := strings.Index(lower[from:], marker)
			if i < 0 {
				break
			}
			i += from
			from = i + len(marker)
			end := len(lower)
			for _, closer := range []string{"</location>", "</locationmatch>", "}"} {
				if j := strings.Index(lower[i:], closer); j >= 0 && i+j < end {
					end = i + j
				}
			}
			block := lower[i:end]
			switch {
			case strings.Contains(block, "require local"):
				return "Require local", true
			case strings.Contains(block, "require ip 127.") || strings.Contains(block, "require ip ::1"):
				return "Require ip 127.0.0.1", true
			case strings.Contains(block, "allow 127.0.0.1") && strings.Contains(block, "deny all"):
				return "allow 127.0.0.1; deny all", true
			case strings.Contains(block, "allow from 127.0.0.1") && (strings.Contains(block, "deny from all") || strings.Contains(block, "order deny,allow")):
				return "Allow from 127.0.0.1", true
			}
		}
	}
	return "", false
}
