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
