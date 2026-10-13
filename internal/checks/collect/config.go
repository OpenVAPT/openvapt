package collect

import (
	"bufio"
	"context"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// ConfigFile is one parsed configuration file.
type ConfigFile struct {
	Path     string
	Values   map[string][]string // lower-case key -> values in file order
	Complete bool
}

// ReadConfigs reads every file matching the glob patterns and parses simple
// "key value", "key = value" or "key: value" lines. Comments starting with
// '#' or ';' are ignored. It is a deliberately small parser for the many
// daemons whose configuration follows this shape (redis, mongod YAML top
// level keys, mysqld, postfix, login.defs, sysctl.d, php.ini, smb.conf).
func ReadConfigs(ctx context.Context, s sys.System, patterns ...string) []ConfigFile {
	seen := map[string]bool{}
	var paths []string
	for _, p := range patterns {
		if !strings.ContainsAny(p, "*?[") {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
			continue
		}
		m, _ := s.Glob(p)
		sort.Strings(m)
		for _, x := range m {
			if !seen[x] {
				seen[x] = true
				paths = append(paths, x)
			}
		}
	}
	var out []ConfigFile
	for _, p := range paths {
		r, err := s.ReadFile(ctx, p)
		if err != nil {
			continue
		}
		out = append(out, ConfigFile{Path: p, Values: ParseKV(string(r.Data)), Complete: r.Complete})
	}
	return out
}

// ParseKV parses key/value lines. Section headers like "[mysqld]" are kept
// as a prefix ("mysqld.key") so INI-style files can be queried precisely.
func ParseKV(text string) map[string][]string {
	m := map[string][]string{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if i := strings.Index(line, " #"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		var k, v string
		if strings.HasPrefix(line, "-") {
			// A command-line option file (memcached.conf): "-l ::1" must not
			// be split at the IPv6 colons.
			f := strings.Fields(line)
			k = f[0]
			v = strings.TrimSpace(strings.TrimPrefix(line, f[0]))
		} else if i := strings.IndexAny(line, "=:"); i > 0 && !strings.ContainsAny(line[:i], " \t") || (i > 0 && strings.TrimSpace(line[:i]) != "" && !strings.Contains(strings.TrimSpace(line[:i]), " ")) {
			k, v = line[:i], line[i+1:]
		} else if f := strings.Fields(line); len(f) >= 1 {
			k = f[0]
			v = strings.TrimSpace(strings.TrimPrefix(line, f[0]))
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k == "" {
			continue
		}
		if section != "" {
			m[section+"."+k] = append(m[section+"."+k], v)
		}
		m[k] = append(m[k], v)
	}
	return m
}

// First returns the first value of key across files, the file it came from,
// and whether it was found.
func First(files []ConfigFile, key string) (string, string, bool) {
	for _, f := range files {
		if v, ok := f.Values[strings.ToLower(key)]; ok && len(v) > 0 {
			return v[0], f.Path, true
		}
	}
	return "", "", false
}
