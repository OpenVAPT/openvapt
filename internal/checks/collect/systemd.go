package collect

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/openvapt/openvapt/internal/sys"
)

// ---------- systemd service units ----------

// Unit is one systemd service unit with its drop-in overrides merged in.
type Unit struct {
	Name     string              // e.g. "shop.service"
	Path     string              // the unit file that won (highest precedence)
	DropIns  []string            // drop-in .conf files applied on top
	Values   map[string][]string // lower-case "section.key" -> values in effect
	Custom   bool                // written by the administrator in /etc/systemd/system
	Complete bool                // false if any file was unreadable or truncated
}

// Get returns the last value of a [Service] (or other section) key, or "".
func (u Unit) Get(key string) string {
	v := u.Values[strings.ToLower(key)]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

// All returns every value of a key, for list settings such as Environment.
func (u Unit) All(key string) []string { return u.Values[strings.ToLower(key)] }

// LongRunning reports whether the unit starts a process that stays running
// (anything other than Type=oneshot), which is what attackers can reach.
func (u Unit) LongRunning() bool {
	return u.Get("service.execstart") != "" && !strings.EqualFold(u.Get("service.type"), "oneshot")
}

// RunsAsRoot reports whether the service's main process runs as root:
// no User= (or User=root / 0) and no DynamicUser=yes.
func (u Unit) RunsAsRoot() bool {
	if Truthy(u.Get("service.dynamicuser")) {
		return false
	}
	user := u.Get("service.user")
	return user == "" || user == "root" || user == "0"
}

// Env returns the Environment= variables of the unit as a name -> value map.
func (u Unit) Env() map[string]string {
	out := map[string]string{}
	for _, line := range u.All("service.environment") {
		for _, kv := range splitEnv(line) {
			if k, v, ok := strings.Cut(kv, "="); ok {
				out[k] = v
			}
		}
	}
	return out
}

// Program returns the executable path of the first ExecStart= line, without
// systemd's special prefixes (@, -, :, +, !).
func (u Unit) Program() string {
	f := strings.Fields(u.Get("service.execstart"))
	if len(f) == 0 {
		return ""
	}
	return strings.TrimLeft(f[0], "@-:+!")
}

// Truthy interprets systemd and ini booleans.
func Truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

// unitDirs are searched from lowest to highest precedence, so a unit in
// /etc/systemd/system overrides the packaged copy of the same name.
var unitDirs = []string{"/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system", "/etc/systemd/system"}

var unitCache sync.Map // per System, cached for one scan

// Units reads every service unit (at most 400) and merges its drop-ins.
// Symlinks are skipped: in /etc/systemd/system they are enablement links or
// masks pointing at files that are read from their real location.
func Units(ctx context.Context, s sys.System) []Unit {
	if v, ok := unitCache.Load(s); ok {
		return v.([]Unit)
	}
	winner := map[string]string{}
	for _, dir := range unitDirs {
		files, _ := s.Glob(dir + "/*.service")
		for _, f := range files {
			if st, err := s.Stat(f); err == nil && st.Mode&fs.ModeSymlink != 0 {
				continue
			}
			winner[filepath.Base(f)] = f
		}
	}
	names := make([]string, 0, len(winner))
	for n := range winner {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 400 {
		names = names[:400]
	}
	var out []Unit
	for _, n := range names {
		u := Unit{Name: n, Path: winner[n], Values: map[string][]string{}, Complete: true}
		u.Custom = strings.HasPrefix(u.Path, "/etc/systemd/system/")
		if !parseUnitFile(ctx, s, u.Path, u.Values) {
			u.Complete = false
		}
		// As systemd does: drop-ins from every directory are applied in one
		// order sorted by file name, and a same-named file in a higher
		// precedence directory replaces the lower one.
		drop := map[string]string{}
		for _, dir := range unitDirs {
			files, _ := s.Glob(dir + "/" + n + ".d/*.conf")
			for _, d := range files {
				drop[filepath.Base(d)] = d
			}
		}
		names := make([]string, 0, len(drop))
		for b := range drop {
			names = append(names, b)
		}
		sort.Strings(names)
		for _, b := range names {
			u.DropIns = append(u.DropIns, drop[b])
			if !parseUnitFile(ctx, s, drop[b], u.Values) {
				u.Complete = false
			}
		}
		out = append(out, u)
	}
	unitCache.Store(s, out)
	return out
}

// parseUnitFile applies one unit file to vals. An empty assignment (Key=)
// resets a list setting, as systemd does.
func parseUnitFile(ctx context.Context, s sys.System, path string, vals map[string][]string) bool {
	r, err := s.ReadFile(ctx, path)
	if err != nil {
		return false
	}
	section := ""
	lines := strings.Split(strings.ReplaceAll(string(r.Data), "\\\n", " "), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := section + "." + strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if v == "" {
			delete(vals, key)
			continue
		}
		vals[key] = append(vals[key], v)
	}
	return r.Complete
}

// splitEnv splits an Environment= value into assignments, honouring quotes:
// Environment="A=1 2" B=3 gives ["A=1 2", "B=3"].
func splitEnv(s string) []string {
	var out []string
	var cur strings.Builder
	quote := rune(0)
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == '"' || r == '\''):
			quote = r
		case quote == 0 && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
