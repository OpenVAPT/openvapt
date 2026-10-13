package collect

import (
	"context"
	"encoding/json"
	"github.com/openvapt/openvapt/internal/sys"
	"path/filepath"
	"regexp"
	"strings"
)

type Installed struct {
	Ecosystem string
	Package   string
	Version   string
	Path      string
}

func Ecosystem(m map[string]string) string {
	v := m["VERSION_ID"]
	switch m["ID"] {
	case "debian":
		return "Debian:" + strings.Split(v, ".")[0]
	case "ubuntu":
		if strings.Contains(strings.ToLower(m["PRETTY_NAME"]), "lts") {
			return "Ubuntu:" + v + ":LTS"
		}
		return "Ubuntu:" + v
	case "almalinux":
		return "AlmaLinux:" + strings.Split(v, ".")[0]
	case "rocky":
		return "Rocky Linux:" + strings.Split(v, ".")[0]
	}
	return ""
}
func HostInventory(ctx context.Context, s sys.System) ([]Installed, bool) {
	eco := Ecosystem(OSRelease(s))
	if eco == "" {
		return nil, false
	}
	var out []Installed
	if strings.HasPrefix(eco, "Debian:") || strings.HasPrefix(eco, "Ubuntu:") {
		r, e := s.ReadFile(ctx, "/var/lib/dpkg/status")
		if e != nil {
			return nil, false
		}
		for _, block := range strings.Split(string(r.Data), "\n\n") {
			m := map[string]string{}
			for _, l := range strings.Split(block, "\n") {
				if k, v, ok := strings.Cut(l, ":"); ok && !strings.HasPrefix(l, " ") {
					m[k] = strings.TrimSpace(v)
				}
			}
			if m["Status"] == "install ok installed" && m["Package"] != "" && m["Version"] != "" {
				out = append(out, Installed{eco, m["Package"], m["Version"], "/var/lib/dpkg/status"})
			}
		}
		return out, r.Complete && len(out) > 0
	}
	if strings.HasPrefix(eco, "AlmaLinux:") || strings.HasPrefix(eco, "Rocky Linux:") {
		v, e := s.Run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n")
		if e != nil {
			return nil, false
		}
		for _, l := range strings.Split(v, "\n") {
			f := strings.Split(l, "\t")
			if len(f) == 2 && f[0] != "" && f[1] != "" {
				out = append(out, Installed{eco, f[0], f[1], "rpm database"})
			}
		}
		return out, len(out) > 0
	}
	return nil, false
}

var wpVersion = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)
var jqVersion = regexp.MustCompile(`(?i)jquery(?: javascript library)?[ -]+v?(\d+\.\d+\.\d+)`)

func WebInventory(ctx context.Context, s sys.System) ([]Installed, bool) {
	roots := DocRoots(ctx, s)
	if len(roots) == 0 {
		return nil, false
	}
	var out []Installed
	complete := true
	for _, root := range roots {
		w, e := s.Walk(ctx, root, 5000)
		if e != nil || !w.Complete {
			complete = false
		}
		for _, fi := range w.Files {
			p := fi.Path
			base := filepath.Base(p)
			if base != "composer.lock" && base != "package-lock.json" && base != "version.php" && !strings.HasPrefix(base, "jquery") {
				continue
			}
			if base == "version.php" && filepath.Base(filepath.Dir(p)) != "wp-includes" {
				continue
			}
			if strings.HasPrefix(base, "jquery") && !strings.HasSuffix(base, ".js") {
				continue
			}
			r, e := sys.ReadFileNoFollow(ctx, s, p)
			if e != nil || !r.Complete {
				complete = false
				continue
			}
			switch base {
			case "composer.lock":
				var x struct {
					Packages    []struct{ Name, Version string }
					PackagesDev []struct{ Name, Version string }
				}
				if json.Unmarshal(r.Data, &x) != nil {
					complete = false
					continue
				}
				for _, a := range append(x.Packages, x.PackagesDev...) {
					out = append(out, Installed{"Packagist", a.Name, strings.TrimPrefix(a.Version, "v"), p})
				}
			case "package-lock.json":
				var x struct {
					LockfileVersion int
					Dependencies    map[string]struct{ Version string }
					Packages        map[string]struct{ Version string }
				}
				if json.Unmarshal(r.Data, &x) != nil || x.LockfileVersion < 1 || x.LockfileVersion > 3 {
					complete = false
					continue
				}
				for n, a := range x.Dependencies {
					out = append(out, Installed{"npm", n, a.Version, p})
				}
				for n, a := range x.Packages {
					if strings.HasPrefix(n, "node_modules/") {
						out = append(out, Installed{"npm", strings.TrimPrefix(n, "node_modules/"), a.Version, p})
					}
				}
			case "version.php":
				if m := wpVersion.FindSubmatch(r.Data); m != nil {
					out = append(out, Installed{"WordPress", "wordpress", string(m[1]), p})
				} else {
					complete = false
				}
			default:
				if m := jqVersion.FindSubmatch(r.Data); m != nil {
					out = append(out, Installed{"npm", "jquery", string(m[1]), p})
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, complete
}
