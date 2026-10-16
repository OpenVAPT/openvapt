package collect

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/openvapt/openvapt/internal/vulndb"
)

// Lockfiles for the Python, Ruby, Go and Rust ecosystems. Only package names
// and versions are kept; nothing else from these files reaches a report.
// Maven is not read: pom.xml versions often come from properties and parent
// files, so a reliable version cannot be established from one file.
var extraLockfiles = map[string]bool{
	"poetry.lock": true, "Pipfile.lock": true, "requirements.txt": true,
	"Gemfile.lock": true, "go.mod": true, "Cargo.lock": true,
}

var (
	tomlName    = regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"`)
	tomlVersion = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`)
	reqPin      = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,]*)`)
	gemSpec     = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)]+)\)$`)
	goRequire   = regexp.MustCompile(`^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/\S+)\s+(v\d\S*)`)
)

// tomlPackages reads [[package]] tables (poetry.lock, Cargo.lock).
func tomlPackages(text, eco, path string) []Installed {
	var out []Installed
	for _, block := range strings.Split(text, "[[package]]")[1:] {
		if i := strings.Index(block, "\n["); i >= 0 {
			block = block[:i]
		}
		n, v := tomlName.FindStringSubmatch(block), tomlVersion.FindStringSubmatch(block)
		if n != nil && v != nil {
			name := n[1]
			if eco == "PyPI" {
				name = vulndb.PyPIName(name)
			}
			out = append(out, Installed{Ecosystem: eco, Package: name, Version: v[1], Path: path})
		}
	}
	return out
}

// ParseLockfile reads one of the extra lockfiles. ok is false when the file
// could not be understood, so the inventory is reported as incomplete.
func ParseLockfile(base, path string, data []byte) (out []Installed, ok bool) {
	text := string(data)
	switch base {
	case "poetry.lock":
		out = tomlPackages(text, "PyPI", path)
		return out, len(out) > 0 || !strings.Contains(text, "[[package]]")
	case "Cargo.lock":
		out = tomlPackages(text, "crates.io", path)
		return out, len(out) > 0 || !strings.Contains(text, "[[package]]")
	case "Pipfile.lock":
		var x map[string]json.RawMessage
		if json.Unmarshal(data, &x) != nil {
			return nil, false
		}
		for _, sec := range []string{"default", "develop"} {
			var pk map[string]struct{ Version string }
			if raw, has := x[sec]; has && json.Unmarshal(raw, &pk) == nil {
				for n, p := range pk {
					if v := strings.TrimPrefix(p.Version, "=="); v != p.Version && v != "" {
						out = append(out, Installed{Ecosystem: "PyPI", Package: vulndb.PyPIName(n), Version: v, Path: path})
					}
				}
			}
		}
		return out, true
	case "requirements.txt":
		// Only exact pins (name==version) say what is installed.
		for _, l := range strings.Split(text, "\n") {
			if m := reqPin.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
				out = append(out, Installed{Ecosystem: "PyPI", Package: vulndb.PyPIName(m[1]), Version: m[2], Path: path})
			}
		}
		return out, true
	case "Gemfile.lock":
		in := false
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimRight(l, "\r")
			switch {
			case strings.TrimSpace(l) == "specs:":
				in = true
			case l == "" || !strings.HasPrefix(l, " "):
				in = false
			case in:
				if m := gemSpec.FindStringSubmatch(l); m != nil {
					v := strings.SplitN(m[2], "-", 2)[0] // drop a platform suffix such as -x86_64-linux
					out = append(out, Installed{Ecosystem: "RubyGems", Package: m[1], Version: v, Path: path})
				}
			}
		}
		return out, true
	case "go.mod":
		for _, l := range strings.Split(text, "\n") {
			l = strings.SplitN(l, "//", 2)[0]
			if strings.HasPrefix(strings.TrimSpace(l), "module ") || strings.HasPrefix(strings.TrimSpace(l), "go ") {
				continue
			}
			if m := goRequire.FindStringSubmatch(l); m != nil {
				out = append(out, Installed{Ecosystem: "Go", Package: m[1], Version: strings.TrimPrefix(strings.SplitN(m[2], "+", 2)[0], "v"), Path: path})
			}
		}
		return out, true
	}
	return nil, false
}
