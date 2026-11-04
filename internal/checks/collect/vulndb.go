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
	// Source and SourceVersion name the source package when it differs from
	// Package. OSV files Debian, Ubuntu and Rocky advisories under the source
	// name (openssh), never the binary name (openssh-server).
	Source        string
	SourceVersion string
	// SourceOnly is set where the feed never uses binary names (dpkg), so a
	// binary sharing a name with an unrelated source is not compared.
	SourceOnly bool
	// Stream is the rpm module stream (nodejs:14) the package was built from.
	Stream string
	// Layer names the container image layer an item was read from.
	Layer string
	Path  string
	// Heuristic marks a version read from a file header or comment rather
	// than a package manager record, so a match is weaker evidence.
	Heuristic bool
}

// Matcher labels how an inventory item's version was established, so a CVE
// finding can say "exact version", "range" or "heuristic" in its evidence.
func (i Installed) Matcher(rangeMatcher string) string {
	if i.Layer != "" {
		return "heuristic (image layer: a later layer may hold a newer version)"
	}
	if i.Heuristic {
		return "heuristic (version read from a file header)"
	}
	return rangeMatcher
}

// Names returns each name and version this item can be matched under.
func (i Installed) Names() [][2]string {
	out := [][2]string{{i.Package, i.Version}}
	if i.Source != "" && i.Source != i.Package {
		v := i.SourceVersion
		if v == "" {
			v = i.Version
		}
		if i.SourceOnly {
			return [][2]string{{i.Source, v}}
		}
		out = append(out, [2]string{i.Source, v})
	}
	return out
}

// rpmSource splits openssh-8.7p1-38.el9.src.rpm into openssh and 8.7p1-38.el9.
func rpmSource(rpm string) (name, versionRelease string) {
	base, ok := strings.CutSuffix(rpm, ".src.rpm")
	if !ok {
		return "", ""
	}
	parts := strings.Split(base, "-")
	if len(parts) < 3 {
		return "", ""
	}
	n := len(parts) - 2
	return strings.Join(parts[:n], "-"), parts[n] + "-" + parts[n+1]
}

// resolveRPMSources gives each item the epoch-qualified source version.
// SOURCERPM has no epoch and a subpackage may carry its own version and epoch
// (perl-Carp under perl), so the epoch comes from a sibling built at the
// source's own version. With no such sibling the source name is dropped: a
// missed match beats comparing the wrong version.
func resolveRPMSources(items []Installed) {
	epochs := map[string]string{}
	for _, i := range items {
		if e, vr, ok := strings.Cut(i.Version, ":"); ok && vr == i.SourceVersion {
			epochs[i.Source+"\x00"+vr] = e
		}
	}
	for n := range items {
		i := &items[n]
		if i.Source == "" {
			continue
		}
		if e, ok := epochs[i.Source+"\x00"+i.SourceVersion]; ok {
			i.SourceVersion = e + ":" + i.SourceVersion
		} else {
			i.Source, i.SourceVersion = "", ""
		}
	}
}

// unsignedKernel maps a signed kernel source to the name advisories use:
// linux-signed-hwe-5.15 is linux-hwe-5.15, and Debian's architecture forms
// (linux-signed-amd64) and plain linux-signed are linux.
func unsignedKernel(src string) (string, bool) {
	if src == "linux-signed" {
		return "linux", true
	}
	rest, ok := strings.CutPrefix(src, "linux-signed-")
	if !ok {
		return "", false
	}
	switch rest {
	case "amd64", "arm64", "i386", "ppc64el", "s390x":
		return "linux", true
	}
	return "linux-" + rest, true
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
	case "alpine":
		// Edge reports a version such as 3.23_alpha20250101, which no feed names.
		if p := strings.Split(v, "."); len(p) >= 2 && !strings.Contains(v, "_") {
			return "Alpine:v" + p[0] + "." + p[1]
		}
		return ""
	case "almalinux":
		return "AlmaLinux:" + strings.Split(v, ".")[0]
	case "rocky":
		return "Rocky Linux:" + strings.Split(v, ".")[0]
	}
	return ""
}

// parseDpkgStatus lists installed packages from a dpkg status file.
func parseDpkgStatus(text, eco, path string) []Installed {
	var out []Installed
	for _, block := range strings.Split(text, "\n\n") {
		m := map[string]string{}
		for _, l := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && !strings.HasPrefix(l, " ") {
				m[k] = strings.TrimSpace(v)
			}
		}
		if m["Status"] == "install ok installed" && m["Package"] != "" && m["Version"] != "" {
			// Source is "name" or "name (version)", absent when equal to Package.
			src, ver, _ := strings.Cut(m["Source"], " (")
			src, ver = strings.TrimSpace(src), strings.TrimSuffix(ver, ")")
			if kernel, ok := unsignedKernel(src); ok {
				src, ver = kernel, m["Version"] // advisories use the unsigned name and binary version
			}
			out = append(out, Installed{Ecosystem: eco, Package: m["Package"], Version: m["Version"], Source: src, SourceVersion: ver, SourceOnly: true, Path: path})
		}
	}
	return out
}

// parseApkInstalled lists packages from an apk database. Blocks hold one
// field per line; advisories use the origin (source) package name.
func parseApkInstalled(text, eco, path string) []Installed {
	var out []Installed
	for _, block := range strings.Split(text, "\n\n") {
		m := map[string]string{}
		for _, l := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && len(k) == 1 {
				m[k] = v
			}
		}
		if m["P"] != "" && m["V"] != "" {
			out = append(out, Installed{Ecosystem: eco, Package: m["P"], Version: m["V"], Source: m["o"], SourceOnly: true, Path: path})
		}
	}
	return out
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
		out = parseDpkgStatus(string(r.Data), eco, "/var/lib/dpkg/status")
		return out, r.Complete && len(out) > 0
	}
	if strings.HasPrefix(eco, "Alpine:") {
		r, e := s.ReadFile(ctx, "/lib/apk/db/installed")
		if e != nil {
			return nil, false
		}
		out = parseApkInstalled(string(r.Data), eco, "/lib/apk/db/installed")
		return out, r.Complete && len(out) > 0
	}
	if strings.HasPrefix(eco, "AlmaLinux:") || strings.HasPrefix(eco, "Rocky Linux:") {
		v, e := s.Run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{MODULARITYLABEL}\n")
		if e != nil {
			return nil, false
		}
		for _, l := range strings.Split(v, "\n") {
			f := strings.Split(l, "\t")
			if len(f) >= 2 && f[0] != "" && f[1] != "" {
				i := Installed{Ecosystem: eco, Package: f[0], Version: f[1], Path: "rpm database"}
				if len(f) >= 3 {
					i.Source, i.SourceVersion = rpmSource(f[2])
				}
				if len(f) == 4 {
					if p := strings.Split(f[3], ":"); len(p) >= 2 {
						i.Stream = p[0] + ":" + p[1]
					}
				}
				out = append(out, i)
			}
		}
		resolveRPMSources(out)
		return out, len(out) > 0
	}
	return nil, false
}

// appRoots hold applications outside any web server document root. Only
// lockfiles and the library files WebInventory names are opened, and only
// package names and versions are kept.
var appRoots = []string{"/srv", "/opt"}

var wpVersion = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)
var jqVersion = regexp.MustCompile(`(?i)jquery(?: javascript library)?[ -]+v?(\d+\.\d+\.\d+)`)

func WebInventory(ctx context.Context, s sys.System) ([]Installed, bool) {
	roots := DocRoots(ctx, s)
	docRoots := len(roots)
	for _, r := range appRoots {
		if fi, e := s.Stat(r); e == nil && fi.IsDir {
			roots = append(roots, r)
		}
	}
	if len(roots) == 0 {
		return nil, false
	}
	var out []Installed
	complete := true
	seen := map[string]bool{}
	for n, root := range roots {
		limit := 5000
		if n >= docRoots {
			limit = 50000
		}
		w, e := s.Walk(ctx, root, limit)
		if e != nil || !w.Complete {
			complete = false
		}
		for _, fi := range w.Files {
			p := fi.Path
			if seen[p] {
				continue
			}
			seen[p] = true
			base := filepath.Base(p)
			if base != "composer.lock" && base != "package-lock.json" && base != "version.php" && !strings.HasPrefix(base, "jquery") && !extraLockfiles[base] {
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
			if extraLockfiles[base] {
				items, ok := ParseLockfile(base, p, r.Data)
				complete = complete && ok
				out = append(out, items...)
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
					out = append(out, Installed{Ecosystem: "Packagist", Package: a.Name, Version: strings.TrimPrefix(a.Version, "v"), Path: p})
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
					out = append(out, Installed{Ecosystem: "npm", Package: n, Version: a.Version, Path: p})
				}
				for n, a := range x.Packages {
					if strings.HasPrefix(n, "node_modules/") {
						out = append(out, Installed{Ecosystem: "npm", Package: strings.TrimPrefix(n, "node_modules/"), Version: a.Version, Path: p})
					}
				}
			case "version.php":
				if m := wpVersion.FindSubmatch(r.Data); m != nil {
					out = append(out, Installed{Ecosystem: "WordPress:Core", Package: "wordpress", Version: string(m[1]), Path: p})
				} else {
					complete = false
				}
			default:
				if m := jqVersion.FindSubmatch(r.Data); m != nil {
					out = append(out, Installed{Ecosystem: "npm", Package: "jquery", Version: string(m[1]), Path: p, Heuristic: true})
				}
			}
		}
	}
	return out, complete
}
