package host

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// Shared read-only helpers for the audit, PAM, package and legacy service
// checks. They tell a check apart three situations that need three different
// outcomes: the evidence was read (Pass or Fail), the file does not exist
// (Skip or Fail, depending on the check), and the file exists but could not
// be read or was truncated (always Incomplete, never Pass).

type fileState int

const (
	fileRead       fileState = iota // read completely
	fileMissing                     // does not exist
	fileUnreadable                  // exists but could not be read in full
)

// readState reads one file and classifies the outcome.
func readState(ctx context.Context, s sys.System, path string) (string, fileState) {
	r, err := s.ReadFile(ctx, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fileMissing
		}
		return "", fileUnreadable
	}
	if !r.Complete {
		return string(r.Data), fileUnreadable
	}
	return string(r.Data), fileRead
}

// textFile is one configuration file that was read completely.
type textFile struct {
	Path, Text string
}

// readAll reads every existing file matching the patterns (literal paths or
// globs) and returns the files read plus the paths that exist but could not
// be read. Missing literal paths are not an error.
func readAll(ctx context.Context, s sys.System, patterns ...string) (files []textFile, unreadable []string) {
	seen := map[string]bool{}
	var paths []string
	for _, p := range patterns {
		if strings.ContainsAny(p, "*?[") {
			m, _ := s.Glob(p)
			sort.Strings(m)
			for _, x := range m {
				if !seen[x] {
					seen[x] = true
					paths = append(paths, x)
				}
			}
			continue
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for _, p := range paths {
		text, st := readState(ctx, s, p)
		switch st {
		case fileRead:
			files = append(files, textFile{Path: p, Text: text})
		case fileUnreadable:
			unreadable = append(unreadable, p)
		}
	}
	return files, unreadable
}

// activeLines returns the non-empty, non-comment lines of a file, trimmed.
func activeLines(text string) []string {
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// exists reports whether a path exists (any type).
func exists(s sys.System, path string) bool {
	_, err := s.Stat(path)
	return err == nil
}

// ---------- installed packages ----------

// pkg is one installed package.
type pkg struct {
	Name, Version string
}

// installedPackages lists installed packages from three read-only sources:
// the dpkg status file, the dpkg info directory (one .list file per
// installed package) and the rpm database (rpm -qa, allow-listed). ok is
// false when none of the sources gave any data, so callers return
// Incomplete rather than Pass.
func installedPackages(ctx context.Context, s sys.System) ([]pkg, bool) {
	var out []pkg
	seen := map[string]bool{}
	add := func(name, ver string) {
		key := name + "\t" + ver
		if name == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, pkg{Name: name, Version: ver})
	}
	ok := false
	if text, st := readState(ctx, s, "/var/lib/dpkg/status"); st == fileRead {
		ok = true
		for _, block := range strings.Split(text, "\n\n") {
			m := map[string]string{}
			for _, l := range strings.Split(block, "\n") {
				if k, v, found := strings.Cut(l, ":"); found && !strings.HasPrefix(l, " ") {
					m[k] = strings.TrimSpace(v)
				}
			}
			if m["Status"] == "install ok installed" && m["Package"] != "" {
				add(m["Package"], m["Version"])
			}
		}
	}
	// The dpkg status file is the source of truth on Debian-family systems:
	// a package removed but not purged ("rc") keeps its *.list file, so the
	// .list fallback is used only when the status file could not be read.
	if lists, _ := s.Glob("/var/lib/dpkg/info/*.list"); !ok && len(lists) > 0 {
		ok = true
		sort.Strings(lists)
		for _, p := range lists {
			name := strings.TrimSuffix(filepath.Base(p), ".list")
			if i := strings.Index(name, ":"); i > 0 {
				name = name[:i] // libc6:amd64 -> libc6
			}
			add(name, "")
		}
	}
	if v, err := s.Run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"); err == nil {
		for _, l := range strings.Split(v, "\n") {
			if f := strings.Split(l, "\t"); len(f) == 2 && f[0] != "" {
				ok = true
				add(f[0], f[1])
			}
		}
	}
	return out, ok
}

// packagesPresent returns which of the named packages are installed, in the
// order given.
func packagesPresent(pkgs []pkg, names ...string) []string {
	have := map[string]bool{}
	for _, p := range pkgs {
		have[p.Name] = true
	}
	var out []string
	for _, n := range names {
		if have[n] {
			out = append(out, n)
		}
	}
	return out
}

// kernelVersions lists the versions of installed kernel packages:
// linux-image-<version> on Debian and Ubuntu, kernel or kernel-core with a
// version-release on the RHEL family. Meta packages (linux-image-generic)
// and debug images are ignored.
func kernelVersions(pkgs []pkg) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, p := range pkgs {
		switch {
		case strings.HasPrefix(p.Name, "linux-image-") && !strings.Contains(p.Name, "-dbg"):
			v := strings.TrimPrefix(p.Name, "linux-image-")
			if v != "" && v[0] >= '0' && v[0] <= '9' {
				add(v)
			}
		case p.Name == "kernel" || p.Name == "kernel-core":
			v := p.Version
			if i := strings.Index(v, ":"); i >= 0 {
				v = v[i+1:] // drop the epoch
			}
			add(v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return kernelLess(out[i], out[j]) })
	return out
}

// kernelLess orders kernel version strings such as 6.8.0-45-generic or
// 5.14.0-427.el9 by comparing their dot- and dash-separated parts, numerically
// where both parts are numbers.
func kernelLess(a, b string) bool {
	split := func(v string) []string {
		return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' })
	}
	as, bs := split(a), split(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		x, xok := atoi(as[i])
		y, yok := atoi(bs[i])
		if xok && yok {
			return x < y
		}
		return as[i] < bs[i]
	}
	return len(as) < len(bs)
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// ---------- systemd enablement ----------

// enabledUnits reports which of the named units start at boot. It reads the
// *.wants links under /etc/systemd/system first and asks systemctl
// is-enabled (allow-listed) only for units not found there.
func enabledUnits(ctx context.Context, s sys.System, names ...string) []string {
	wanted := map[string]bool{}
	if links, _ := s.Glob("/etc/systemd/system/*.wants/*"); len(links) > 0 {
		for _, l := range links {
			wanted[filepath.Base(l)] = true
		}
	}
	var out []string
	for _, n := range names {
		if wanted[n] {
			out = append(out, n)
			continue
		}
		if o, err := s.Run(ctx, "systemctl", "is-enabled", n); err == nil && strings.TrimSpace(o) == "enabled" {
			out = append(out, n)
		}
	}
	return out
}
