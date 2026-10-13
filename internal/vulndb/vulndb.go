package vulndb

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

//go:embed data/snapshot.json.gz
var files embed.FS

type Source struct {
	Name    string
	URL     string
	Licence string
}
type Counts struct {
	Advisories int
	Affected   int
}
type Header struct {
	Schema    int
	Generated string
	Fixture   bool
	Sources   []Source
	Counts    Counts
}
type Event struct {
	Introduced string
	Fixed      string
}
type Range struct {
	Type   string
	Events []Event
}
type Affected struct {
	Ecosystem string
	Package   string
	Ranges    []Range
	Versions  []string
}
type Advisory struct {
	ID         string
	Aliases    []string
	Summary    string
	Severity   string
	CVSSScore  float64
	CVSSVector string
	Published  string
	Modified   string
	References []string
	KEV        bool
	Affected   []Affected
}
type Snapshot struct {
	Header     Header
	Advisories []Advisory
}

func Embedded() (Snapshot, error) {
	b, e := files.ReadFile("data/snapshot.json.gz")
	if e != nil {
		return Snapshot{}, e
	}
	return Decode(bytes.NewReader(b))
}
func Decode(r io.Reader) (Snapshot, error) {
	z, e := gzip.NewReader(r)
	if e != nil {
		return Snapshot{}, e
	}
	defer z.Close()
	var s Snapshot
	e = json.NewDecoder(io.LimitReader(z, 64<<20)).Decode(&s)
	if e != nil {
		return s, e
	}
	if s.Header.Schema != 1 {
		return s, errors.New("unsupported vulnerability snapshot schema")
	}
	return s, nil
}
func (s Snapshot) Age(now time.Time) (bool, error) {
	d, e := time.Parse("2006-01-02", s.Header.Generated)
	if e != nil {
		return true, e
	}
	return s.Header.Fixture || now.UTC().Sub(d) > 90*24*time.Hour, nil
}
func (s Snapshot) Notice() string {
	n := "Snapshot date " + s.Header.Generated + ". An outdated snapshot misses newer vulnerabilities."
	if s.Header.Fixture {
		n += " Test fixture data - coverage is deliberately limited."
	}
	return n
}
func (s Snapshot) Match(ecosystem, packageName, version string) []Advisory {
	var out []Advisory
	for _, a := range s.Advisories {
		for _, p := range a.Affected {
			if p.Ecosystem != ecosystem || p.Package != packageName {
				continue
			}
			if affected(p, version) {
				out = append(out, a)
				break
			}
		}
	}
	return out
}
func affected(a Affected, v string) bool {
	for _, x := range a.Versions {
		if x == v {
			return true
		}
	}
	for _, r := range a.Ranges {
		cmp := comparator(a.Ecosystem, r.Type)
		if cmp == nil {
			continue
		}
		open := false
		for _, ev := range r.Events {
			if ev.Introduced != "" {
				open = ev.Introduced == "0" || cmp(v, ev.Introduced) >= 0
			}
			if ev.Fixed != "" && open && cmp(v, ev.Fixed) >= 0 {
				open = false
			}
		}
		if open {
			return true
		}
	}
	return false
}
func comparator(eco, kind string) func(string, string) int {
	if kind != "ECOSYSTEM" && kind != "SEMVER" {
		return nil
	}
	switch {
	case strings.HasPrefix(eco, "Debian:"), strings.HasPrefix(eco, "Ubuntu:"):
		return DebianCompare
	case strings.HasPrefix(eco, "AlmaLinux:"), strings.HasPrefix(eco, "Rocky Linux:"):
		return RPMCompare
	case eco == "npm", eco == "Packagist":
		return SemverCompare
	}
	return nil
}
