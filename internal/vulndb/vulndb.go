package vulndb

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"sort"
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

// Event is one OSV range event. Exactly one field is normally set.
type Event struct {
	Introduced   string
	Fixed        string
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
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
		if a.Ecosystem == "Packagist" && strings.HasPrefix(strings.ToLower(v), "dev-") {
			continue // a branch name has no place on a version line
		}
		if rangeAffects(r.Events, v, cmp) {
			return true
		}
	}
	return false
}

// eventVersion returns the version an event refers to and its kind.
func eventVersion(e Event) (string, string) {
	switch {
	case e.Introduced != "":
		return e.Introduced, "introduced"
	case e.Fixed != "":
		return e.Fixed, "fixed"
	case e.LastAffected != "":
		return e.LastAffected, "last_affected"
	case e.Limit != "":
		return e.Limit, "limit"
	}
	return "", ""
}

// rangeAffects implements the OSV evaluation algorithm: sort the events by
// version with the ecosystem comparator, then v is affected when the last
// event at or below v is "introduced" (a "last_affected" event closes the
// range only for versions above it). "limit" events bound the range from
// above. See https://ossf.github.io/osv-schema/#evaluation
func rangeAffects(events []Event, v string, cmp func(string, string) int) bool {
	type ev struct{ ver, kind string }
	var evs, limits []ev
	for _, e := range events {
		ver, kind := eventVersion(e)
		switch kind {
		case "":
			continue
		case "limit":
			limits = append(limits, ev{ver, kind})
		default:
			evs = append(evs, ev{ver, kind})
		}
	}
	vcmp := func(a, b string) int {
		if a == b {
			return 0
		}
		if a == "0" {
			return -1
		}
		if b == "0" {
			return 1
		}
		return cmp(a, b)
	}
	sort.SliceStable(evs, func(i, j int) bool { return vcmp(evs[i].ver, evs[j].ver) < 0 })
	if len(limits) > 0 {
		under := false
		for _, l := range limits {
			if l.ver == "*" || vcmp(v, l.ver) < 0 {
				under = true
				break
			}
		}
		if !under {
			return false
		}
	}
	affected := false
	for _, e := range evs {
		switch e.kind {
		case "introduced":
			if vcmp(v, e.ver) >= 0 {
				affected = true
			}
		case "fixed":
			if vcmp(v, e.ver) >= 0 {
				affected = false
			}
		case "last_affected":
			if vcmp(v, e.ver) > 0 {
				affected = false
			}
		}
	}
	return affected
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
	case eco == "npm":
		return SemverCompare
	case eco == "Packagist":
		return ComposerCompare
	}
	return nil
}
