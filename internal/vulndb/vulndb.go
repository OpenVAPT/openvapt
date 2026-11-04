package vulndb

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
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
	// Streams names the module streams (nodejs:14) an erratum is for.
	Streams []string `json:",omitempty"`
}
type Snapshot struct {
	Header     Header
	Advisories []Advisory

	// index maps ecosystem + package to the positions of the advisories
	// that name it, so Match never scans the whole snapshot. It is built
	// once by Decode and shared read-only between copies of the Snapshot.
	index map[string][]int
}

// Matcher names how a version was matched, in the style of other
// vulnerability scanners, so a reader can weigh the evidence.
const (
	MatcherExact = "exact version"
	MatcherRange = "range"
)

// Match is one advisory that applies to a package version, with the way
// the version was matched.
type Match struct {
	Advisory Advisory
	Matcher  string
}

var (
	embeddedOnce sync.Once
	embeddedSnap Snapshot
	embeddedErr  error
)

// Embedded returns the snapshot compiled into the binary. It is decoded and
// indexed once; every CVE check shares the same copy.
func Embedded() (Snapshot, error) {
	embeddedOnce.Do(func() {
		b, e := files.ReadFile("data/snapshot.json.gz")
		if e != nil {
			embeddedErr = e
			return
		}
		embeddedSnap, embeddedErr = Decode(bytes.NewReader(b))
	})
	return embeddedSnap, embeddedErr
}

// maxSnapshot caps uncompressed snapshot bytes; a full build is about 105 MiB.
const maxSnapshot = 256 << 20

// Decode reads a gzip-compressed JSON snapshot.
func Decode(r io.Reader) (Snapshot, error) {
	z, e := gzip.NewReader(r)
	if e != nil {
		return Snapshot{}, e
	}
	defer z.Close()
	return DecodeJSON(io.LimitReader(z, maxSnapshot))
}

// DecodeJSON reads an uncompressed JSON snapshot (the simulated labs carry
// one in memory) and builds the package index.
func DecodeJSON(r io.Reader) (Snapshot, error) {
	s, e := decode(r, false)
	if e != nil {
		return s, e
	}
	s.buildIndex()
	return s, nil
}

// decode reads advisories one at a time, so the decoder buffers one record
// and not the whole file: a full snapshot must load on a small server.
// headerOnly stops at the header, which the generator writes first.
func decode(r io.Reader, headerOnly bool) (Snapshot, error) {
	var s Snapshot
	// A tighter collector for the load keeps the peak low on small servers.
	defer debug.SetGCPercent(debug.SetGCPercent(25))
	strs := map[string]string{}
	intern := func(v string) string {
		if c, ok := strs[v]; ok {
			return c
		}
		strs[v] = v
		return v
	}
	d := json.NewDecoder(io.LimitReader(r, maxSnapshot))
	if _, e := d.Token(); e != nil {
		return s, e
	}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return s, e
		}
		name, _ := key.(string)
		switch {
		case strings.EqualFold(name, "Header"):
			if e = d.Decode(&s.Header); e != nil {
				return s, e
			}
			if s.Header.Schema != 1 {
				return s, errors.New("unsupported vulnerability snapshot schema")
			}
			if headerOnly {
				return s, nil
			}
		case strings.EqualFold(name, "Advisories"):
			t, e := d.Token()
			if e != nil {
				return s, unexpected(e)
			}
			if t != json.Delim('[') { // null
				continue
			}
			for d.More() {
				var a Advisory
				if e = d.Decode(&a); e != nil {
					return s, unexpected(e)
				}
				for i := range a.Affected { // these repeat across hundreds of thousands of rows
					x := &a.Affected[i]
					x.Ecosystem, x.Package = intern(x.Ecosystem), intern(x.Package)
					for j := range x.Ranges {
						x.Ranges[j].Type = intern(x.Ranges[j].Type)
					}
				}
				a.Severity = intern(a.Severity)
				s.Advisories = append(s.Advisories, a)
			}
			if _, e = d.Token(); e != nil { // ]
				return s, unexpected(e)
			}
		default:
			var skip json.RawMessage
			if e = d.Decode(&skip); e != nil {
				return s, e
			}
		}
	}
	// A cut file must never load as a smaller clean snapshot: that would turn
	// missing advisories into a Pass.
	if _, e := d.Token(); e != nil { // }
		return s, unexpected(e)
	}
	if s.Header.Schema != 1 {
		return s, errors.New("unsupported vulnerability snapshot schema")
	}
	return s, nil
}

func unexpected(e error) error {
	if e == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return e
}

// EmbeddedHeader reads only the embedded snapshot's header, for commands
// that do not match anything.
func EmbeddedHeader() (Header, error) {
	b, e := files.ReadFile("data/snapshot.json.gz")
	if e != nil {
		return Header{}, e
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		return Header{}, e
	}
	defer z.Close()
	s, e := decode(z, true)
	return s.Header, e
}

func indexKey(eco, pkg string) string { return eco + "\x00" + pkg }

// Covers reports whether the snapshot holds advisories for exactly this
// ecosystem. An uncovered host must report Incomplete, never a clean Pass.
func (s Snapshot) Covers(ecosystem string) bool {
	for _, a := range s.Advisories {
		for _, p := range a.Affected {
			if p.Ecosystem == ecosystem {
				return true
			}
		}
	}
	return false
}

func (s *Snapshot) buildIndex() {
	s.index = make(map[string][]int, len(s.Advisories))
	for i, a := range s.Advisories {
		seen := map[string]bool{}
		for _, p := range a.Affected {
			k := indexKey(p.Ecosystem, p.Package)
			if !seen[k] {
				seen[k] = true
				s.index[k] = append(s.index[k], i)
			}
		}
	}
}

// HasEcosystem reports whether any advisory in the snapshot names an
// ecosystem equal to, or starting with, prefix (for example "WordPress").
// A check that inventories an ecosystem the snapshot never covers must
// report Incomplete, not Pass.
func (s Snapshot) HasEcosystem(prefix string) bool {
	for _, a := range s.Advisories {
		for _, p := range a.Affected {
			if strings.HasPrefix(p.Ecosystem, prefix) {
				return true
			}
		}
	}
	return false
}

// AgeDays returns how many days old the snapshot is at now, or -1 when the
// generation date cannot be parsed.
func (s Snapshot) AgeDays(now time.Time) int {
	d, e := time.Parse("2006-01-02", s.Header.Generated)
	if e != nil {
		return -1
	}
	return int(now.UTC().Sub(d).Hours() / 24)
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

// Match returns every advisory that applies to the package version, with
// the matcher that decided it.
func (s Snapshot) Match(ecosystem, packageName, version string) []Match {
	var out []Match
	visit := func(a Advisory) {
		for _, p := range a.Affected {
			if p.Ecosystem != ecosystem || p.Package != packageName {
				continue
			}
			if how, ok := affectedBy(p, version); ok {
				out = append(out, Match{Advisory: a, Matcher: how})
				break
			}
		}
	}
	if s.index != nil {
		for _, i := range s.index[indexKey(ecosystem, packageName)] {
			visit(s.Advisories[i])
		}
		return out
	}
	for _, a := range s.Advisories {
		visit(a)
	}
	return out
}

// MatchStream is Match for a package built from a module stream: an erratum
// for another stream does not apply. An empty stream means not known.
func (s Snapshot) MatchStream(ecosystem, packageName, version, stream string) []Match {
	ms := s.Match(ecosystem, packageName, version)
	if stream == "" {
		return ms
	}
	out := ms[:0]
	for _, m := range ms {
		if len(m.Advisory.Streams) == 0 || slices.Contains(m.Advisory.Streams, stream) {
			out = append(out, m)
		}
	}
	return out
}

// FixedVersion returns the first fix above version for the package, from the
// ranges that apply to it, or "" when none is published.
func FixedVersion(a Advisory, ecosystem, packageName, version string) string {
	best := ""
	for _, p := range a.Affected {
		if p.Ecosystem != ecosystem || p.Package != packageName {
			continue
		}
		for _, r := range p.Ranges {
			cmp := comparator(p.Ecosystem, r.Type)
			if cmp == nil {
				continue
			}
			if otherModuleStream(r, version) || !rangeAffects(r.Events, version, cmp) {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" && cmp(e.Fixed, version) > 0 && (best == "" || cmp(e.Fixed, best) < 0) {
					best = e.Fixed
				}
			}
		}
	}
	return best
}

// CVEs returns the CVE names an advisory stands for, so one flaw published by
// several sources (DSA and DEBIAN-CVE, USN and UBUNTU-CVE) can be told apart
// from a new one.
func CVEs(a Advisory) []string {
	var out []string
	for _, id := range append([]string{a.ID}, a.Aliases...) {
		if i := strings.Index(id, "CVE-"); i >= 0 {
			out = append(out, id[i:])
		}
	}
	return out
}

// Advisories returns only the advisories of Match.
func Advisories(ms []Match) []Advisory {
	out := make([]Advisory, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Advisory)
	}
	return out
}

func affected(a Affected, v string) bool {
	_, ok := affectedBy(a, v)
	return ok
}

func affectedBy(a Affected, v string) (string, bool) {
	for _, x := range a.Versions {
		if x == v {
			return MatcherExact, true
		}
	}
	for _, r := range a.Ranges {
		cmp := comparator(a.Ecosystem, r.Type)
		if cmp == nil {
			continue
		}
		if otherModuleStream(r, v) {
			continue
		}
		if a.Ecosystem == "Packagist" && strings.HasPrefix(strings.ToLower(v), "dev-") {
			continue // a branch name has no place on a version line
		}
		if rangeAffects(r.Events, v, cmp) {
			return MatcherRange, true
		}
	}
	return "", false
}

// eventVersion returns the version an event refers to and its kind.
// otherModuleStream reports a Rocky or AlmaLinux range fixed by a module build
// (nodejs:14) that cannot apply to version v: v is not a module build, or has
// a different leading version number. OSV ranges name no stream, so every
// older stream would otherwise fall below a newer stream's fix. Streams that
// share a leading number (php:7.2, php:7.4) are not told apart.
func otherModuleStream(r Range, v string) bool {
	for _, e := range r.Events {
		if strings.Contains(e.Fixed, ".module") {
			return !strings.Contains(v, ".module") || leadingNumber(e.Fixed) != leadingNumber(v)
		}
	}
	return false
}

// leadingNumber returns the first version component, without any epoch.
func leadingNumber(v string) string {
	if _, rest, ok := strings.Cut(v, ":"); ok {
		v = rest
	}
	n, _, _ := strings.Cut(v, ".")
	return n
}

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
	case strings.HasPrefix(eco, "Alpine:"):
		return AlpineCompare
	case eco == "npm", eco == "Go", eco == "crates.io":
		return SemverCompare
	case eco == "PyPI":
		return PEP440Compare
	case eco == "RubyGems":
		return GemCompare
	case eco == "Packagist":
		return ComposerCompare
	case eco == "WordPress" || strings.HasPrefix(eco, "WordPress:"):
		return WordPressCompare
	}
	return nil
}
