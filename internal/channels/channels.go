// Package channels is OpenVAPT's release channel model: one codebase moves
// through Alpha, Beta, Release Candidate and Stable, and a build is promoted
// to the next channel only when every gate for that channel passes.
//
// The gates are decided by evidence, not by opinion: CI results, the
// simulated lab, the installer test, release signing, time spent in the
// previous channel and the AI legal reviewer's record. The state of every
// channel and the full promotion history live in release/channels.json, so
// each promotion is traceable to the evidence that allowed it, as an
// assessment record should be (NIST SP 800-115, reporting and records).
package channels

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Channel is one release channel.
type Channel string

const (
	Alpha  Channel = "alpha"
	Beta   Channel = "beta"
	RC     Channel = "rc"
	Stable Channel = "stable"
	Dev    Channel = "dev" // a local build that was never promoted
)

// Order lists the channels from least to most mature.
var Order = []Channel{Alpha, Beta, RC, Stable}

// Info describes a channel for people.
type Info struct {
	ID       Channel
	Name     string
	Audience string
	Meaning  string
	SoakDays int // minimum days the build must spend in the previous channel
}

// Infos describes each channel in order.
var Infos = []Info{
	{Alpha, "Alpha", "Contributors and AI agents", "Every change that passes CI. Incomplete and may be wrong; for testing the project itself.", 0},
	{Beta, "Beta", "Early testers on test machines", "An alpha that passed the full lab, the legal review and at least 7 days without regressions.", 7},
	{RC, "Release Candidate", "Testers preparing to rely on it", "A beta that is signed, has provenance and an SBOM, installs cleanly, and spent at least 7 days in beta.", 7},
	{Stable, "Stable", "Everyone, for their own use", "A release candidate that spent at least 14 days without regressions and has the legal reviewer's sign-off for public release.", 14},
}

// InfoFor returns the description of a channel.
func InfoFor(c Channel) Info {
	for _, i := range Infos {
		if i.ID == c {
			return i
		}
	}
	return Info{ID: c, Name: "Development Build", Audience: "The person who built it", Meaning: "Built from source and never promoted."}
}

// Previous returns the channel a build is promoted from ("" for Alpha).
func Previous(c Channel) Channel {
	for i, x := range Order {
		if x == c && i > 0 {
			return Order[i-1]
		}
	}
	return ""
}

var semver = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$`)

// Of returns the channel a version string belongs to: v1.2.0-alpha.3 is
// Alpha, v1.2.0-rc.1 is RC, v1.2.0 is Stable, anything else is Dev.
func Of(version string) Channel {
	m := semver.FindStringSubmatch(version)
	switch {
	case m == nil:
		return Dev
	case m[4] == "":
		return Stable
	default:
		return Channel(m[4])
	}
}

// Base returns the stable version a pre-release leads to: v1.2.0-rc.1 -> v1.2.0.
func Base(version string) string {
	m := semver.FindStringSubmatch(version)
	if m == nil {
		return ""
	}
	return fmt.Sprintf("v%s.%s.%s", m[1], m[2], m[3])
}

// Release is one build in one channel.
type Release struct {
	Channel  Channel  `json:"channel"`
	Version  string   `json:"version"`
	Commit   string   `json:"commit"`
	Date     string   `json:"date"` // YYYY-MM-DD, UTC
	Decision string   `json:"decision"`
	Evidence []string `json:"evidence"`
}

// State is the content of release/channels.json.
type State struct {
	Schema  string              `json:"schema"`
	Next    string              `json:"next"` // the stable version the current cycle leads to
	Current map[Channel]Release `json:"current"`
	History []Release           `json:"history"`
}

// Load reads a state file.
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is the repository's own release/channels.json
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Current == nil {
		s.Current = map[Channel]Release{}
	}
	if Of(s.Next) != Stable {
		return nil, fmt.Errorf("%s: next must be a stable version such as v0.1.0, got %q", path, s.Next)
	}
	return &s, nil
}

// Save writes a state file with stable formatting.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644) // #nosec G306 -- public, version-controlled release record
}

// Text renders the plain "channel version" list the installer reads, one
// line per released channel, so a shell script never has to parse JSON.
func (s *State) Text() string {
	var b strings.Builder
	b.WriteString("# OpenVAPT release channels: <channel> <version> <commit> <date>\n")
	for _, c := range Order {
		if r, ok := s.Current[c]; ok {
			fmt.Fprintf(&b, "%s %s %s %s\n", c, r.Version, r.Commit, r.Date)
		}
	}
	return b.String()
}

// Highest returns the most mature channel that has a release, or "".
func (s *State) Highest() Channel {
	var h Channel
	for _, c := range Order {
		if _, ok := s.Current[c]; ok {
			h = c
		}
	}
	return h
}

// NextVersion returns the version a promotion to c would publish.
func (s *State) NextVersion(c Channel) string {
	if c == Stable {
		return s.Next
	}
	n := 0
	for _, r := range s.History {
		if r.Channel == c && Base(r.Version) == s.Next {
			if m := semver.FindStringSubmatch(r.Version); m != nil {
				if k, _ := strconv.Atoi(m[5]); k > n {
					n = k
				}
			}
		}
	}
	return fmt.Sprintf("%s-%s.%d", s.Next, c, n+1)
}

// LegalReview is release/legal-review.json, written by the AI legal reviewer.
type LegalReview struct {
	Version              string `json:"version"`
	Reviewed             string `json:"reviewed"`
	Reviewer             string `json:"reviewer"`
	OpenHighRisks        int    `json:"open_high_risks"`
	PublicLaunchApproved bool   `json:"public_launch_approved"`
	Notes                string `json:"notes"`
}

// LoadLegal reads the legal review record.
func LoadLegal(path string) (LegalReview, error) {
	var l LegalReview
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own release/legal-review.json
	if err != nil {
		return l, err
	}
	return l, json.Unmarshal(b, &l)
}

// Evidence is what CI observed for the candidate commit.
type Evidence struct {
	Commit       string
	CIGreen      bool // format, vet, race tests, static analysis, security scan
	LabPass      bool // every check fails on the vulnerable lab and passes on the hardened lab
	InstallerE2E bool // the installer installs a verified build and refuses a tampered one
	Signed       bool // the previous channel's release has Sigstore bundles, provenance and an SBOM
	Legal        LegalReview
	LegalErr     error
	Now          time.Time
}

// Check is one gate condition and its outcome.
type Check struct {
	Name   string
	Passed bool
	Detail string
}

// Gate evaluates every condition for promoting a build to channel c. The
// promotion is allowed only if every check passes; there is no override.
func Gate(s *State, c Channel, e Evidence) (bool, []Check) {
	var out []Check
	add := func(name string, ok bool, detail string) { out = append(out, Check{name, ok, detail}) }

	add("CI Green", e.CIGreen, "format, vet, race tests, static analysis, security and vulnerability scans")
	add("Lab Proof", e.LabPass, "every check fails on the vulnerable lab and passes on the hardened lab")

	prev := Previous(c)
	candidate := e.Commit
	if prev != "" {
		src, ok := s.Current[prev]
		if !ok {
			add("Previous Channel", false, "no "+InfoFor(prev).Name+" release exists yet")
			return false, out
		}
		candidate = src.Commit
		add("Previous Channel", true, InfoFor(prev).Name+" "+src.Version+" at commit "+short(src.Commit))
		if cur, ok := s.Current[c]; ok && cur.Commit == src.Commit {
			add("New Build", false, "this build is already "+InfoFor(c).Name+" "+cur.Version)
		}
		if e.Commit != src.Commit {
			add("Same Build Tested", false, "CI evidence is for commit "+short(e.Commit)+", not the "+InfoFor(prev).Name+" commit "+short(src.Commit))
		}
		if Base(src.Version) != s.Next {
			add("Same Cycle", false, src.Version+" does not belong to the "+s.Next+" cycle")
		}
		days := daysSince(src.Date, e.Now)
		need := InfoFor(c).SoakDays
		add("Soak Time", days >= need, fmt.Sprintf("%d of %d days in %s", days, need, InfoFor(prev).Name))
	} else {
		if cur, ok := s.Current[Alpha]; ok && cur.Commit == e.Commit {
			add("New Build", false, "commit "+short(e.Commit)+" is already Alpha "+cur.Version)
		}
	}
	if candidate == "" {
		add("Candidate Commit", false, "no commit to promote")
	}

	if c == Beta || c == RC || c == Stable {
		promoted := s.Current[prev].Version
		switch {
		case e.LegalErr != nil:
			add("Legal Review", false, "no legal review record: "+e.LegalErr.Error())
		case e.Legal.Version != promoted:
			add("Legal Review", false, "the legal review covers "+e.Legal.Version+", not the build being promoted, "+promoted)
		case e.Legal.OpenHighRisks > 0:
			add("Legal Review", false, fmt.Sprintf("%d open High legal risks", e.Legal.OpenHighRisks))
		default:
			add("Legal Review", true, "reviewed "+e.Legal.Reviewed+" by "+e.Legal.Reviewer)
		}
	}
	if c == RC || c == Stable {
		add("Installer Test", e.InstallerE2E, "verified install succeeds and a tampered binary is refused")
		add("Signed Release", e.Signed, "Sigstore bundles, build provenance and SBOM on the "+InfoFor(prev).Name+" release")
	}
	if c == Stable {
		add("Public Release Sign-Off", e.LegalErr == nil && e.Legal.PublicLaunchApproved, "the AI legal reviewer approved public release")
	}

	ok := true
	for _, x := range out {
		ok = ok && x.Passed
	}
	return ok, out
}

// Promote records a promotion that passed its gate and returns the release.
func (s *State) Promote(c Channel, e Evidence, checks []Check) Release {
	commit := e.Commit
	if p := Previous(c); p != "" {
		commit = s.Current[p].Commit
	}
	r := Release{Channel: c, Version: s.NextVersion(c), Commit: commit, Date: e.Now.UTC().Format("2006-01-02"),
		Decision: "promoted automatically: every gate passed"}
	for _, x := range checks {
		r.Evidence = append(r.Evidence, x.Name+": "+x.Detail)
	}
	s.Current[c] = r
	s.History = append(s.History, r)
	if c == Stable {
		s.Next = bumpMinor(s.Next)
	}
	return r
}

func bumpMinor(v string) string {
	m := semver.FindStringSubmatch(v)
	minor, _ := strconv.Atoi(m[2])
	return fmt.Sprintf("v%s.%d.0", m[1], minor+1)
}

func daysSince(date string, now time.Time) int {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return 0
	}
	return int(now.UTC().Sub(t).Hours() / 24)
}

func short(c string) string { return c[:min(12, len(c))] }
