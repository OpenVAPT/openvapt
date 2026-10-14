package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// MaxSuppressFileSize caps how much of a suppression file is read.
const MaxSuppressFileSize = 1 << 20

// MaxSuppressDays is how far ahead an entry may expire. Every suppression
// must be reviewed at least once a year.
const MaxSuppressDays = 365

// SuppressEntry is one line of a suppression file, in the spirit of the
// Grype and Trivy ignore files, but with a reason and an expiry required.
type SuppressEntry struct {
	ID      string `json:"id"`                 // check id, required
	Target  string `json:"target,omitempty"`   // exact target or glob; empty means every target
	Reason  string `json:"reason"`             // required, non-empty
	Expires string `json:"expires"`            // required, YYYY-MM-DD, inclusive
	AddedBy string `json:"added_by,omitempty"` // optional
}

// Suppressions is a validated suppression file.
type Suppressions struct {
	Path    string
	SHA256  string
	Active  []SuppressEntry
	Expired []SuppressEntry // ignored, listed as a warning
}

// SuppressionInfo is written into the report header so a reader always
// knows suppressions were used, from which file and how many applied.
type SuppressionInfo struct {
	File       string   `json:"file"`
	SHA256     string   `json:"sha256"`
	Entries    int      `json:"entries"`    // active entries in the file
	Suppressed int      `json:"suppressed"` // failed results suppressed in this report
	Expired    []string `json:"expired,omitempty"`
}

// Suppressed records why one failed result of a finding was suppressed.
// The result keeps its original status; nothing is dropped.
type Suppressed struct {
	Target  string `json:"target"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	AddedBy string `json:"added_by,omitempty"`
}

// LoadSuppressions reads and validates a suppression file with the same
// bounded regular-file reader the report loader uses. now decides which
// entries have expired.
func LoadSuppressions(p string, now time.Time) (*Suppressions, error) {
	b, err := sys.ReadLocalFile(p, MaxSuppressFileSize)
	if errors.Is(err, sys.ErrTooLarge) {
		return nil, errors.New("suppression file is too large")
	}
	if err != nil {
		return nil, err
	}
	return ParseSuppressions(p, b, now)
}

// ParseSuppressions validates the bytes of a suppression file.
func ParseSuppressions(name string, b []byte, now time.Time) (*Suppressions, error) {
	if err := checkKeys(b); err != nil {
		return nil, fmt.Errorf("%s: %v", name, strings.Replace(err.Error(), "OpenVAPT report", "suppression file", 1))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var list []SuppressEntry
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("%s is not a suppression file (a JSON list of entries): %w", name, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: trailing data after the list", name)
	}
	sum := sha256.Sum256(b)
	s := &Suppressions{Path: name, SHA256: hex.EncodeToString(sum[:])}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	limit := today.AddDate(0, 0, MaxSuppressDays)
	for i, e := range list {
		n := i + 1
		if strings.TrimSpace(e.ID) == "" {
			return nil, fmt.Errorf("%s entry %d: id is required", name, n)
		}
		if check.Get(e.ID) == nil {
			return nil, fmt.Errorf("%s entry %d: unknown check id %q (see 'openvapt checks')", name, n, e.ID)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("%s entry %d (%s): reason is required", name, n, e.ID)
		}
		if e.Expires == "" {
			return nil, fmt.Errorf("%s entry %d (%s): expires is required (YYYY-MM-DD)", name, n, e.ID)
		}
		exp, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			return nil, fmt.Errorf("%s entry %d (%s): expires must be a date in YYYY-MM-DD form, got %q", name, n, e.ID, e.Expires)
		}
		if exp.After(limit) {
			return nil, fmt.Errorf("%s entry %d (%s): expires %s is more than %d days ahead; review suppressions at least once a year", name, n, e.ID, e.Expires, MaxSuppressDays)
		}
		if e.Target != "" {
			if _, err := path.Match(e.Target, ""); err != nil {
				return nil, fmt.Errorf("%s entry %d (%s): target %q is not a valid pattern", name, n, e.ID, e.Target)
			}
		}
		if exp.Before(today) {
			s.Expired = append(s.Expired, e)
			continue
		}
		s.Active = append(s.Active, e)
	}
	return s, nil
}

// match returns the first active entry that covers a failed result.
func (s *Suppressions) match(id, target string) *SuppressEntry {
	for i := range s.Active {
		e := &s.Active[i]
		if e.ID != id {
			continue
		}
		if e.Target == "" || e.Target == target {
			return e
		}
		if ok, _ := path.Match(e.Target, target); ok {
			return e
		}
	}
	return nil
}

// ApplySuppressions marks matching failed results as suppressed and states
// the file in the report header. Status, severity and the summary counts
// are not changed: a suppression is visible, never silent.
func (r *Report) ApplySuppressions(s *Suppressions) {
	if s == nil {
		return
	}
	info := &SuppressionInfo{File: filepath.Base(s.Path), SHA256: s.SHA256, Entries: len(s.Active)} // file name only: a full path can name the user
	for _, e := range s.Expired {
		info.Expired = append(info.Expired, e.ID+" (expired "+e.Expires+")")
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		f.Suppressed = nil
		for _, res := range f.Results {
			if res.Status != check.Fail {
				continue
			}
			if e := s.match(f.ID, res.Target); e != nil {
				f.Suppressed = append(f.Suppressed, Suppressed{Target: res.Target, Reason: e.Reason, Expires: e.Expires, AddedBy: e.AddedBy})
				info.Suppressed++
			}
		}
	}
	r.Suppression = info
}

// SuppressionFor returns the suppression covering one result, if any.
func (f Finding) SuppressionFor(res check.Result) *Suppressed {
	if res.Status != check.Fail {
		return nil
	}
	for i := range f.Suppressed {
		if f.Suppressed[i].Target == res.Target {
			return &f.Suppressed[i]
		}
	}
	return nil
}

// FullySuppressed reports whether every failed result of a failed finding
// is suppressed, so the finding does not count toward --fail-on.
func (f Finding) FullySuppressed() bool {
	if f.Status != string(check.Fail) || len(f.Suppressed) == 0 {
		return false
	}
	for _, res := range f.Results {
		if res.Status == check.Fail && f.SuppressionFor(res) == nil {
			return false
		}
	}
	return true
}

// SuppressedRow is one suppressed result, for the report sections.
type SuppressedRow struct {
	ID, Title, Severity string
	Suppressed
}

// SuppressedRows lists every suppressed result for the report sections.
func (r *Report) SuppressedRows() []SuppressedRow {
	var out []SuppressedRow
	for _, f := range r.Findings {
		for _, s := range f.Suppressed {
			out = append(out, SuppressedRow{ID: f.ID, Title: f.Title, Severity: f.Severity, Suppressed: s})
		}
	}
	return out
}

// SuppressionNotice is the one-line header statement, empty when no
// suppression file was used.
func (r *Report) SuppressionNotice() string {
	si := r.Suppression
	if si == nil {
		return ""
	}
	n := fmt.Sprintf("Suppressions: %d failed result(s) suppressed by %s (sha256 %s, %d active entries). Suppressed results keep their status and are listed under Suppressed Findings.", si.Suppressed, si.File, si.SHA256, si.Entries)
	if len(si.Expired) > 0 {
		n += " Expired entries ignored: " + strings.Join(si.Expired, ", ") + "."
	}
	return n
}
