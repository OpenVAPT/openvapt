package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
)

// Confidence levels say how firmly the evidence supports a check outcome.
const (
	ConfidenceHigh   = "high"   // read from configuration or an exact version
	ConfidenceMedium = "medium" // a heuristic match, such as a version read from a file header
	ConfidenceLow    = "low"    // part of the input could not be read
)

// FalsePositiveURL is the issue form for reporting a wrong finding, and
// SuppressionDocsURL explains how to accept a finding with an expiry date.
const (
	FalsePositiveURL   = "https://github.com/OpenVAPT/openvapt/issues/new?template=false-positive.yml"
	SuppressionDocsURL = "https://github.com/OpenVAPT/openvapt#suppressing-accepted-findings"
)

// FalsePositiveHint is printed under every failed finding.
const FalsePositiveHint = "If you believe this is a false positive, report it with the False Positive form (" + FalsePositiveURL + "), or accept it with an expiry date in a suppression file (" + SuppressionDocsURL + ")."

// ConfidenceFor derives a confidence level from the result data a check
// already produced: Incomplete or Error siblings mean partial reads (Low),
// a heuristic matcher label or a check that calls itself a heuristic means
// Medium, and anything else came from configuration or exact versions (High).
func ConfidenceFor(f Finding) string {
	if len(f.Results) == 0 {
		return ""
	}
	heuristic := strings.Contains(strings.ToLower(f.Summary), "heuristic")
	for _, r := range f.Results {
		if r.Status == check.Incomplete || r.Status == check.Error {
			return ConfidenceLow
		}
		for _, e := range r.Evidence {
			if strings.HasPrefix(strings.ToLower(e), "matcher: heuristic") {
				heuristic = true
			}
		}
	}
	if heuristic {
		return ConfidenceMedium
	}
	return ConfidenceHigh
}

// incompleteTargets counts Incomplete and Error results inside checks that
// still reached a verdict (Pass or Fail). SARIF lists each of them, so the
// summary counts them too.
func incompleteTargets(f Finding) int {
	if f.Status != string(check.Pass) && f.Status != string(check.Fail) {
		return 0
	}
	n := 0
	for _, r := range f.Results {
		if r.Status == check.Incomplete || r.Status == check.Error {
			n++
		}
	}
	return n
}

// cvssScore returns the base score of a finding's vector, or 0.
func cvssScore(f Finding) float64 {
	s, err := check.BaseScore(f.CVSS)
	if err != nil {
		return 0
	}
	return s
}

// TopRisk is one line of the executive summary's top risks.
type TopRisk struct {
	ID, Title, Severity, Score, Why string
}

// ExecSummary is the plain-English executive summary built from the data.
type ExecSummary struct {
	Paragraphs []string
	Top        []TopRisk
	Gaps       []string // notable coverage gaps, one line each
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Executive builds the executive summary: scope, counts, top risks, gaps,
// suppressions, snapshot age and the main limitation.
func (r *Report) Executive() ExecSummary {
	var e ExecSummary
	s := r.Summary
	priv := "with root access"
	if !r.Scan.AsRoot {
		priv = "without root access, so some protected files could not be read"
	}
	dur := ""
	if !r.Scan.Started.IsZero() && r.Scan.Finished.Sub(r.Scan.Started) >= time.Second {
		dur = " in " + r.Scan.Finished.Sub(r.Scan.Started).Round(time.Second).String()
	}
	e.Paragraphs = append(e.Paragraphs, fmt.Sprintf("Scope: this report covers one machine, %s, assessed on %s UTC%s, %s. %s ran, read-only and limited to this machine.",
		r.Scan.Host, r.Scan.Started.UTC().Format("2006-01-02 15:04"), dur, priv, plural(r.Scan.Checks, "check", "checks")))
	e.Paragraphs = append(e.Paragraphs, fmt.Sprintf("Result: %s failed (%d Critical, %d High, %d Medium, %d Low, %d Info) and %d passed. %s",
		plural(s.Failed, "check", "checks"), s.Critical, s.High, s.Medium, s.Low, s.Info, s.Passed, r.Posture()))
	gaps := s.Incomplete + s.Errors + s.Skipped
	if gaps > 0 || s.IncompleteTargets > 0 {
		e.Paragraphs = append(e.Paragraphs, fmt.Sprintf("Coverage: %d Incomplete, %d Error and %d Skipped, plus %s inside other checks that could not be fully read. These areas are not shown to be free of weaknesses; see Coverage Gaps.",
			s.Incomplete, s.Errors, s.Skipped, plural(s.IncompleteTargets, "target", "targets")))
	}
	if r.Suppression != nil {
		e.Paragraphs = append(e.Paragraphs, fmt.Sprintf("Suppressions: %s accepted in the suppression file. They are still listed with their severity.", plural(r.Suppression.Suppressed, "failed result was", "failed results were")))
	}
	e.Paragraphs = append(e.Paragraphs, strings.TrimSuffix(r.Scan.VulnDB.Notice(), ".")+".")
	e.Paragraphs = append(e.Paragraphs, "Limitation: this is an automated, read-only self-assessment, not a penetration test. A clean result does not prove the machine is free of weaknesses.")
	for _, f := range r.TopRisks() {
		e.Top = append(e.Top, TopRisk{ID: f.ID, Title: f.Title, Severity: f.Severity, Score: fmt.Sprintf("%.1f", cvssScore(f)), Why: firstSentence(f.Rationale)})
	}
	for _, f := range r.Findings {
		if len(e.Gaps) >= 5 {
			break
		}
		for _, res := range f.Results {
			if res.Status == check.Incomplete || res.Status == check.Error {
				e.Gaps = append(e.Gaps, f.ID+" ("+res.Target+"): "+res.Message)
				break
			}
		}
	}
	return e
}

// sortTopRisks orders failed findings by severity, then CVSS base score.
func sortTopRisks(x []Finding) {
	sort.SliceStable(x, func(i, j int) bool {
		ri, rj := check.Severity(x[i].Severity).Rank(), check.Severity(x[j].Severity).Rank()
		if ri != rj {
			return ri < rj
		}
		return cvssScore(x[i]) > cvssScore(x[j])
	})
}
