// Package report defines the report produced by a scan and writes it as
// JSON, SARIF 2.1.0, Markdown and a self-contained HTML page.
//
// The structure follows the reporting guidance of NIST SP 800-115 (section 8):
// scope and methodology first, then findings with severity, evidence and
// remediation, then limitations. Reports are written only to the local disk.
package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
)

// SchemaVersion changes whenever the JSON shape changes incompatibly.
const SchemaVersion = "openvapt.report/3"

type Report struct {
	Schema      string     `json:"schema"`
	Tool        Tool       `json:"tool"`
	Scan        Scan       `json:"scan"`
	Summary     Summary    `json:"summary"`
	Findings    []Finding  `json:"findings"`
	Methodology []string   `json:"methodology"`
	Limitations []string   `json:"limitations"`
	Disclaimer  string     `json:"disclaimer"`
	Integrity   *Integrity `json:"integrity,omitempty"`
	// Suppression is set when --suppress was used; see suppress.go.
	Suppression *SuppressionInfo `json:"suppression,omitempty"`
	// Citation is the How to Cite block; see citation.go.
	Citation *Citation `json:"citation,omitempty"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Channel string `json:"channel"` // alpha, beta, rc, stable or dev
	Commit  string `json:"commit"`
	URL     string `json:"url"`
}

type Scan struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Host     string    `json:"host"`
	OS       string    `json:"os"`
	AsRoot   bool      `json:"as_root"`
	Checks   int       `json:"checks"`
	Sites    []string  `json:"sites"`
	VulnDB   *VulnDB   `json:"vulndb,omitempty"`
	// Command is the command line with file paths and other free values
	// replaced, so it carries no secrets or local names.
	Command string `json:"command,omitempty"`
}

// VulnDB describes the offline vulnerability snapshot the CVE checks used,
// so every report says how fresh its advisory data was. A snapshot older
// than StaleAfterDays is flagged as a warning, never as a failure.
type VulnDB struct {
	Generated  string `json:"generated"`  // YYYY-MM-DD
	Fixture    bool   `json:"fixture"`    // test fixture data, no CVE matching possible
	Advisories int    `json:"advisories"` // advisories in the snapshot
	AgeDays    int    `json:"age_days"`   // age at scan time, -1 if unknown
	Stale      bool   `json:"stale"`      // older than StaleAfterDays
}

// StaleAfterDays is the age at which a snapshot is flagged in the header.
const StaleAfterDays = 90

// Notice is the one-line snapshot status printed in report headers.
func (v *VulnDB) Notice() string {
	if v == nil {
		return "Vulnerability snapshot: not available"
	}
	if v.Fixture {
		return "Vulnerability snapshot: test fixture data only (no CVE matching was possible; build with make vulndb or use a release build)"
	}
	age := "age unknown"
	if v.AgeDays >= 0 {
		age = itoa(v.AgeDays) + " days old"
	}
	n := "Vulnerability snapshot: " + v.Generated + " (" + age + ", " + itoa(v.Advisories) + " advisories)"
	if v.Stale {
		n += ". Warning: older than " + itoa(StaleAfterDays) + " days; newer vulnerabilities are not in it. This warning is not a failure."
	}
	return n
}

func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// AcademyRef points a finding at the Academy module that teaches it.
type AcademyRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// AcademyFor returns the Academy modules that teach a check, with the
// website address of each module page (/academy/<module id>.html).
func AcademyFor(checkID string) []AcademyRef {
	var out []AcademyRef
	for _, m := range academy.ForCheck(checkID) {
		out = append(out, AcademyRef{ID: m.ID, Title: m.Title, URL: "https://openvapt.com/academy/" + strings.ToLower(m.ID) + ".html"})
	}
	return out
}

// Summary counts failed checks by severity, plus outcomes overall.
type Summary struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
	Passed     int `json:"passed"`
	Failed     int `json:"failed"`
	Skipped    int `json:"skipped"`
	Errors     int `json:"errors"`
	Incomplete int `json:"incomplete"`
	// IncompleteTargets counts Incomplete or Error results inside checks
	// that still passed or failed, matching the per-result SARIF output.
	IncompleteTargets int `json:"incomplete_targets"`
}

// Finding is one check with its outcome on this machine.
type Finding struct {
	ID        string          `json:"id"`
	Title     string          `json:"title"`
	Domain    string          `json:"domain"`
	Severity  string          `json:"severity"`
	Category  check.Category  `json:"category"`
	Effort    check.Effort    `json:"effort"`
	CVSS      string          `json:"cvss"`
	Status    string          `json:"status"`
	Summary   string          `json:"summary"`
	Rationale string          `json:"rationale"`
	Fix       string          `json:"fix"`
	Verify    string          `json:"verify"`
	Refs      []check.Ref     `json:"refs"`
	Standards check.Standards `json:"standards"`
	Source    string          `json:"source"`
	Academy   []AcademyRef    `json:"academy,omitempty"` // modules that teach this check
	// Confidence is high, medium or low; see ConfidenceFor.
	Confidence string         `json:"confidence,omitempty"`
	Results    []check.Result `json:"results"`
	// Suppressed lists failed results covered by the suppression file. They
	// keep their status; only the --fail-on exit code ignores them.
	Suppressed []Suppressed `json:"suppressed,omitempty"`
}

// Integrity lets a reader confirm the report was not edited after it was
// written. See package sign.
type Integrity struct {
	Algorithm string `json:"algorithm"`  // "ed25519"
	SHA256    string `json:"sha256"`     // of the canonical report bytes, see Format
	PublicKey string `json:"public_key"` // base64
	KeyID     string `json:"key_id"`     // short fingerprint of the public key
	Signature string `json:"signature"`  // base64 signature over the SHA-256 digest
	// Format names how the digest was computed. "openvapt.sign/2": SHA-256 of
	// CanonicalJSON, and the file must be exactly the canonical JSON of the
	// report. Empty: the earlier compact form, still verifiable for files in
	// canonical form.
	Format string `json:"format,omitempty"`
}

// FromCheck copies the static metadata of a check into a finding.
func FromCheck(c *check.Check) Finding {
	return Finding{
		ID: c.ID, Title: c.Title, Domain: string(c.Domain), Severity: string(c.Severity), Category: c.Category, Effort: c.Effort, CVSS: c.CVSS,
		Summary: c.Summary, Rationale: c.Rationale, Fix: c.Fix, Verify: c.Verify,
		Refs: c.Refs, Standards: c.Standards, Source: c.SourceFile, Academy: AcademyFor(c.ID),
	}
}

type HeatRow struct {
	Category                          string
	Critical, High, Medium, Low, Info int
}
type CoverageRow struct {
	Framework, Control     string
	Checks, Failed, Passed int
}

func (r *Report) Posture() string {
	if r.Summary.Critical > 0 {
		return "Critical weaknesses require immediate attention."
	}
	if r.Summary.High > 0 {
		return "High-risk weaknesses should be addressed promptly."
	}
	if r.Summary.Medium > 0 {
		return "The system has material hardening opportunities."
	}
	if r.Summary.Failed > 0 {
		return "Only lower-severity weaknesses were detected."
	}
	if r.Summary.Incomplete+r.Summary.Errors+r.Summary.Skipped+r.Summary.IncompleteTargets > 0 {
		return "No checks failed, but incomplete and skipped checks still limit assurance."
	}
	return "No checks failed and every check completed; this is still an automated self-assessment, not proof the machine is free of weaknesses."
}
func (r *Report) TopRisks() []Finding {
	var x []Finding
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) {
			x = append(x, f)
		}
	}
	sortTopRisks(x)
	if len(x) > 5 {
		x = x[:5]
	}
	return x
}
func (r *Report) RemediationPlan() []Finding {
	var x []Finding
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) {
			x = append(x, f)
		}
	}
	eff := func(e check.Effort) int {
		if e == check.EffortLow {
			return 0
		}
		if e == check.EffortMedium {
			return 1
		}
		return 2
	}
	sort.SliceStable(x, func(i, j int) bool {
		si, sj := check.Severity(x[i].Severity).Rank(), check.Severity(x[j].Severity).Rank()
		quickI := si <= 1 && x[i].Effort == check.EffortLow
		quickJ := sj <= 1 && x[j].Effort == check.EffortLow
		if quickI != quickJ {
			return quickI
		}
		if si != sj {
			return si < sj
		}
		if eff(x[i].Effort) != eff(x[j].Effort) {
			return eff(x[i].Effort) < eff(x[j].Effort)
		}
		return x[i].ID < x[j].ID
	})
	return x
}
func (r *Report) HeatMap() []HeatRow {
	rows := make([]HeatRow, 0, len(check.Categories))
	for _, c := range check.Categories {
		row := HeatRow{Category: c.Name}
		for _, f := range r.Findings {
			if f.Status != string(check.Fail) || f.Category != c.ID {
				continue
			}
			switch check.Severity(f.Severity) {
			case check.Critical:
				row.Critical++
			case check.High:
				row.High++
			case check.Medium:
				row.Medium++
			case check.Low:
				row.Low++
			default:
				row.Info++
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// ComplianceCoverage counts each check toward the CIS Controls v8 safeguard
// and NIST CSF 2.0 subcategories it maps to (Standards.CIS and
// Standards.CSF), not toward every safeguard of its broad category.
func (r *Report) ComplianceCoverage() []CoverageRow {
	type key struct{ f, c string }
	m := map[key]*CoverageRow{}
	for _, f := range r.Findings {
		var ks []key
		for _, c := range f.Standards.CIS {
			if c != "" && c != "none" {
				ks = append(ks, key{"CIS Controls v8", c})
			}
		}
		for _, c := range f.Standards.CSF {
			if c != "" {
				ks = append(ks, key{"NIST CSF 2.0", c})
			}
		}
		for _, k := range ks {
			row := m[k]
			if row == nil {
				row = &CoverageRow{Framework: k.f, Control: k.c}
				m[k] = row
			}
			row.Checks++
			if f.Status == string(check.Fail) {
				row.Failed++
			}
			if f.Status == string(check.Pass) {
				row.Passed++
			}
		}
	}
	out := make([]CoverageRow, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return safeguardLess(out[i].Control, out[j].Control)
	})
	return out
}

// safeguardLess orders ids like "4.1" < "4.10" and "PR.PS-01" < "PR.PS-02".
func safeguardLess(a, b string) bool {
	pa, pb := splitNum(a), splitNum(b)
	for k := 0; k < len(pa) && k < len(pb); k++ {
		if pa[k] != pb[k] {
			na, ea := strconv.Atoi(pa[k])
			nb, eb := strconv.Atoi(pb[k])
			if ea == nil && eb == nil {
				return na < nb
			}
			return pa[k] < pb[k]
		}
	}
	return len(pa) < len(pb)
}

func splitNum(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
}

// Summarise fills in r.Summary from r.Findings.
func (r *Report) Summarise() {
	var s Summary
	for i := range r.Findings {
		r.Findings[i].Confidence = ConfidenceFor(r.Findings[i])
		s.IncompleteTargets += incompleteTargets(r.Findings[i])
	}
	for _, f := range r.Findings {
		switch check.Status(f.Status) {
		case check.Pass:
			s.Passed++
		case check.Skip:
			s.Skipped++
		case check.Error:
			s.Errors++
		case check.Incomplete:
			s.Incomplete++
		case check.Fail:
			s.Failed++
			switch check.Severity(f.Severity) {
			case check.Critical:
				s.Critical++
			case check.High:
				s.High++
			case check.Medium:
				s.Medium++
			case check.Low:
				s.Low++
			default:
				s.Info++
			}
		}
	}
	r.Summary = s
}

// Methodology is printed in every report so readers know exactly what was done.
var Methodology = []string{
	"Scope: this machine only. Every network connection is restricted in code to loopback addresses (127.0.0.0/8, ::1). No other host was contacted.",
	"Approach: automated, non-intrusive vulnerability assessment following the planning, discovery, analysis and reporting phases of NIST SP 800-115. No exploitation was attempted.",
	"Discovery: configuration files, /proc and /sys were read; a short allow-list of read-only commands was run (for example sshd -T and apt-get -s upgrade, which only simulates).",
	"Web: websites were discovered from the local web server configuration and requested through 127.0.0.1 with GET requests for fixed paths only. No forms were submitted and no attack payloads were sent.",
	"Rating: each check carries a qualitative severity on the CVSS v3.1 scale with a representative base vector. Environmental factors on your network may raise or lower the real risk. Detective gaps such as missing logging, auditing or integrity monitoring carry a local attack vector: a missing record opens no network path, it makes a separate intrusion harder to trace.",
	"Evidence: secrets (passwords, keys, tokens, hashes) were redacted before writing this report.",
}

// Limitations are printed in every report, because an honest report says
// what it could not see.
var Limitations = []string{
	"An automated self-assessment is not a penetration test. It does not prove that the machine is secure; absence of findings is not proof of absence of vulnerabilities.",
	"Only the checks listed in this report were performed. Application logic flaws (for example SQL injection, broken access control or business logic errors) require manual testing or code review.",
	"Some checks need root to read protected files or the real daemon state. A check that could not read what it needed is marked Skipped (it did not apply or could not start) or Incomplete (it ran, but part of its input was unreadable, truncated or missing); neither is a Pass.",
	"Results reflect the machine at the time of the scan. Configuration drift after the scan is not covered.",
	"End-of-life and version tables are dated and may be out of date for releases newer than this version of OpenVAPT.",
}

// Disclaimer appears at the top of every report.
const Disclaimer = "OpenVAPT is an academic, non-commercial project with source-available code built by AI Cybersecurity Engineers (AI systems, not people or registered engineers). This report was produced by automated, read-only checks run by the user on their own machine, for their own use, 100% at their own risk. It is not a penetration test, an audit, a certification, a service or professional advice, and it may be wrong or incomplete. The developers accept no responsibility or liability for any decision taken from it. OpenVAPT may not be sold or used to provide services. No data from this report was sent anywhere."
