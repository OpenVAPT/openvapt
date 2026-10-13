// Package report defines the report produced by a scan and writes it as
// JSON, SARIF 2.1.0, Markdown and a self-contained HTML page.
//
// The structure follows the reporting guidance of NIST SP 800-115 (section 8):
// scope and methodology first, then findings with severity, evidence and
// remediation, then limitations. Reports are written only to the local disk.
package report

import (
	"sort"
	"time"

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
	Results   []check.Result  `json:"results"`
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
		Refs: c.Refs, Standards: c.Standards, Source: c.SourceFile,
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
	return "No checks failed, but incomplete and skipped checks still limit assurance."
}
func (r *Report) TopRisks() []Finding {
	var x []Finding
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) {
			x = append(x, f)
		}
	}
	sort.SliceStable(x, func(i, j int) bool {
		return check.Severity(x[i].Severity).Rank() < check.Severity(x[j].Severity).Rank()
	})
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
func (r *Report) ComplianceCoverage() []CoverageRow {
	type key struct{ f, c string }
	m := map[key]*CoverageRow{}
	for _, ci := range check.Categories {
		for _, c := range ci.CIS {
			m[key{"CIS Controls v8", c}] = &CoverageRow{Framework: "CIS Controls v8", Control: c}
		}
		for _, c := range ci.NISTCSF {
			m[key{"NIST CSF 2.0", c}] = &CoverageRow{Framework: "NIST CSF 2.0", Control: c}
		}
	}
	for _, f := range r.Findings {
		ci := check.CategoryByID(f.Category)
		var ks []key
		for _, c := range ci.CIS {
			ks = append(ks, key{"CIS Controls v8", c})
		}
		for _, c := range ci.NISTCSF {
			ks = append(ks, key{"NIST CSF 2.0", c})
		}
		for _, k := range ks {
			row := m[k]
			row.Checks++
			if f.Status == string(check.Fail) {
				row.Failed++
			}
			if f.Status == string(check.Pass) {
				row.Passed++
			}
		}
	}
	var out []CoverageRow
	for _, v := range m {
		if v.Checks > 0 {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].Control < out[j].Control
	})
	return out
}

// Summarise fills in r.Summary from r.Findings.
func (r *Report) Summarise() {
	var s Summary
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
	"Rating: each check carries a qualitative severity on the CVSS v3.1 scale with a representative base vector. Environmental factors on your network may raise or lower the real risk.",
	"Evidence: secrets (passwords, keys, tokens, hashes) were redacted before writing this report.",
}

// Limitations are printed in every report, because an honest report says
// what it could not see.
var Limitations = []string{
	"An automated self-assessment is not a penetration test. It does not prove that the machine is secure; absence of findings is not proof of absence of vulnerabilities.",
	"Only the checks listed in this report were performed. Application logic flaws (for example SQL injection, broken access control or business logic errors) require manual testing or code review.",
	"Some checks need root to read protected files. Checks that could not read what they needed are marked Skipped.",
	"Results reflect the machine at the time of the scan. Configuration drift after the scan is not covered.",
	"End-of-life and version tables are dated and may be out of date for releases newer than this version of OpenVAPT.",
}

// Disclaimer appears at the top of every report.
const Disclaimer = "OpenVAPT is an academic, non-commercial project with source-available code built by AI Cybersecurity Engineers (AI systems, not people or registered engineers). This report was produced by automated, read-only checks run by the user on their own machine, for their own use, 100% at their own risk. It is not a penetration test, an audit, a certification, a service or professional advice, and it may be wrong or incomplete. The developers accept no responsibility or liability for any decision taken from it. OpenVAPT may not be sold or used to provide services. No data from this report was sent anywhere."
