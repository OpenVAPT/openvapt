package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openvapt/openvapt/internal/cite"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// JSON returns the indented JSON form of the report.
func (r *Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// ReadFile reads a report file the operator named: a regular file only,
// opened without blocking, at most MaxReportSize bytes. It is shared by
// Load (--baseline, diff) and sign.VerifyFile so every path into a report
// has the same guard.
func ReadFile(path string) ([]byte, error) {
	b, err := sys.ReadLocalFile(path, MaxReportSize)
	if errors.Is(err, sys.ErrTooLarge) {
		return nil, errors.New("report file is too large")
	}
	return b, err
}

// Load reads a JSON report from disk.
func Load(path string) (*Report, error) {
	b, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s is not an OpenVAPT report: %w", path, err)
	}
	if r.Schema == "openvapt.report/2" {
		for i := range r.Findings {
			if r.Findings[i].Category == "" {
				r.Findings[i].Category = check.CatConfig
			}
			if r.Findings[i].Effort == "" {
				r.Findings[i].Effort = check.EffortMedium
			}
		}
		r.Schema = SchemaVersion
	}
	if r.Schema != SchemaVersion {
		return nil, fmt.Errorf("%s has schema %q, expected %q", path, r.Schema, SchemaVersion)
	}
	return &r, nil
}

// WriteAll writes every format into dir with private file permissions
// (0600): reports describe weaknesses and should not be world-readable.
func (r *Report) WriteAll(dir string, formats []string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	clean, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// The report folder itself must not be a symlink. Parent folders may be
	// (for example /home on some distributions); the ownership and permission
	// checks below, and exclusive file creation, protect against planted links.
	if lst, err := os.Lstat(clean); err != nil {
		return nil, err
	} else if lst.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("report directory is a symlink: %s", clean)
	}
	st, err := os.Stat(clean)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("invalid report directory %s", clean)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("report directory %s must not be accessible by group or others", clean)
	}
	if !ownedByCurrentUser(st) {
		return nil, fmt.Errorf("report directory %s is not owned by the effective user", clean)
	}
	var written []string
	for _, f := range formats {
		var data []byte
		var err error
		name := "report." + f
		switch f {
		case "json":
			data, err = r.JSON()
		case "html":
			data, err = r.HTML()
		case "sarif":
			name = "report.sarif"
			data, err = r.SARIF()
		case "md":
			data = []byte(r.Markdown())
		default:
			return written, fmt.Errorf("unknown format %q (use json, html, sarif, md)", f)
		}
		if err != nil {
			return written, err
		}
		p := filepath.Join(clean, name)
		file, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return written, err
		}
		if _, err = file.Write(data); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return written, err
		}
		written = append(written, p)
	}
	return written, nil
}

// Markdown renders a plain-text report suitable for tickets and email.
func (r *Report) Markdown() string {
	var b strings.Builder
	s := r.Summary
	fmt.Fprintf(&b, "# OpenVAPT Self-Assessment Report\n\n")
	fmt.Fprintf(&b, "> %s\n\n", r.Disclaimer)
	fmt.Fprintf(&b, "| Item | Value |\n|---|---|\n| Host | %s |\n| Operating System | %s |\n| Scan Time (UTC) | %s |\n| Run As Root | %v |\n| Tool | %s %s (%s, %s channel) |\n\n",
		mdTable(r.Scan.Host), mdTable(r.Scan.OS), r.Scan.Started.Format("2006-01-02 15:04:05"), r.Scan.AsRoot, mdTable(r.Tool.Name), mdTable(r.Tool.Version), mdTable(short(r.Tool.Commit)), mdTable(r.Tool.Channel))
	fmt.Fprintf(&b, "%s\n\n", mdText(r.Scan.VulnDB.Notice()))
	if n := r.SuppressionNotice(); n != "" {
		fmt.Fprintf(&b, "%s\n\n", mdText(n))
	}
	ex := r.Executive()
	fmt.Fprintf(&b, "## Executive Summary\n\n")
	for _, p := range ex.Paragraphs {
		fmt.Fprintf(&b, "%s\n\n", mdText(p))
	}
	fmt.Fprintf(&b, "| Critical | High | Medium | Low | Passed | Incomplete | Incomplete Targets | Skipped | Errors |\n|---|---|---|---|---|---|---|---|---|\n| %d | %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		s.Critical, s.High, s.Medium, s.Low, s.Passed, s.Incomplete, s.IncompleteTargets, s.Skipped, s.Errors)
	fmt.Fprintf(&b, "### Top 5 Risks\n\n| ID | Risk | Severity | CVSS | Why It Matters |\n|---|---|---|---|---|\n")
	for _, t := range ex.Top {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdTable(t.ID), mdTable(t.Title), mdTable(t.Severity), mdTable(t.Score), mdTable(t.Why))
	}
	if len(ex.Gaps) > 0 {
		fmt.Fprintf(&b, "\n### Notable Coverage Gaps\n\n")
		for _, g := range ex.Gaps {
			fmt.Fprintf(&b, "- %s\n", mdText(g))
		}
	}
	fmt.Fprintf(&b, "\n## Risk Heat Map\n\n| Category | Critical | High | Medium | Low | Info |\n|---|---|---|---|---|---|\n")
	for _, x := range r.HeatMap() {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", mdTable(x.Category), x.Critical, x.High, x.Medium, x.Low, x.Info)
	}
	fmt.Fprintf(&b, "\n## Compliance Coverage\n\nCoverage is a mapping of automated checks, not certification of compliance.\n\n| Framework | Safeguard or Subcategory | Checks Run | Failed | Passed |\n|---|---|---|---|---|\n")
	for _, x := range r.ComplianceCoverage() {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d |\n", mdTable(x.Framework), mdTable(x.Control), x.Checks, x.Failed, x.Passed)
	}
	fmt.Fprintf(&b, "\n## Prioritised Remediation Plan\n\nHigh-severity, low-effort quick wins appear first.\n\n")
	for i, f := range r.RemediationPlan() {
		fmt.Fprintf(&b, "%d. **%s - %s** (%s severity, %s effort)\n   %s\n", i+1, mdText(f.ID), mdText(f.Title), mdText(f.Severity), mdText(string(f.Effort)), mdText(f.Fix))
	}
	fmt.Fprintf(&b, "## Findings\n\n")
	for _, f := range r.Findings {
		if f.Status != string(check.Fail) {
			continue
		}
		fmt.Fprintf(&b, "### \\[%s\\] %s (%s)\n\nCategory: %s. Effort: %s. Confidence: %s.\n\n%s\n\n**Why it matters:** %s\n\n", strings.ToUpper(mdText(f.Severity)), mdText(f.Title), mdText(f.ID), mdText(string(f.Category)), mdText(string(f.Effort)), mdText(f.Confidence), mdText(f.Summary), mdText(f.Rationale))
		for _, res := range f.Results {
			if res.Status != check.Fail {
				continue
			}
			tag := ""
			if s := f.SuppressionFor(res); s != nil {
				tag = " (suppressed until " + mdText(s.Expires) + ")"
			}
			fmt.Fprintf(&b, "- **%s:** %s%s\n", mdText(res.Target), mdText(res.Message), tag)
			for _, e := range res.Evidence {
				fmt.Fprintf(&b, "  - %s\n", mdCode(e))
			}
		}
		fmt.Fprintf(&b, "\n**Fix:** %s\n\n**Verify:** %s\n\n", mdText(f.Fix), mdCode(f.Verify))
		fmt.Fprintf(&b, "%s\n\n", mdText(FalsePositiveHint))
		if st := standardsLine(f.Standards); st != "" {
			fmt.Fprintf(&b, "**Standards:** %s\n\n", mdText(st))
		}
		for _, m := range f.Academy {
			fmt.Fprintf(&b, "**Learn:** %s: %s, %s (offline: %s)\n\n", mdText(m.ID), mdText(m.Title), m.URL, mdCode("openvapt learn "+m.ID))
		}
	}
	if r.Suppression != nil {
		fmt.Fprintf(&b, "## Suppressed Findings\n\nThese failed results were accepted in the suppression file. They keep their Fail status and severity; only the --fail-on exit code ignores them.\n\n| ID | Severity | Target | Reason | Expires | Added By |\n|---|---|---|---|---|---|\n")
		for _, x := range r.SuppressedRows() {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", mdTable(x.ID), mdTable(x.Severity), mdTable(x.Target), mdTable(x.Reason), mdTable(x.Expires), mdTable(x.AddedBy))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Passed and Skipped Checks\n\n| ID | Title | Status |\n|---|---|---|\n")
	for _, f := range r.Findings {
		if f.Status != string(check.Fail) {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdTable(f.ID), mdTable(f.Title), mdTable(f.Status))
		}
	}
	fmt.Fprintf(&b, "\n## Coverage Gaps\n\nIncomplete, Error and Skipped checks do not establish that the affected area is secure.\n\n| ID | Status | Affected Area and Reason |\n|---|---|---|\n")
	for _, f := range r.Findings {
		whole := f.Status == string(check.Incomplete) || f.Status == string(check.Error) || f.Status == string(check.Skip)
		for _, res := range f.Results {
			if !whole && res.Status != check.Incomplete && res.Status != check.Error {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %s: %s |\n", mdTable(f.ID), mdTable(string(res.Status)), mdTable(res.Target), mdTable(res.Message))
		}
	}
	fmt.Fprintf(&b, "\n## Methodology\n\n")
	for _, m := range r.Methodology {
		fmt.Fprintf(&b, "- %s\n", m)
	}
	fmt.Fprintf(&b, "\n## Limitations\n\n")
	for _, m := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", m)
	}
	c := r.HowToCite()
	fmt.Fprintf(&b, "\n## How to Cite\n\n%s\n\n%s\n\n**APA 7:** %s\n\n**BibTeX:**\n\n%s\n\n**Credit when you share this report:** %s\n", mdText(c.Reference), mdText(cite.Request), mdText(c.APA), mdFence(c.BibTeX, "bibtex"), mdText(c.Credit))
	return b.String()
}

// standardsLine renders every framework mapping of a finding (D-03: the
// Markdown report used to omit WSTG and ASVS).
func standardsLine(st check.Standards) string {
	var parts []string
	if len(st.CWE) > 0 {
		parts = append(parts, strings.Join(st.CWE, ", "))
	}
	if len(st.OWASP) > 0 {
		parts = append(parts, "OWASP Top 10 "+strings.Join(st.OWASP, ", "))
	}
	if len(st.ASVS) > 0 {
		parts = append(parts, "ASVS "+strings.Join(st.ASVS, ", "))
	}
	if len(st.WSTG) > 0 {
		parts = append(parts, strings.Join(st.WSTG, ", "))
	}
	if len(st.NIST) > 0 {
		parts = append(parts, "NIST SP 800-53 "+strings.Join(st.NIST, ", "))
	}
	return strings.Join(parts, "; ")
}

// mdClean turns control characters and line breaks into spaces.
func mdClean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s))
}

// mdEscaper backslash-escapes every Markdown character that could start
// emphasis, a heading, a link, raw HTML or a code span, so text taken from
// files on the scanned machine renders literally.
var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "#", `\#`, "[", `\[`, "]", `\]`,
	"<", `\<`, ">", `\>`, "!", `\!`, "~", `\~`,
	// Break GFM autolinks so a shared report never carries a clickable link
	// chosen by a file on the scanned machine.
	"://", `:\/\/`, "www.", `www\.`,
)

// mdText escapes prose for Markdown.
func mdText(s string) string { return mdEscaper.Replace(mdClean(s)) }

// mdTable escapes prose for a Markdown table cell.
func mdTable(s string) string { return strings.ReplaceAll(mdText(s), "|", "\\|") }

// mdCode renders s as an inline code span. Nothing is escaped inside: the
// fence is one backtick longer than the longest backtick run in s, and a
// space pads content that starts or ends with a backtick.
func mdCode(s string) string {
	s = mdClean(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") || s == "" {
		s = " " + s + " "
	}
	return fence + s + fence
}

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// PrintSummary writes a short console summary.
func (r *Report) PrintSummary(w io.Writer) {
	s := r.Summary
	fmt.Fprintf(w, "\n  Checks run:  %d   Passed: %d   Failed: %d   Incomplete: %d (plus %d targets)   Skipped: %d   Errors: %d\n", r.Scan.Checks, s.Passed, s.Failed, s.Incomplete, s.IncompleteTargets, s.Skipped, s.Errors)
	fmt.Fprintf(w, "  Failed by severity:  Critical %d   High %d   Medium %d   Low %d\n", s.Critical, s.High, s.Medium, s.Low)
	fmt.Fprintf(w, "  %s\n", r.Scan.VulnDB.Notice())
	if n := r.SuppressionNotice(); n != "" {
		fmt.Fprintf(w, "  %s\n", n)
	}
	fmt.Fprintln(w)
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) {
			mark := ""
			if f.FullySuppressed() {
				mark = " (suppressed)"
			}
			fmt.Fprintf(w, "  %-9s %-13s %s%s\n", strings.ToUpper(f.Severity), f.ID, f.Title, mark)
		}
	}
	for _, f := range r.Findings {
		if f.Status == string(check.Incomplete) || f.Status == string(check.Error) || f.Status == string(check.Skip) {
			fmt.Fprintf(w, "  %-9s %-13s %s\n", strings.ToUpper(f.Status), f.ID, f.Title)
		}
	}
	fmt.Fprintf(w, "\n  %s\n", cite.CLILine)
}

// mdFence renders s as a fenced code block whose fence is longer than any
// backtick run in s, so text read back from a report file cannot close it.
func mdFence(s, lang string) string {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + lang + "\n" + s + "\n" + fence
}
