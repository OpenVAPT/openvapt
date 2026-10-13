package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
)

// JSON returns the indented JSON form of the report.
func (r *Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Load reads a JSON report from disk.
func Load(path string) (*Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s is not an OpenVAPT report: %w", path, err)
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
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
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
	fmt.Fprintf(&b, "| Item | Value |\n|---|---|\n| Host | %s |\n| Operating System | %s |\n| Scan Time (UTC) | %s |\n| Run As Root | %v |\n| Tool | %s %s (%s) |\n\n",
		r.Scan.Host, r.Scan.OS, r.Scan.Started.Format("2006-01-02 15:04:05"), r.Scan.AsRoot, r.Tool.Name, r.Tool.Version, short(r.Tool.Commit))
	fmt.Fprintf(&b, "## Summary\n\n| Critical | High | Medium | Low | Passed | Skipped | Errors |\n|---|---|---|---|---|---|---|\n| %d | %d | %d | %d | %d | %d | %d |\n\n",
		s.Critical, s.High, s.Medium, s.Low, s.Passed, s.Skipped, s.Errors)
	fmt.Fprintf(&b, "## Findings\n\n")
	for _, f := range r.Findings {
		if f.Status != string(check.Fail) {
			continue
		}
		fmt.Fprintf(&b, "### [%s] %s (%s)\n\n%s\n\n**Why it matters:** %s\n\n", strings.ToUpper(f.Severity), f.Title, f.ID, f.Summary, f.Rationale)
		for _, res := range f.Results {
			if res.Status != check.Fail {
				continue
			}
			fmt.Fprintf(&b, "- **%s:** %s\n", res.Target, res.Message)
			for _, e := range res.Evidence {
				fmt.Fprintf(&b, "  - `%s`\n", strings.ReplaceAll(e, "`", "'"))
			}
		}
		fmt.Fprintf(&b, "\n**Fix:** %s\n\n**Verify:** %s\n\n", f.Fix, f.Verify)
		if len(f.Standards.CWE) > 0 {
			fmt.Fprintf(&b, "**Standards:** %s\n\n", strings.Join(append(append([]string{}, f.Standards.CWE...), f.Standards.OWASP...), ", "))
		}
	}
	fmt.Fprintf(&b, "## Passed and Skipped Checks\n\n| ID | Title | Status |\n|---|---|---|\n")
	for _, f := range r.Findings {
		if f.Status != string(check.Fail) {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", f.ID, f.Title, f.Status)
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
	return b.String()
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
	fmt.Fprintf(w, "\n  Checks run:  %d   Passed: %d   Failed: %d   Skipped: %d   Errors: %d\n", r.Scan.Checks, s.Passed, s.Failed, s.Skipped, s.Errors)
	fmt.Fprintf(w, "  Failed by severity:  Critical %d   High %d   Medium %d   Low %d\n\n", s.Critical, s.High, s.Medium, s.Low)
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) {
			fmt.Fprintf(w, "  %-9s %-13s %s\n", strings.ToUpper(f.Severity), f.ID, f.Title)
		}
	}
}
