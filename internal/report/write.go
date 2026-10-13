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
	fmt.Fprintf(&b, "| Item | Value |\n|---|---|\n| Host | %s |\n| Operating System | %s |\n| Scan Time (UTC) | %s |\n| Run As Root | %v |\n| Tool | %s %s (%s) |\n\n",
		mdTable(r.Scan.Host), mdTable(r.Scan.OS), r.Scan.Started.Format("2006-01-02 15:04:05"), r.Scan.AsRoot, mdTable(r.Tool.Name), mdTable(r.Tool.Version), mdTable(short(r.Tool.Commit)))
	fmt.Fprintf(&b, "## Summary\n\n| Critical | High | Medium | Low | Passed | Incomplete | Skipped | Errors |\n|---|---|---|---|---|---|---|---|\n| %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		s.Critical, s.High, s.Medium, s.Low, s.Passed, s.Incomplete, s.Skipped, s.Errors)
	fmt.Fprintf(&b, "## Findings\n\n")
	for _, f := range r.Findings {
		if f.Status != string(check.Fail) {
			continue
		}
		fmt.Fprintf(&b, "### [%s] %s (%s)\n\n%s\n\n**Why it matters:** %s\n\n", strings.ToUpper(mdText(f.Severity)), mdText(f.Title), mdText(f.ID), mdText(f.Summary), mdText(f.Rationale))
		for _, res := range f.Results {
			if res.Status != check.Fail {
				continue
			}
			fmt.Fprintf(&b, "- **%s:** %s\n", mdText(res.Target), mdText(res.Message))
			for _, e := range res.Evidence {
				fmt.Fprintf(&b, "  - `%s`\n", strings.ReplaceAll(mdText(e), "`", "'"))
			}
		}
		fmt.Fprintf(&b, "\n**Fix:** %s\n\n**Verify:** %s\n\n", mdText(f.Fix), mdText(f.Verify))
		if len(f.Standards.CWE) > 0 {
			fmt.Fprintf(&b, "**Standards:** %s\n\n", strings.Join(append(append([]string{}, f.Standards.CWE...), f.Standards.OWASP...), ", "))
		}
	}
	fmt.Fprintf(&b, "## Passed and Skipped Checks\n\n| ID | Title | Status |\n|---|---|---|\n")
	for _, f := range r.Findings {
		if f.Status != string(check.Fail) {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdTable(f.ID), mdTable(f.Title), mdTable(f.Status))
		}
	}
	fmt.Fprintf(&b, "\n## Coverage Gaps\n\nIncomplete, Error and Skipped checks do not establish that the affected area is secure.\n\n| ID | Status | Affected Area and Reason |\n|---|---|---|\n")
	for _, f := range r.Findings {
		if f.Status != string(check.Incomplete) && f.Status != string(check.Error) && f.Status != string(check.Skip) {
			continue
		}
		for _, res := range f.Results {
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
	return b.String()
}

func mdText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return ' '
		}
		return r
	}, s)
	s = strings.NewReplacer("\r", " ", "\n", " ", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;").Replace(s)
	return strings.TrimSpace(s)
}
func mdTable(s string) string { return strings.ReplaceAll(mdText(s), "|", "\\|") }

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// PrintSummary writes a short console summary.
func (r *Report) PrintSummary(w io.Writer) {
	s := r.Summary
	fmt.Fprintf(w, "\n  Checks run:  %d   Passed: %d   Failed: %d   Incomplete: %d   Skipped: %d   Errors: %d\n", r.Scan.Checks, s.Passed, s.Failed, s.Incomplete, s.Skipped, s.Errors)
	fmt.Fprintf(w, "  Failed by severity:  Critical %d   High %d   Medium %d   Low %d\n\n", s.Critical, s.High, s.Medium, s.Low)
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) {
			fmt.Fprintf(w, "  %-9s %-13s %s\n", strings.ToUpper(f.Severity), f.ID, f.Title)
		}
	}
	for _, f := range r.Findings {
		if f.Status == string(check.Incomplete) || f.Status == string(check.Error) || f.Status == string(check.Skip) {
			fmt.Fprintf(w, "  %-9s %-13s %s\n", strings.ToUpper(f.Status), f.ID, f.Title)
		}
	}
}
