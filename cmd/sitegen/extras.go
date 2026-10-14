package main

// Build-time extras added in the 2026-10-14 website review: per-page
// modification dates from git, data tables behind every chart, the
// machine-readable check catalogue, RFC 9116 security.txt and distinct
// descriptions for check pages whose summaries collide.

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
)

// ---------- per-page lastmod (W-06) ----------

var modCache = map[string]string{}

// lastMod returns the date (YYYY-MM-DD) of the newest commit that touched any
// of the given files, so sitemap lastmod and dateModified change only when a
// page's inputs change. It falls back to the build date when git cannot
// answer (no checkout, or a file that has never been committed).
func lastMod(files ...string) string {
	key := strings.Join(files, "\x00")
	if d, ok := modCache[key]; ok {
		return d
	}
	d := built.Format("2006-01-02")
	args := append([]string{"log", "-1", "--format=%cI", "--"}, files...)
	if out, err := exec.Command("git", args...).Output(); err == nil {
		if s := strings.TrimSpace(string(out)); len(s) >= 10 {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				d = t.UTC().Format("2006-01-02")
			}
		}
	}
	modCache[key] = d
	return d
}

// academyFiles lists the Academy source files, which together are the input
// of every module, worksheet and glossary page.
func academyFiles() []string {
	m, _ := filepath.Glob("internal/academy/*.go")
	var out []string
	for _, f := range m {
		if !strings.HasSuffix(f, "_test.go") {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// ---------- chart data tables (W-15) ----------

// chartTable renders the numbers behind a chart as a disclosure with a plain
// table, from the same ChartData the chart script reads, so the data is
// reachable without a mouse, without scripts and by crawlers.
func chartTable(data map[string]any, kind, label string) template.HTML {
	var b strings.Builder
	esc := template.HTMLEscapeString
	fmt.Fprintf(&b, `<details class="chart-table"><summary>%sView as Table</summary><div class="table-wrap"><table class="table"><caption class="sr-only">%s</caption>`, icon("list-checks"), esc(label))
	switch kind {
	case "matrix":
		cats, _ := data["categories"].([]string)
		sevs, _ := data["severities"].([]string)
		matrix, _ := data["matrix"].([][]int)
		b.WriteString(`<thead><tr><th scope="col">Category</th>`)
		for _, s := range sevs {
			fmt.Fprintf(&b, `<th scope="col">%s</th>`, esc(s))
		}
		b.WriteString(`<th scope="col">Total</th></tr></thead><tbody>`)
		for i, c := range cats {
			if i >= len(matrix) {
				break
			}
			total := 0
			fmt.Fprintf(&b, `<tr><th scope="row">%s</th>`, esc(c))
			for _, v := range matrix[i] {
				total += v
				fmt.Fprintf(&b, `<td>%d</td>`, v)
			}
			fmt.Fprintf(&b, `<td>%d</td></tr>`, total)
		}
		b.WriteString(`</tbody>`)
	default:
		rows, _ := data[kind].([]nv)
		total := 0
		fmt.Fprintf(&b, `<thead><tr><th scope="col">%s</th><th scope="col">Checks</th></tr></thead><tbody>`, esc(label))
		for _, r := range rows {
			total += r.Value
			fmt.Fprintf(&b, `<tr><th scope="row">%s</th><td>%d</td></tr>`, esc(r.Name), r.Value)
		}
		fmt.Fprintf(&b, `</tbody><tfoot><tr><th scope="row">Total</th><td>%d</td></tr></tfoot>`, total)
	}
	b.WriteString(`</table></div></details>`)
	return template.HTML(b.String()) // #nosec G203 -- every value is escaped above; icon() is vendored SVG
}

// ---------- distinct check descriptions (W-13) ----------

// checkDescs returns a meta description per check. Where several checks
// share the same summary (the three HOST-CVE checks do), the title is
// prefixed so each indexed page has its own snippet.
func checkDescs(cs []*check.Check) map[string]string {
	seen := map[string]int{}
	for _, c := range cs {
		seen[strings.Join(strings.Fields(c.Summary), " ")]++
	}
	out := map[string]string{}
	for _, c := range cs {
		s := strings.Join(strings.Fields(c.Summary), " ")
		if seen[s] > 1 {
			s = c.Title + ": " + strings.ToLower(s[:1]) + s[1:]
		}
		out[c.ID] = padDesc(trimDesc(s), "Detection, fix and verification steps.")
	}
	return out
}

// ---------- machine-readable catalogue (checks/catalogue.json) ----------

type catalogueEntry struct {
	ID         string          `json:"id"`
	Title      string          `json:"title"`
	Domain     string          `json:"domain"`
	Severity   string          `json:"severity"`
	CVSS       string          `json:"cvss"`
	Category   string          `json:"category"`
	Effort     string          `json:"effort"`
	Summary    string          `json:"summary"`
	Standards  check.Standards `json:"standards"`
	CIS        []string        `json:"cis_controls_v8"`
	NISTCSF    []string        `json:"nist_csf_2"`
	Modules    []string        `json:"academy_modules"`
	Page       string          `json:"page"`
	Source     string          `json:"source"`
	SourceFile string          `json:"source_file"`
}

// writeCatalogueJSON publishes the check catalogue as a dataset other tools
// and researchers can read, with a licence and credit line in the file.
func writeCatalogueJSON(cs []*check.Check) {
	var entries []catalogueEntry
	for _, c := range cs {
		cat := check.CategoryByID(c.Category)
		var mods []string
		for _, m := range academy.ForCheck(c.ID) {
			mods = append(mods, m.ID)
		}
		entries = append(entries, catalogueEntry{
			ID: c.ID, Title: c.Title, Domain: string(c.Domain), Severity: string(c.Severity), CVSS: c.CVSS,
			Category: cat.Name, Effort: string(c.Effort), Summary: c.Summary, Standards: c.Standards,
			CIS: cat.CIS, NISTCSF: cat.NISTCSF, Modules: mods,
			Page:   pageURL("checks/" + c.ID + ".html"),
			Source: fmt.Sprintf("%s/blob/%s/%s", repoURL, commit, c.SourceFile), SourceFile: c.SourceFile,
		})
	}
	doc := struct {
		Schema      string           `json:"schema"`
		Name        string           `json:"name"`
		Description string           `json:"description"`
		Version     string           `json:"version"`
		Commit      string           `json:"commit"`
		Generated   string           `json:"generated"`
		URL         string           `json:"url"`
		Homepage    string           `json:"homepage"`
		Repository  string           `json:"repository"`
		Licence     string           `json:"licence"`
		LicenceURL  string           `json:"licence_url"`
		Credit      string           `json:"credit"`
		Count       int              `json:"count"`
		Checks      []catalogueEntry `json:"checks"`
	}{
		Schema:      "openvapt.catalogue/1",
		Name:        "OpenVAPT Check Catalogue",
		Description: fmt.Sprintf("All %d read-only checks of OpenVAPT v%s with their severity, CVSS v3.1 vector, control category, standards mapping and source permalink. Generated from the code at build time.", len(cs), citeVersion()),
		Version:     citeVersion(),
		Commit:      commit,
		Generated:   built.Format("2006-01-02"),
		URL:         pageURL("checks/catalogue.json"),
		Homepage:    pageURL("checks/index.html"),
		Repository:  repoURL,
		Licence:     "LicenseRef-OpenVAPT-SAL-1.3",
		LicenceURL:  pageURL("legal/licence-text.html"),
		Credit:      "Data from OpenVAPT (openvapt.com), version " + citeVersion() + ", built by AI Cybersecurity Engineers, used under the OpenVAPT Source-Available Licence 1.3. Credit is required when you copy or adapt it; see " + pageURL("cite.html") + ".",
		Count:       len(cs),
		Checks:      entries,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(*outDir, "checks", "catalogue.json"), append(b, '\n'), 0o644)) // #nosec G306 -- public website file
}

// ---------- RFC 9116 security.txt ----------

// securityTxtPath is where the file is served; .htaccess redirects the
// legacy /security.txt to it and serves it as text/plain.
const securityTxtPath = ".well-known/security.txt"

func writeSecurityTxt() {
	expires := built.AddDate(0, 11, 0).Format("2006-01-02T15:04:05Z")
	body := "# OpenVAPT security contact (RFC 9116). There is no email channel:\n" +
		"# flaws in OpenVAPT or this website are reported through GitHub Private\n" +
		"# Vulnerability Reporting, which keeps the report private until a fix is out.\n" +
		"Contact: " + repoURL + "/security/advisories/new\n" +
		"Policy: " + repoURL + "/blob/main/SECURITY.md\n" +
		"Expires: " + expires + "\n" +
		"Preferred-Languages: en\n" +
		"Canonical: " + root() + "/" + securityTxtPath + "\n"
	dst := filepath.Join(*outDir, securityTxtPath)
	must(os.MkdirAll(filepath.Dir(dst), 0o755))  // #nosec G301 -- public website output
	must(os.WriteFile(dst, []byte(body), 0o644)) // #nosec G306 -- public website file
}
