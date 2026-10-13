// Command sitegen builds the static openvapt.com website from this repository.
//
// The website is generated, not hand-written, so it can never drift from the
// code: every check page is built from the check's own registered metadata,
// and every code citation is the real source file, with line numbers and a
// GitHub permalink pinned to the commit being built.
//
//	go run ./cmd/sitegen -out dist/site
//
// The output is plain HTML and CSS plus one small script. It sets no cookies,
// loads nothing from other sites and collects no data.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html/template"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/engine"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/terms"
	"github.com/openvapt/openvapt/internal/version"
)

const (
	siteURL = "https://openvapt.com"
	repoURL = "https://github.com/openvapt/openvapt"
)

var (
	outDir  = flag.String("out", "dist/site", "output directory")
	base    = flag.String("base", "/", "URL path the site is served under, e.g. /beta/")
	noindex = flag.Bool("noindex", false, "add noindex to every page (for the beta site)")
	commit  string
	built   = time.Now().UTC()
)

// Page is the data every template receives.
type Page struct {
	Title, Description, Path, Section  string
	Base, Commit, CommitShort, Version string
	Built                              string
	NoIndex                            bool
	JSONLD                             template.JS
	Body                               template.HTML
	Data                               any
}

// Cite is one block of quoted source code with its location.
type Cite struct {
	File, Func string
	Start, End int
	Lines      []Line
	Permalink  string
}

type Line struct {
	N    int
	Text string
}

func main() {
	flag.Parse()
	commit = gitCommit()
	if !strings.HasSuffix(*base, "/") {
		*base += "/"
	}
	must(os.RemoveAll(*outDir))
	must(os.MkdirAll(*outDir, 0o755)) // #nosec G301 -- public website output

	g := &gen{}

	checks := check.All()
	// Fill live counts into FAQ answers so they never go stale.
	n := counts(checks)
	rep := strings.NewReplacer("{TOTAL}", fmt.Sprint(n["total"]), "{HOST}", fmt.Sprint(n["host"]), "{NETWORK}", fmt.Sprint(n["network"]), "{WEB}", fmt.Sprint(n["web"]), "{MODULES}", fmt.Sprint(len(academy.Modules)))
	for i := range faqs {
		faqs[i].A = rep.Replace(faqs[i].A)
	}
	cites := map[string]Cite{}
	for _, c := range checks {
		cites[c.ID] = citeFile(c.SourceFile)
	}

	// Content pages: site/content/*.html are templates with access to data.
	data := map[string]any{
		"Checks":      checks,
		"Counts":      counts(checks),
		"Walkthrough": walkthrough(),
		"Standards":   standards(checks),
		"Repo":        repoURL,
		"Catalogue":   catalogueRows(checks),
		"Categories":  check.Categories,
		"Pillars":     terms.Pillars,
		"Acks":        terms.Acknowledgements,
		"TermsVer":    terms.Version,
		"FAQ":         faqs,
		"Levels":      academy.Levels(),
		"Modules":     academy.Modules,
		"Glossary":    academy.Glossary,
		"Terms":       academy.Terms(),
		"ChartData":   chartData(checks),
	}
	pages := []struct{ file, path, title, desc, section string }{
		{"index.html", "index.html", "OpenVAPT, an Academic Vulnerability Assessment Tool", "OpenVAPT is an academic, non-commercial project with AI-generated, source-available code. Free to download and use on your own Linux server, for personal or business own use, 100% at your own risk.", "home"},
		{"how-it-works.html", "how-it-works.html", "How OpenVAPT Is Built", "A module by module walkthrough of the OpenVAPT source code, with every function cited to the exact file and line.", "built"},
		{"standards.html", "standards.html", "Standards and Methodology", "How OpenVAPT maps to NIST SP 800-115, CVSS v3.1, OWASP Top 10, OWASP ASVS, CWE and NIST SP 800-53.", "standards"},
		{"limits.html", "limits.html", "What OpenVAPT Does Not Do", "The deliberate limits of OpenVAPT: no exploitation, no remote targets, no data collection, not a penetration test.", "limits"},
		{"learn.html", "learn.html", "Learn Vulnerability Assessment", "Lessons on vulnerability assessment using OpenVAPT and its safe simulated lab servers.", "learn"},
		{"download.html", "download.html", "Download and Run OpenVAPT", "Build OpenVAPT from source or download a release, verify it, and run it on your own Linux machine.", "download"},
		{"contribute.html", "contribute.html", "Review, Report and Contribute", "Report bugs, false positives and new check ideas on GitHub, and how OpenVAPT versions and releases work.", "contribute"},
		{"cite.html", "cite.html", "Cite OpenVAPT", "How to cite OpenVAPT in academic work.", "cite"},
		{"coverage.html", "coverage.html", "Coverage Dashboard: What OpenVAPT Assesses", "Interactive coverage of OpenVAPT's checks by control category and severity, mapped to CIS Controls v8, NIST CSF 2.0, OWASP Top 10 and OWASP WSTG.", "coverage"},
		{"faq.html", "faq.html", "OpenVAPT FAQ: Free Academic VAPT Tool Questions Answered", "Answers about OpenVAPT, the free academic vulnerability assessment tool for Linux: cost, licence, company use, scope, safety, standards and data.", "faq"},
		{"compare.html", "compare.html", "OpenVAPT Compared With Lynis, OpenSCAP, OpenVAS, Nuclei and ZAP", "How OpenVAPT, a free academic VAPT learning tool, compares with Lynis, OpenSCAP, OpenVAS, Nuclei, Trivy and OWASP ZAP, and when to use each.", "compare"},
		{"privacy-notice.html", "no-data.html", "We Collect No Data", "OpenVAPT and openvapt.com collect no data: no cookies, no analytics, no logs, no forms, no accounts.", "nodata"},
		{"404.html", "404.html", "Page Not Found", "This page does not exist.", ""},
	}
	for _, p := range pages {
		g.content(p.file, p.path, p.title, p.desc, p.section, data)
	}

	// Check catalogue.
	g.content("checks.html", "checks/index.html", "Check Catalogue", fmt.Sprintf("All %d OpenVAPT checks with their rationale, detection logic, fix, references and source code.", len(checks)), "checks", data)
	for _, c := range checks {
		g.render("check.html", "checks/"+c.ID+".html", c.ID+": "+c.Title, c.Summary, "checks",
			map[string]any{"C": c, "Cite": cites[c.ID], "Learn": academy.ForCheck(c.ID)})
	}

	// OpenVAPT Academy: course index, one page per module, and the glossary.
	g.render("academy.html", "academy/index.html", "OpenVAPT Academy: Learn VAPT From Theory to Application", "A free 15-module course that teaches vulnerability assessment from security basics to running, fixing, reporting and building checks, using OpenVAPT and a safe simulated lab.", "academy", data)
	for i := range academy.Modules {
		m := &academy.Modules[i]
		var prev, next *academy.Module
		if i > 0 {
			prev = &academy.Modules[i-1]
		}
		if i+1 < len(academy.Modules) {
			next = &academy.Modules[i+1]
		}
		g.render("module.html", "academy/"+strings.ToLower(m.ID)+".html", m.ID+": "+m.Title+" - OpenVAPT Academy", m.Summary, "academy",
			map[string]any{"M": m, "Checks": checksFor(m), "Prev": prev, "Next": next, "Glossary": academy.Glossary})
	}
	g.render("glossary.html", "glossary.html", "VAPT Glossary: Vulnerability Assessment Terms Explained", "Plain-language definitions of vulnerability assessment and penetration testing terms, from ASLR and CVSS to TLS and VAPT.", "academy", data)

	// Legal pages are rendered from the Markdown files in the repository root,
	// so the website and the repository always say the same thing.
	for _, l := range []struct{ md, path, title, desc string }{
		{"EULA.md", "legal/eula.html", "End User Licence Agreement", "Terms for downloading and using OpenVAPT."},
		{"DISCLAIMER.md", "legal/disclaimer.html", "Disclaimer", "OpenVAPT is an academic project provided as is, at your own risk."},
		{"PRIVACY.md", "legal/privacy.html", "Privacy Policy", "OpenVAPT collects no personal data at all."},
		{"ACCEPTABLE_USE.md", "legal/acceptable-use.html", "Acceptable Use Policy", "How OpenVAPT may and may not be used."},
		{"LICENSING.md", "legal/licence.html", "Licence", "OpenVAPT is licensed under the PolyForm Noncommercial License 1.0.0 with an additional permission for own use."},
		{"AI-DISCLOSURE.md", "legal/ai-disclosure.html", "AI Disclosure", "OpenVAPT is entirely AI-generated. Which AI systems produced it, what the human owner did, and what has not been reviewed."},
		{"CREDITS.md", "legal/credits.html", "Credits, Sources and Citations", "Every component, tool, standard, source and AI system OpenVAPT uses or refers to, cited precisely."},
	} {
		b, err := os.ReadFile(l.md)
		must(err)
		g.page("legal/"+filepath.Base(l.path), l.path, l.title, l.desc, "legal",
			template.HTML(`<div class="legal"><h1>`+template.HTMLEscapeString(l.title)+`</h1>`+markdown(string(b))+`</div>`)) // #nosec G203 -- markdown() HTML-escapes all text first
	}

	writeSampleReports()
	copyDir("site/static", *outDir)
	writeSEO(g.paths, checks)
	fmt.Printf("Built %d pages into %s (commit %s)\n", len(g.paths), *outDir, commit[:min(12, len(commit))])
}

type gen struct {
	paths []string
}

// newLayout parses a fresh copy of the layout (html/template forbids cloning
// a template after it has executed).
func newLayout() *template.Template {
	return template.Must(template.New("layout").Funcs(funcs()).ParseFiles("site/templates/layout.html"))
}

func (g *gen) content(file, path, title, desc, section string, data any) {
	g.render(file, path, title, desc, section, data)
}

func (g *gen) render(file, path, title, desc, section string, data any) {
	t := template.Must(newLayout().ParseFiles("site/content/" + file))
	var body bytes.Buffer
	if err := t.ExecuteTemplate(&body, "content", pageFor(path, title, desc, section, "", data)); err != nil {
		log.Fatalf("%s: %v", file, err)
	}
	g.page(file, path, title, desc, section, template.HTML(body.String())) // #nosec G203 -- output of html/template, already escaped
}

func (g *gen) page(_, path, title, desc, section string, body template.HTML) {
	p := pageFor(path, title, desc, section, body, nil)
	p.JSONLD = jsonLD(p)
	var out bytes.Buffer
	if err := newLayout().ExecuteTemplate(&out, "layout", p); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	dst := filepath.Join(*outDir, path)
	must(os.MkdirAll(filepath.Dir(dst), 0o755)) // #nosec G301 -- public website output
	must(os.WriteFile(dst, out.Bytes(), 0o644)) // #nosec G306 -- public website file
	g.paths = append(g.paths, path)
}

func pageFor(path, title, desc, section string, body template.HTML, data any) Page {
	return Page{Title: title, Description: desc, Path: path, Section: section, Base: *base,
		Commit: commit, CommitShort: commit[:min(12, len(commit))], Version: version.Version,
		Built: built.Format("2006-01-02"), NoIndex: *noindex, Body: body, Data: data}
}

func funcs() template.FuncMap {
	return template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"join":  strings.Join,
		"title": func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
		"repo":  func() string { return repoURL },
		"blob":  func(file string) string { return repoURL + "/blob/" + commit + "/" + file },
		"cwe": func(id string) string {
			return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(id, "CWE-") + ".html"
		},
		"icon":      icon,
		"tagline":   func() string { return terms.Tagline },
		"add":       func(a, b int) int { return a + b },
		"slug":      slug,
		"hasPrefix": strings.HasPrefix,
		"json": func(v any) template.JS {
			b, err := json.Marshal(v) // escapes <, > and & so it is safe inside a script element
			must(err)
			return template.JS(b) // #nosec G203 -- json.Marshal escapes <, > and &
		},
		"catName": func(c check.Category) string { return check.CategoryByID(c).Name },
		"catInfo": check.CategoryByID,
		"pct": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a * 100 / b
		},
	}
}

// icon inlines a Lucide SVG (vendored into site/icons by npm run vendor).
// Icons are decorative, so they are hidden from screen readers.
func icon(name string) template.HTML {
	b, err := os.ReadFile("site/icons/" + name + ".svg")
	if err != nil {
		log.Fatalf("icon %q not vendored: %v", name, err)
	}
	svg := string(b)
	if i := strings.Index(svg, "<svg"); i >= 0 {
		svg = svg[i:]
	}
	svg = strings.Replace(svg, "<svg", `<svg aria-hidden="true" focusable="false"`, 1)
	return template.HTML(svg) // #nosec G203 -- trusted SVG vendored into the repository at build time
}

// ---------- code citation ----------

func gitCommit() string {
	if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return "main"
}

func readLines(file string) []string {
	b, err := os.ReadFile(file)
	must(err)
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// citeFile quotes a whole source file.
func citeFile(file string) Cite {
	lines := readLines(file)
	c := Cite{File: file, Start: 1, End: len(lines)}
	for i, l := range lines {
		c.Lines = append(c.Lines, Line{i + 1, l})
	}
	c.Permalink = fmt.Sprintf("%s/blob/%s/%s#L%d-L%d", repoURL, commit, file, c.Start, c.End)
	return c
}

// citeFunc quotes one function or method, found by parsing the Go file, so
// the line numbers are always exact for the commit being built.
func citeFunc(file, name string) Cite {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	must(err)
	lines := readLines(file)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name {
			continue
		}
		start := fset.Position(fd.Pos()).Line
		if fd.Doc != nil {
			start = fset.Position(fd.Doc.Pos()).Line
		}
		end := fset.Position(fd.End()).Line
		c := Cite{File: file, Func: name, Start: start, End: end}
		for n := start; n <= end; n++ {
			c.Lines = append(c.Lines, Line{n, lines[n-1]})
		}
		c.Permalink = fmt.Sprintf("%s/blob/%s/%s#L%d-L%d", repoURL, commit, file, start, end)
		return c
	}
	log.Fatalf("function %s not found in %s", name, file)
	return Cite{}
}

// ---------- walkthrough ----------

type Module struct {
	Name, Path, Purpose string
	Points              []string
	Cites               []Cite
	Lines               int
}

func countLines(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") {
			n += len(readLines(p))
		}
		return nil
	})
	return n
}

func walkthrough() []Module {
	m := []Module{
		{Name: "Scope Guard", Path: "internal/scope", Purpose: "The security boundary. Every network connection the tool makes passes through here, and anything that is not a loopback address is refused before a single packet is sent.",
			Points: []string{"Host names are never resolved, only literal loopback IPs count, so /etc/hosts or DNS tricks cannot redirect a scan.", "The check runs on every dial, including HTTP redirects, and again on the connected peer as defence in depth.", "There is no flag to turn it off. The unit test proves remote addresses are refused."},
			Cites:  []Cite{citeFunc("internal/scope/scope.go", "IsLoopback"), citeFunc("internal/scope/scope.go", "CheckAddr"), citeFunc("internal/scope/scope.go", "DialContext")}},
		{Name: "System Access Layer", Path: "internal/sys", Purpose: "Checks never call the operating system directly. They receive a System with a small read-only interface, which makes the tool read-only by construction and lets the same check run against the real machine, a dry-run recorder or a simulated lab.",
			Points: []string{"There is no write, delete or restart operation in the interface to call.", "Commands must match an exact allow-list of read-only programs; php may only run echo ini_get() expressions.", "HTTP requests go to 127.0.0.1 with the site name as Host header, redirects are reported but never followed, and proxies are disabled."},
			Cites:  []Cite{citeFunc("internal/sys/sys.go", "IsAllowed"), citeFunc("internal/sys/sys.go", "safePHP"), citeFunc("internal/sys/sys.go", "NewLive")}},
		{Name: "Check Registry", Path: "internal/check", Purpose: "Defines what a check is: its id, severity, CVSS vector, rationale, detection logic, fix, verification step, references and standards mapping. Registration refuses checks with missing documentation or no citations.",
			Points: []string{"Each check records the file it is defined in, which is how this website cites its source.", "Severities follow the CVSS v3.1 qualitative scale."},
			Cites:  []Cite{citeFunc("internal/check/check.go", "Register")}},
		{Name: "Collectors", Path: "internal/checks/collect", Purpose: "Shared read-only discovery: the effective SSH configuration, kernel parameters from /proc/sys, listening sockets decoded from /proc/net, and the websites configured in Apache, nginx or LiteSpeed.",
			Points: []string{"Listening sockets are read from the kernel's own tables, not by port scanning.", "Websites are discovered from local configuration, which is what keeps web checks on this machine."},
			Cites:  []Cite{citeFunc("internal/checks/collect/collect.go", "parseProcAddr"), citeFunc("internal/checks/collect/collect.go", "VHosts")}},
		{Name: "Scan Engine", Path: "internal/engine", Purpose: "Runs the selected checks in parallel with a timeout each, turns a crash in one check into an Error result instead of stopping the scan, redacts secrets, and builds the report.",
			Points: []string{"Phases follow NIST SP 800-115 minus the attack phase.", "Results are sorted by status, then severity, so the most serious findings come first."},
			Cites:  []Cite{citeFunc("internal/engine/engine.go", "runOne"), citeFunc("internal/engine/engine.go", "overall")}},
		{Name: "Secret Redaction", Path: "internal/redact", Purpose: "Every message and evidence line passes through redaction before it is written, so reports can be shared without leaking passwords, keys, tokens or password hashes.",
			Cites: []Cite{citeFunc("internal/redact/redact.go", "String")}},
		{Name: "Reports", Path: "internal/report", Purpose: "Writes the report locally as self-contained HTML (prints to PDF), JSON, SARIF 2.1.0 and Markdown, with methodology and limitations in every report, and compares two reports to show what was fixed.",
			Cites: []Cite{citeFunc("internal/report/report.go", "Summarise"), citeFunc("internal/report/diff.go", "Diff")}},
		{Name: "Report Signing", Path: "internal/sign", Purpose: "Optional Ed25519 signature with a key generated and kept on the user's own machine, so a recipient can confirm a report was not edited. It proves integrity, never security.",
			Cites: []Cite{citeFunc("internal/sign/sign.go", "Sign"), citeFunc("internal/sign/sign.go", "Verify")}},
		{Name: "Simulated Lab", Path: "internal/lab", Purpose: "Two in-memory servers, one deliberately vulnerable and one hardened. 'openvapt demo' scans them safely on any computer, and the tests require every check to fail on the first and pass on the second.",
			Cites: []Cite{citeFunc("internal/engine/engine_test.go", "TestEveryCheckFiresOnVulnerableLab"), citeFunc("internal/engine/engine_test.go", "TestNoCheckFiresOnHardenedLab")}},
		{Name: "Command Line", Path: "cmd/openvapt", Purpose: "The user interface: scan, demo, checks, explain, diff, verify, terms. The scan asks the user to accept the terms each run (nothing is stored) and supports --dry-run to list every operation first.",
			Cites: []Cite{citeFunc("cmd/openvapt/main.go", "cmdScan")}},
	}
	for i := range m {
		m[i].Lines = countLines(m[i].Path)
	}
	return m
}

// ---------- standards ----------

type StdRow struct {
	Key, Name string
	IDs       []string
}

func counts(cs []*check.Check) map[string]int {
	m := map[string]int{"total": len(cs)}
	for _, c := range cs {
		m[string(c.Domain)]++
		m[string(c.Severity)]++
	}
	return m
}

func standards(cs []*check.Check) map[string][]StdRow {
	group := func(get func(*check.Check) []string, names map[string]string) []StdRow {
		idx := map[string][]string{}
		for _, c := range cs {
			for _, k := range get(c) {
				idx[k] = append(idx[k], c.ID)
			}
		}
		var rows []StdRow
		for k, ids := range idx {
			rows = append(rows, StdRow{Key: k, Name: names[k], IDs: ids})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
		return rows
	}
	owasp := map[string]string{"A01:2021": "Broken Access Control", "A02:2021": "Cryptographic Failures", "A03:2021": "Injection",
		"A04:2021": "Insecure Design", "A05:2021": "Security Misconfiguration", "A06:2021": "Vulnerable and Outdated Components",
		"A07:2021": "Identification and Authentication Failures", "A08:2021": "Software and Data Integrity Failures",
		"A09:2021": "Security Logging and Monitoring Failures", "A10:2021": "Server-Side Request Forgery"}
	return map[string][]StdRow{
		"OWASP": group(func(c *check.Check) []string { return c.Standards.OWASP }, owasp),
		"CWE":   group(func(c *check.Check) []string { return c.Standards.CWE }, nil),
		"NIST":  group(func(c *check.Check) []string { return c.Standards.NIST }, nil),
		"ASVS":  group(func(c *check.Check) []string { return c.Standards.ASVS }, nil),
		"WSTG":  group(func(c *check.Check) []string { return c.Standards.WSTG }, nil),
	}
}

// checksFor returns the checks a module applies, in catalogue order.
func checksFor(m *academy.Module) []*check.Check {
	var out []*check.Check
	for _, c := range check.All() {
		for _, r := range m.RelatedChecks {
			if c.ID == r || (strings.HasSuffix(r, "-") && strings.HasPrefix(c.ID, r)) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// catalogueRows is the data behind the AG Grid check catalogue.
func catalogueRows(cs []*check.Check) []map[string]string {
	var rows []map[string]string
	for _, c := range cs {
		rows = append(rows, map[string]string{
			"id": c.ID, "title": c.Title, "domain": string(c.Domain), "severity": string(c.Severity),
			"cwe": strings.Join(c.Standards.CWE, ", "), "owasp": strings.Join(c.Standards.OWASP, ", "),
			"category": check.CategoryByID(c.Category).Name, "effort": string(c.Effort), "wstg": strings.Join(c.Standards.WSTG, ", "),
		})
	}
	return rows
}

type nv struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// chartData feeds the ECharts charts on the home, standards and coverage pages.
func chartData(cs []*check.Check) map[string]any {
	n := counts(cs)
	sev := []nv{{"Critical", n["critical"]}, {"High", n["high"]}, {"Medium", n["medium"]}, {"Low", n["low"]}, {"Info", n["info"]}}
	dom := []nv{{"Server", n["host"]}, {"Network", n["network"]}, {"Web Apps", n["web"]}}
	var owasp []nv
	for _, r := range standards(cs)["OWASP"] {
		owasp = append(owasp, nv{r.Key + " " + r.Name, len(r.IDs)})
	}
	sevs := []check.Severity{check.Critical, check.High, check.Medium, check.Low, check.Info}
	var cats []string
	matrix := [][]int{} // [category][severity]
	cis := map[string]int{}
	csf := map[string]int{}
	for _, c := range check.Categories {
		cats = append(cats, c.Name)
		row := make([]int, len(sevs))
		for _, k := range cs {
			if k.Category != c.ID {
				continue
			}
			for i, sv := range sevs {
				if k.Severity == sv {
					row[i]++
				}
			}
			for _, x := range c.CIS {
				cis[x]++
			}
			for _, x := range c.NISTCSF {
				csf[x]++
			}
		}
		matrix = append(matrix, row)
	}
	toNV := func(m map[string]int, label func(string) string) []nv {
		var out []nv
		for k, v := range m {
			out = append(out, nv{label(k), v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}
	cisNames := map[string]string{"2": "Software Asset Inventory", "3": "Data Protection", "4": "Secure Configuration", "5": "Account Management", "6": "Access Control Management", "7": "Vulnerability Management", "8": "Audit Log Management", "12": "Network Infrastructure", "13": "Network Monitoring and Defense", "16": "Application Software Security"}
	csfNames := map[string]string{"PR.AA": "Identity Management, Authentication and Access Control", "PR.DS": "Data Security", "PR.PS": "Platform Security", "PR.IR": "Technology Infrastructure Resilience", "ID.RA": "Risk Assessment", "DE.CM": "Continuous Monitoring"}
	cisNV := toNV(cis, func(k string) string { return "CIS " + k + " " + cisNames[k] })
	sort.Slice(cisNV, func(i, j int) bool { return cisKey(cisNV[i].Name) < cisKey(cisNV[j].Name) })
	return map[string]any{"severity": sev, "domain": dom, "owasp": owasp, "categories": cats,
		"severities": []string{"Critical", "High", "Medium", "Low", "Info"}, "matrix": matrix,
		"cis": cisNV, "csf": toNV(csf, func(k string) string { return k + " " + csfNames[k] })}
}

// cisKey extracts the control number from "CIS 12 ..." for numeric sorting.
func cisKey(name string) int {
	f := strings.Fields(strings.TrimPrefix(name, "CIS "))
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return 0
	}
	return n
}

// ---------- SEO / GEO artefacts ----------

func jsonLD(p Page) template.JS {
	url := siteURL + "/" + strings.TrimSuffix(p.Path, "index.html")
	org := map[string]any{"@type": "Organization", "@id": siteURL + "/#org", "name": "OpenVAPT",
		"url": siteURL, "logo": siteURL + "/assets/icon.svg", "sameAs": []string{"https://github.com/OpenVAPT", repoURL},
		"description": "An academic, non-commercial project that publishes OpenVAPT, a free, AI-generated vulnerability assessment learning tool with source-available code. Not a business; provides no services."}
	site := map[string]any{"@type": "WebSite", "@id": siteURL + "/#website", "name": "OpenVAPT", "url": siteURL, "publisher": map[string]string{"@id": siteURL + "/#org"}, "inLanguage": "en"}
	app := map[string]any{"@type": "SoftwareApplication", "@id": siteURL + "/#software", "name": "OpenVAPT",
		"applicationCategory": "SecurityApplication", "applicationSubCategory": "Vulnerability Assessment Tool",
		"operatingSystem": "Linux", "url": siteURL, "downloadUrl": siteURL + "/download.html", "softwareVersion": p.Version,
		"description":         terms.Tagline + " Read-only checks for the Linux machine it runs on: server, network exposure and websites.",
		"isAccessibleForFree": true, "offers": map[string]any{"@type": "Offer", "price": "0", "priceCurrency": "USD"},
		"license": "https://polyformproject.org/licenses/noncommercial/1.0.0/", "publisher": map[string]string{"@id": siteURL + "/#org"},
		"keywords":    "free VAPT tool, VAPT learning, vulnerability assessment, source-available code, AI-generated, Linux security, server hardening, web security headers, academic, education",
		"featureList": []string{fmt.Sprintf("%d read-only checks", len(check.All())), "Server, network and web app coverage", "CVSS v3.1 ratings", "OWASP, CWE and NIST mapping", "HTML, JSON, SARIF and Markdown reports", "Loopback-only scope guard", "Simulated lab for learning", "Zero data collection"}}
	graph := []any{org, site}
	switch {
	case p.Path == "index.html":
		graph = append(graph, app, map[string]any{"@type": "SoftwareSourceCode", "name": "OpenVAPT source code", "codeRepository": repoURL,
			"programmingLanguage": "Go", "license": "https://polyformproject.org/licenses/noncommercial/1.0.0/", "targetProduct": map[string]string{"@id": siteURL + "/#software"}})
	case p.Path == "faq.html":
		var qs []any
		for _, f := range faqs {
			qs = append(qs, map[string]any{"@type": "Question", "name": f.Q, "acceptedAnswer": map[string]string{"@type": "Answer", "text": f.A}})
		}
		graph = append(graph, map[string]any{"@type": "FAQPage", "url": url, "mainEntity": qs})
	case p.Path == "academy/index.html":
		var parts []any
		for _, m := range academy.Modules {
			parts = append(parts, map[string]any{"@type": "LearningResource", "name": m.ID + ": " + m.Title, "url": siteURL + "/academy/" + strings.ToLower(m.ID) + ".html", "educationalLevel": string(m.Level), "timeRequired": fmt.Sprintf("PT%dM", m.Minutes)})
		}
		graph = append(graph, map[string]any{"@type": "Course", "name": "OpenVAPT Academy", "url": url, "description": p.Description,
			"provider": map[string]string{"@id": siteURL + "/#org"}, "isAccessibleForFree": true, "inLanguage": "en", "educationalLevel": "Beginner to Intermediate",
			"teaches": "Vulnerability assessment (VAPT) from theory to application", "hasPart": parts,
			"offers":            map[string]any{"@type": "Offer", "price": "0", "priceCurrency": "USD", "category": "Free"},
			"hasCourseInstance": map[string]any{"@type": "CourseInstance", "courseMode": "online", "courseWorkload": "PT5H"}})
	case strings.HasPrefix(p.Path, "academy/"):
		graph = append(graph, map[string]any{"@type": "LearningResource", "name": p.Title, "description": p.Description, "url": url,
			"isPartOf": map[string]string{"@type": "Course", "name": "OpenVAPT Academy", "url": siteURL + "/academy/"}, "isAccessibleForFree": true,
			"learningResourceType": "Lesson", "inLanguage": "en", "publisher": map[string]string{"@id": siteURL + "/#org"}})
	case p.Path == "glossary.html":
		var ts []any
		for _, t := range academy.Terms() {
			ts = append(ts, map[string]any{"@type": "DefinedTerm", "name": t, "description": academy.Glossary[t], "url": url + "#" + slug(t)})
		}
		graph = append(graph, map[string]any{"@type": "DefinedTermSet", "name": "VAPT Glossary", "url": url, "hasDefinedTerm": ts})
	case strings.HasPrefix(p.Path, "checks/") && p.Path != "checks/index.html":
		graph = append(graph, map[string]any{"@type": "TechArticle", "headline": p.Title, "description": p.Description, "url": url,
			"about": map[string]string{"@id": siteURL + "/#software"}, "publisher": map[string]string{"@id": siteURL + "/#org"}, "dateModified": p.Built, "inLanguage": "en"})
	default:
		graph = append(graph, map[string]any{"@type": "WebPage", "name": p.Title, "url": url, "description": p.Description,
			"isPartOf": map[string]string{"@id": siteURL + "/#website"}, "about": map[string]string{"@id": siteURL + "/#software"}, "dateModified": p.Built})
	}
	if p.Path != "index.html" {
		items := []any{map[string]any{"@type": "ListItem", "position": 1, "name": "OpenVAPT", "item": siteURL + "/"}}
		if strings.HasPrefix(p.Path, "checks/") && p.Path != "checks/index.html" {
			items = append(items, map[string]any{"@type": "ListItem", "position": 2, "name": "Check Catalogue", "item": siteURL + "/checks/"})
		}
		if strings.HasPrefix(p.Path, "academy/") && p.Path != "academy/index.html" {
			items = append(items, map[string]any{"@type": "ListItem", "position": 2, "name": "OpenVAPT Academy", "item": siteURL + "/academy/"})
		}
		if strings.HasPrefix(p.Path, "legal/") {
			items = append(items, map[string]any{"@type": "ListItem", "position": 2, "name": "Legal", "item": siteURL + "/legal/eula.html"})
		}
		items = append(items, map[string]any{"@type": "ListItem", "position": len(items) + 1, "name": p.Title, "item": url})
		graph = append(graph, map[string]any{"@type": "BreadcrumbList", "itemListElement": items})
	}
	b, _ := json.Marshal(map[string]any{"@context": "https://schema.org", "@graph": graph})
	return template.JS(b) // #nosec G203 -- json.Marshal escapes <, > and &
}

func writeSEO(paths []string, cs []*check.Check) {
	var sm strings.Builder
	sm.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range paths {
		if p == "404.html" {
			continue
		}
		fmt.Fprintf(&sm, "  <url><loc>%s/%s</loc><lastmod>%s</lastmod></url>\n", siteURL, strings.TrimSuffix(p, "index.html"), built.Format("2006-01-02"))
	}
	sm.WriteString("</urlset>\n")
	must(os.WriteFile(filepath.Join(*outDir, "sitemap.xml"), []byte(sm.String()), 0o644)) // #nosec G306 -- public website file

	robots := "User-agent: *\nAllow: /\n\n"
	for _, bot := range []string{"GPTBot", "ClaudeBot", "Claude-Web", "anthropic-ai", "PerplexityBot", "Google-Extended", "CCBot", "Applebot-Extended", "OAI-SearchBot", "ChatGPT-User"} {
		robots += "User-agent: " + bot + "\nAllow: /\n\n"
	}
	robots += "Sitemap: " + siteURL + "/sitemap.xml\n"
	if *noindex {
		robots = "User-agent: *\nDisallow: /\n"
	}
	must(os.WriteFile(filepath.Join(*outDir, "robots.txt"), []byte(robots), 0o644)) // #nosec G306 -- public website file

	var l strings.Builder
	l.WriteString("# OpenVAPT\n\n> OpenVAPT is a free, academic, non-commercial vulnerability assessment (VA) tool for Linux servers with source-available code, generated entirely by AI under human direction. It runs read-only checks on the machine it is installed on (and only that machine) to identify weaknesses in the server, its network exposure and its websites, rates findings with CVSS v3.1 and proposes cited fixes. It is made for learning how a VAPT tool works. It is not a business, not a penetration testing service and collects no data.\n\n")
	l.WriteString("Key facts:\n- Price: free. No account, no licence key.\n- Use: anyone, including companies, may use it on machines they own or control, for their own use. It may not be sold or used to provide services.\n- Risk: provided as is; users carry 100% of the risk.\n- Licence: PolyForm Noncommercial 1.0.0 plus an own-use permission (source-available).\n- Platform: Linux. Single static Go binary, standard library only.\n- Scope: loopback-only, enforced in code. Detection only, no exploit code.\n- Standards: NIST SP 800-115, CVSS v3.1, OWASP Top 10 2021, OWASP ASVS 4.0.3, CWE, NIST SP 800-53.\n- Source: " + repoURL + "\n- Built with AI assistance (Claude by Anthropic, via Claude Code) under the owner's direction.\n\n## Docs\n\n")
	for _, p := range [][2]string{{"faq.html", "FAQ"}, {"how-it-works.html", "How it is built, with code citations"}, {"checks/", "Check catalogue"}, {"standards.html", "Standards and methodology"}, {"compare.html", "Comparison with Lynis, OpenSCAP, OpenVAS, Nuclei, Trivy, ZAP"}, {"limits.html", "What it does not do"}, {"learn.html", "Lessons and lab"}, {"download.html", "Download and acknowledgements"}, {"no-data.html", "No data collected"}, {"legal/eula.html", "EULA"}, {"legal/disclaimer.html", "Disclaimer"}, {"legal/privacy.html", "Privacy Policy"}} {
		l.WriteString("- [" + p[1] + "](" + siteURL + "/" + p[0] + ")\n")
	}
	l.WriteString("\n## FAQ\n\n")
	for _, f := range faqs {
		l.WriteString("### " + f.Q + "\n" + f.A + "\n\n")
	}
	must(os.WriteFile(filepath.Join(*outDir, "llms.txt"), []byte(l.String()), 0o644)) // #nosec G306 -- public website file

	var full strings.Builder
	full.WriteString(l.String() + "\n## All checks\n\n")
	for _, c := range cs {
		fmt.Fprintf(&full, "### %s %s\n- Domain: %s, severity: %s, CVSS: %s\n- What: %s\n- Why: %s\n- How detected: %s\n- Fix: %s\n- Verify: %s\n- Source: %s/blob/%s/%s\n\n",
			c.ID, c.Title, c.Domain, c.Severity, c.CVSS, c.Summary, c.Rationale, c.Detection, c.Fix, c.Verify, repoURL, commit, c.SourceFile)
	}
	must(os.WriteFile(filepath.Join(*outDir, "llms-full.txt"), []byte(full.String()), 0o644)) // #nosec G306 -- public website file
}

// writeSampleReports scans the simulated lab servers with the real engine and
// publishes the reports, so visitors can see genuine output without running
// anything. These are simulations, never real machines.
func writeSampleReports() {
	for name, s := range map[string]sys.System{"vulnerable": lab.Vulnerable(), "hardened": lab.Hardened()} {
		r := engine.Run(context.Background(), s, engine.Options{})
		r.Scan.Host = "lab-" + name + " (simulated)"
		r.Scan.AsRoot = true
		_, err := r.WriteAll(filepath.Join(*outDir, "sample", name), []string{"html", "json", "sarif", "md"})
		must(err)
	}
	// WriteAll uses private permissions for real reports; samples are public.
	_ = filepath.WalkDir(filepath.Join(*outDir, "sample"), func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			mode := os.FileMode(0o644)
			if d.IsDir() {
				mode = 0o755
			}
			_ = os.Chmod(p, mode)
		}
		return nil
	})
}

// ---------- helpers ----------

func copyDir(src, dst string) {
	_ = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		must(err)
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(t, 0o755) // #nosec G301 -- public website output
		}
		b, err := os.ReadFile(p)
		must(err)
		return os.WriteFile(t, b, 0o644) // #nosec G306 -- public website file
	})
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
