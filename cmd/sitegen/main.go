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
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/engine"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
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
	must(os.MkdirAll(*outDir, 0o755))

	g := &gen{}

	checks := check.All()
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
		"ChartData":   chartData(checks),
	}
	pages := []struct{ file, path, title, desc, section string }{
		{"index.html", "index.html", "OpenVAPT, an Open Academic Vulnerability Assessment Tool", "OpenVAPT is a free, open academic project showing how a vulnerability assessment tool is built. Read every line, run it on your own Linux server, at your own risk.", "home"},
		{"how-it-works.html", "how-it-works.html", "How OpenVAPT Is Built", "A module by module walkthrough of the OpenVAPT source code, with every function cited to the exact file and line.", "built"},
		{"standards.html", "standards.html", "Standards and Methodology", "How OpenVAPT maps to NIST SP 800-115, CVSS v3.1, OWASP Top 10, OWASP ASVS, CWE and NIST SP 800-53.", "standards"},
		{"limits.html", "limits.html", "What OpenVAPT Does Not Do", "The deliberate limits of OpenVAPT: no exploitation, no remote targets, no data collection, not a penetration test.", "limits"},
		{"learn.html", "learn.html", "Learn Vulnerability Assessment", "Lessons on vulnerability assessment using OpenVAPT and its safe simulated lab servers.", "learn"},
		{"download.html", "download.html", "Download and Run OpenVAPT", "Build OpenVAPT from source or download a release, verify it, and run it on your own Linux machine.", "download"},
		{"contribute.html", "contribute.html", "Review, Report and Contribute", "Report bugs, false positives and new check ideas on GitHub, and how OpenVAPT versions and releases work.", "contribute"},
		{"cite.html", "cite.html", "Cite OpenVAPT", "How to cite OpenVAPT in academic work.", "cite"},
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
			map[string]any{"C": c, "Cite": cites[c.ID]})
	}

	// Legal pages are rendered from the Markdown files in the repository root,
	// so the website and the repository always say the same thing.
	for _, l := range []struct{ md, path, title, desc string }{
		{"EULA.md", "legal/eula.html", "End User Licence Agreement", "Terms for downloading and using OpenVAPT."},
		{"DISCLAIMER.md", "legal/disclaimer.html", "Disclaimer", "OpenVAPT is an academic project provided as is, at your own risk."},
		{"PRIVACY.md", "legal/privacy.html", "Privacy Policy", "OpenVAPT collects no personal data at all."},
		{"ACCEPTABLE_USE.md", "legal/acceptable-use.html", "Acceptable Use Policy", "How OpenVAPT may and may not be used."},
		{"LICENSING.md", "legal/licence.html", "Licence", "OpenVAPT is licensed under the PolyForm Noncommercial License 1.0.0 with an additional permission for own use."},
	} {
		b, err := os.ReadFile(l.md)
		must(err)
		g.page("legal/"+filepath.Base(l.path), l.path, l.title, l.desc, "legal",
			template.HTML(`<div class="legal"><h1>`+template.HTMLEscapeString(l.title)+`</h1>`+markdown(string(b))+`</div>`))
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
	g.page(file, path, title, desc, section, template.HTML(body.String()))
}

func (g *gen) page(_, path, title, desc, section string, body template.HTML) {
	p := pageFor(path, title, desc, section, body, nil)
	p.JSONLD = jsonLD(p)
	var out bytes.Buffer
	if err := newLayout().ExecuteTemplate(&out, "layout", p); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	dst := filepath.Join(*outDir, path)
	must(os.MkdirAll(filepath.Dir(dst), 0o755))
	must(os.WriteFile(dst, out.Bytes(), 0o644))
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
		"icon": icon,
		"json": func(v any) template.JS {
			b, err := json.Marshal(v) // escapes <, > and & so it is safe inside a script element
			must(err)
			return template.JS(b)
		},
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
	return template.HTML(svg) //nolint:gosec // trusted, vendored at build time
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
	}
}

// catalogueRows is the data behind the AG Grid check catalogue.
func catalogueRows(cs []*check.Check) []map[string]string {
	var rows []map[string]string
	for _, c := range cs {
		rows = append(rows, map[string]string{
			"id": c.ID, "title": c.Title, "domain": string(c.Domain), "severity": string(c.Severity),
			"cwe": strings.Join(c.Standards.CWE, ", "), "owasp": strings.Join(c.Standards.OWASP, ", "),
		})
	}
	return rows
}

type nv struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// chartData feeds the ECharts charts on the home and standards pages.
func chartData(cs []*check.Check) map[string][]nv {
	n := counts(cs)
	sev := []nv{{"Critical", n["critical"]}, {"High", n["high"]}, {"Medium", n["medium"]}, {"Low", n["low"]}, {"Info", n["info"]}}
	dom := []nv{{"Server", n["host"]}, {"Network", n["network"]}, {"Web Apps", n["web"]}}
	var owasp []nv
	for _, r := range standards(cs)["OWASP"] {
		owasp = append(owasp, nv{r.Key + " " + r.Name, len(r.IDs)})
	}
	return map[string][]nv{"severity": sev, "domain": dom, "owasp": owasp}
}

// ---------- SEO / GEO artefacts ----------

func jsonLD(p Page) template.JS {
	url := siteURL + "/" + strings.TrimSuffix(p.Path, "index.html")
	var doc any
	if p.Path == "index.html" {
		doc = map[string]any{
			"@context": "https://schema.org", "@graph": []any{
				map[string]any{"@type": "SoftwareApplication", "name": "OpenVAPT", "applicationCategory": "SecurityApplication",
					"operatingSystem": "Linux", "url": siteURL, "description": p.Description, "softwareVersion": p.Version,
					"isAccessibleForFree": true, "offers": map[string]any{"@type": "Offer", "price": "0", "priceCurrency": "USD"},
					"license": "https://polyformproject.org/licenses/noncommercial/1.0.0/"},
				map[string]any{"@type": "SoftwareSourceCode", "name": "OpenVAPT source code", "codeRepository": repoURL,
					"programmingLanguage": "Go", "license": "https://polyformproject.org/licenses/noncommercial/1.0.0/"},
			}}
	} else {
		doc = map[string]any{"@context": "https://schema.org", "@type": "WebPage", "name": p.Title, "url": url, "description": p.Description,
			"isPartOf": map[string]any{"@type": "WebSite", "name": "OpenVAPT", "url": siteURL}}
	}
	b, _ := json.Marshal(doc)
	return template.JS(b)
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
	must(os.WriteFile(filepath.Join(*outDir, "sitemap.xml"), []byte(sm.String()), 0o644))

	robots := "User-agent: *\nAllow: /\n\n"
	for _, bot := range []string{"GPTBot", "ClaudeBot", "Claude-Web", "anthropic-ai", "PerplexityBot", "Google-Extended", "CCBot", "Applebot-Extended", "OAI-SearchBot", "ChatGPT-User"} {
		robots += "User-agent: " + bot + "\nAllow: /\n\n"
	}
	robots += "Sitemap: " + siteURL + "/sitemap.xml\n"
	if *noindex {
		robots = "User-agent: *\nDisallow: /\n"
	}
	must(os.WriteFile(filepath.Join(*outDir, "robots.txt"), []byte(robots), 0o644))

	var l strings.Builder
	l.WriteString("# OpenVAPT\n\n> OpenVAPT is an open, free, academic project that shows how a vulnerability assessment tool is designed, built and tested. It runs read-only checks on the Linux machine it is installed on, and only that machine. It is not a penetration testing service. It collects no data.\n\n")
	l.WriteString("- Licence: PolyForm Noncommercial 1.0.0 with an additional permission: anyone, including companies, may use it on their own machines for their own use; not for providing services or selling.\n- Source: " + repoURL + "\n- Risk: provided as is; users carry 100% of the risk.\n\n## Pages\n\n")
	for _, p := range []string{"how-it-works.html", "checks/", "standards.html", "limits.html", "learn.html", "download.html", "no-data.html", "legal/eula.html", "legal/disclaimer.html", "legal/privacy.html"} {
		l.WriteString("- " + siteURL + "/" + p + "\n")
	}
	must(os.WriteFile(filepath.Join(*outDir, "llms.txt"), []byte(l.String()), 0o644))

	var full strings.Builder
	full.WriteString(l.String() + "\n## All checks\n\n")
	for _, c := range cs {
		fmt.Fprintf(&full, "### %s %s\n- Domain: %s, severity: %s, CVSS: %s\n- What: %s\n- Why: %s\n- How detected: %s\n- Fix: %s\n- Verify: %s\n- Source: %s/blob/%s/%s\n\n",
			c.ID, c.Title, c.Domain, c.Severity, c.CVSS, c.Summary, c.Rationale, c.Detection, c.Fix, c.Verify, repoURL, commit, c.SourceFile)
	}
	must(os.WriteFile(filepath.Join(*outDir, "llms-full.txt"), []byte(full.String()), 0o644))
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
			return os.MkdirAll(t, 0o755)
		}
		b, err := os.ReadFile(p)
		must(err)
		return os.WriteFile(t, b, 0o644)
	})
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
