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
	"github.com/openvapt/openvapt/internal/channels"
	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/engine"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/terms"
)

const (
	siteURL = "https://openvapt.com"
	repoURL = "https://github.com/OpenVAPT/openvapt" // exact case GitHub shows, so no link is rewritten
)

var (
	outDir      = flag.String("out", "dist/site", "output directory")
	base        = flag.String("base", "/", "URL path the site is served under (the public site uses /)")
	noindex     = flag.Bool("noindex", false, "add noindex to every page (automatic until the owner approves the public launch)")
	unpinned    = flag.Bool("allow-unpinned", false, "build even when no git commit can be resolved (code citations then point at the main branch, not a pinned commit)")
	commit      string
	built       = time.Now().UTC()
	siteChannel siteChannels
)

// Page is the data every template receives.
type Page struct {
	Title, Description, Path, Section  string
	Base, Commit, CommitShort, Version string
	Built                              string
	LastMod                            string // date the page's inputs last changed in git (build date when unknown)
	NoIndex                            bool   // whole build is noindex (only before launch approval, or when -noindex is passed)
	NoIndexPage                        bool   // this page alone is noindex (404)
	Canonical                          string // absolute URL of this page; empty when it has none (404)
	Root                               string // absolute URL of the site root, siteURL + base, no trailing slash
	Channel                            string // most mature released channel, or Pre-Release
	PreRelease                         bool
	JSONLD                             template.JS
	PageCite                           []CiteBox // set on check and Academy module pages
	Published                          string    // date the page's inputs first appeared in git (datePublished)
	Markdown                           string    // URL path of the page's Markdown twin, when it has one
	Article                            bool      // check and Academy module pages: og:type article
	AltJSON                            string    // URL path of a JSON dataset that mirrors the page (check catalogue)
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

	chans := loadChannels()
	siteChannel = chans
	siteFeatures = featuresFor(chans)
	applyFeatures(siteFeatures, faqs)

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
		"Checks":       checks,
		"Counts":       counts(checks),
		"Walkthrough":  walkthrough(),
		"Standards":    standards(checks),
		"Repo":         repoURL,
		"Catalogue":    catalogueRows(checks),
		"Categories":   check.Categories,
		"Pillars":      terms.Pillars,
		"Acks":         terms.Acknowledgements,
		"TermsVer":     terms.Version,
		"FAQ":          faqs,
		"Levels":       academy.Levels(),
		"Modules":      academy.Modules,
		"Glossary":     academy.Glossary,
		"Terms":        academy.Terms(),
		"ChartData":    chartData(checks),
		"Channels":     chans,
		"Courses":      academy.Courses,
		"Rubric":       academy.Rubric,
		"RubricLevels": academy.RubricLevels,
		"CiteStyles":   citeStyles(),
		"CiteExtras":   citeExtras(),
		"CiteVersion":  citeVersion(),
		"Install":      installBoxes(chans),
		"CiteHero":     citeHero(),
		"Features":     siteFeatures,
		"IndexNowKey":  indexNowKey(),
	}
	pages := []struct{ file, path, title, desc, section string }{
		{"index.html", "index.html", "OpenVAPT, an Academic Vulnerability Assessment Tool", "Academic, non-commercial VAPT tool with source-available code built by AI Cybersecurity Engineers. Free for own use on your Linux server, 100% at your own risk.", "home"},
		{"how-it-works.html", "how-it-works.html", "How OpenVAPT Is Built", "A module by module walkthrough of the OpenVAPT source code, with every function cited to the exact file and line.", "built"},
		{"standards.html", "standards.html", "Standards and Methodology", "How OpenVAPT maps to NIST SP 800-115, CVSS v3.1, OWASP Top 10, OWASP ASVS, CWE and NIST SP 800-53.", "standards"},
		{"limits.html", "limits.html", "What OpenVAPT Does Not Do", "The deliberate limits of OpenVAPT: no exploitation, no remote targets, no data collection, not a penetration test.", "limits"},
		{"learn.html", "learn.html", "Learn Vulnerability Assessment", "Lessons on vulnerability assessment using OpenVAPT and its safe simulated lab servers.", "learn"},
		{"download.html", "download.html", "Download and Run OpenVAPT", "Download Only, or Download and Scan in one command: verify and install OpenVAPT, or build it from source, and assess your own Linux machine.", "download"},
		{"contribute.html", "contribute.html", "Review, Report and Contribute", "Report bugs, false positives and new check ideas on GitHub, and how OpenVAPT versions and releases work.", "contribute"},
		{"cite.html", "cite.html", "How to Cite OpenVAPT", "Copy a ready-made OpenVAPT citation in APA, IEEE, Harvard, MLA, Chicago, Vancouver, BibTeX, RIS or CSL-JSON, with version, commit and credit lines.", "cite"},
		{"coverage.html", "coverage.html", "Coverage Dashboard: What It Assesses", "Interactive coverage of OpenVAPT's checks by control category and severity, mapped to CIS Controls v8, NIST CSF 2.0, OWASP Top 10 and OWASP WSTG.", "coverage"},
		{"teach.html", "teach.html", "For Teachers: Teach Vulnerability Assessment", "Free course plans, printable worksheets and answer keys, a marking rubric and per-student practice labs for teaching vulnerability assessment with OpenVAPT.", "teach"},
		{"channels.html", "channels.html", "Release Channels: Alpha to Stable", "How OpenVAPT moves from Alpha to Beta, Release Candidate and Stable, the evidence each gate requires, and the current build in every channel.", "channels"},
		{"faq.html", "faq.html", "FAQ: Free Academic VAPT Tool Questions", "Answers about OpenVAPT, the free academic vulnerability assessment tool for Linux: cost, licence, company use, scope, safety, standards and data.", "faq"},
		{"compare.html", "compare.html", "Compared With Lynis, OpenSCAP, OpenVAS and ZAP", "How OpenVAPT, a free academic VAPT learning tool, compares with Lynis, OpenSCAP, OpenVAS, Nuclei, Trivy and OWASP ZAP, and when to use each.", "compare"},
		{"machine.html", "machine-readable.html", "For Machines and AI: Every Data File", "Every machine-readable file openvapt.com publishes: sitemap, Atom feed, llms.txt, Markdown twins, JSON catalogue, codemeta.json, security.txt and more.", "machine"},
		{"privacy-notice.html", "no-data.html", "We Collect No Data", "OpenVAPT and openvapt.com collect no data: no cookies, no analytics, no logs, no forms, no accounts.", "nodata"},
		{"404.html", "404.html", "Page Not Found", "This page does not exist. Try the OpenVAPT check catalogue or the home page.", ""},
	}
	layoutFile := "site/templates/layout.html"
	for _, p := range pages {
		g.inputs = []string{"site/content/" + p.file, layoutFile, "cmd/sitegen"}
		g.content(p.file, p.path, p.title, p.desc, p.section, data)
	}

	// Check catalogue.
	g.inputs = []string{"site/content/checks.html", layoutFile, "internal/checks"}
	g.content("checks.html", "checks/index.html", "Check Catalogue", fmt.Sprintf("All %d OpenVAPT checks with their rationale, detection logic, fix, references and source code.", len(checks)), "checks", data)
	descs := checkDescs(checks)
	for _, c := range checks {
		g.inputs = []string{c.SourceFile, "site/content/check.html", layoutFile}
		g.render("check.html", "checks/"+c.ID+".html", shortTitle(c.ID+" "+c.Title), descs[c.ID], "checks",
			map[string]any{"C": c, "Cite": cites[c.ID], "Learn": academy.ForCheck(c.ID), "PageCite": pageCite(c.ID, c.ID+" "+c.Title, "OpenVAPT Check Catalogue", "checks/"+c.ID+".html")})
	}

	// OpenVAPT Academy: course index, one page per module, and the glossary.
	acad := append(academyFiles(), layoutFile)
	g.inputs = append([]string{"site/content/academy.html"}, acad...)
	g.render("academy.html", "academy/index.html", "Academy: Learn VAPT From Theory to Application", trimDesc(fmt.Sprintf("A free %d-module course that teaches vulnerability assessment from security basics to running, fixing, reporting and building checks, with a safe simulated lab.", len(academy.Modules))), "academy", data)
	for i := range academy.Modules {
		m := &academy.Modules[i]
		var prev, next *academy.Module
		if i > 0 {
			prev = &academy.Modules[i-1]
		}
		if i+1 < len(academy.Modules) {
			next = &academy.Modules[i+1]
		}
		g.inputs = append([]string{"site/content/module.html"}, acad...)
		g.render("module.html", "academy/"+strings.ToLower(m.ID)+".html", shortTitle(m.ID+": "+m.Title), padDesc(trimDesc(m.Summary), "A free OpenVAPT Academy module."), "academy",
			map[string]any{"M": m, "Checks": checksFor(m), "Prev": prev, "Next": next, "Glossary": academy.Glossary,
				"PageCite": pageCite(m.ID, m.ID+": "+m.Title, "OpenVAPT Academy", "academy/"+strings.ToLower(m.ID)+".html")})
		// Printable worksheet and teacher answer key for every module.
		for _, w := range []struct {
			answers   bool
			prefix, t string
		}{{false, "worksheet-", "Worksheet"}, {true, "key-", "Answer Key"}} {
			path := "academy/" + w.prefix + strings.ToLower(m.ID) + ".html"
			g.inputs = acad
			g.page(path, path, shortTitle(m.ID+" "+w.t+": "+m.Title), trimDesc("Printable "+strings.ToLower(w.t)+" for OpenVAPT Academy module "+m.ID+", "+m.Title+", for free teaching use."), "teach",
				template.HTML(`<div class="legal worksheet"><p class="muted no-print"><a href="../teach.html">For Teachers</a> &middot; <a href="`+strings.ToLower(m.ID)+`.html">Back to the Module</a> &middot; Print with your browser's Print command.</p><h1>`+template.HTMLEscapeString(m.ID+" "+map[bool]string{false: "Worksheet", true: "Teacher Answer Key"}[w.answers]+": "+m.Title)+`</h1>`+markdown(academy.Worksheet(m, w.answers))+`</div>`)) // #nosec G203 -- markdown() HTML-escapes all text first
		}
	}
	g.inputs = append([]string{"site/content/glossary.html"}, acad...)
	g.render("glossary.html", "glossary.html", "VAPT Glossary: Assessment Terms Explained", "Plain-language definitions of vulnerability assessment and penetration testing terms, from ASLR and CVSS to TLS and VAPT.", "academy", data)

	// Legal pages are rendered from the Markdown files in the repository root,
	// so the website and the repository always say the same thing.
	legal := []struct{ md, path, title, desc string }{
		{"EULA.md", "legal/eula.html", "End User Licence Agreement", "Terms for downloading and using OpenVAPT, free for own use at your own risk."},
		{"DISCLAIMER.md", "legal/disclaimer.html", "Disclaimer", "OpenVAPT is an academic project provided as is, at your own risk."},
		{"PRIVACY.md", "legal/privacy.html", "Privacy Policy", "OpenVAPT and openvapt.com collect no personal data: no cookies, no analytics, no forms."},
		{"ACCEPTABLE_USE.md", "legal/acceptable-use.html", "Acceptable Use Policy", "How OpenVAPT may and may not be used: only on machines you own or control."},
		{"LICENSING.md", "legal/licence.html", "Licence", "How OpenVAPT is licensed: the OpenVAPT Source-Available Licence 1.3, for own use only, with no services and no selling."},
		{"LICENSE", "legal/licence-text.html", "OpenVAPT Source-Available Licence 1.3", "The full text of the OpenVAPT Source-Available Licence 1.3, the only licence under which OpenVAPT is made available."},
		{"AI-DISCLOSURE.md", "legal/ai-disclosure.html", "AI Disclosure", "OpenVAPT is built entirely by AI Cybersecurity Engineers under human direction: which AI systems built it, what the owner did and what is not reviewed."},
		{"TEACHING.md", "legal/teaching.html", "Teaching With OpenVAPT", "What teachers, schools, colleges and universities may do with OpenVAPT and its Academy, free, and what stays excluded."},
		{"CITING.md", "legal/citing.html", "Citing OpenVAPT", "The canonical guide to crediting and citing OpenVAPT: when credit is required, when citation is requested, and every citation style."},
		{"CREDITS.md", "legal/credits.html", "Credits, Sources and Citations", "Every component, tool, standard, source and AI system OpenVAPT uses or refers to, cited precisely."},
		{"SOURCES.md", "legal/sources.html", "Sources Cited by Checks and the Academy", "Every public source OpenVAPT's checks and Academy cite, grouped by publisher, with terms, credit lines and the checks citing each. Generated from code."},
		{"GOVERNANCE-CONTROL-ASSURANCE.md", "legal/governance.html", "Governance, Control and Assurance", "How OpenVAPT's AI Cybersecurity Engineers and its owner decide, what controls enforce, and how outcomes are verified and audited."},
		{"AGENTS.md", "legal/agents.html", "AI Cybersecurity Engineer Policy", "The binding policy for every AI Cybersecurity Engineer working on OpenVAPT: what is always allowed, what needs the owner, and what is never allowed."},
	}
	for _, l := range legal {
		mdPages[l.md] = filepath.Base(l.path)
	}
	// Documents that carry a version and effective date also say which version
	// governs a given copy (LICENSE sections 12 and 15; EULA section 27).
	versioned := map[string]bool{"EULA.md": true, "DISCLAIMER.md": true, "PRIVACY.md": true, "ACCEPTABLE_USE.md": true, "LICENSING.md": true, "LICENSE": true, "TEACHING.md": true, "CITING.md": true}
	const versionNote = `<p class="muted">This is the current published version. The version that travels with your copy of OpenVAPT governs that copy (licence sections 12 and 15; EULA section 27). Earlier versions are in the public Git history.</p>`
	for _, l := range legal {
		b, err := os.ReadFile(l.md)
		must(err)
		g.inputs = []string{l.md, layoutFile, "cmd/sitegen/markdown.go"}
		note := ""
		if versioned[l.md] {
			note = versionNote
		}
		g.page("legal/"+filepath.Base(l.path), l.path, l.title, l.desc, "legal",
			template.HTML(`<div class="legal"><h1>`+template.HTMLEscapeString(l.title)+`</h1>`+note+markdown(string(b))+`</div>`)) // #nosec G203 -- markdown() HTML-escapes all text first
	}

	// The VAPT skill for AI assistants: one page rendered from SKILL.md and its
	// references, plus the raw files so an assistant can install them as-is.
	skillHTML, skillInputs := renderSkill(*outDir)
	g.inputs = append(skillInputs, layoutFile, "cmd/sitegen/markdown.go")
	g.page("vapt-skill.html", "vapt-skill.html", "VAPT Skill for AI Assistants: Assess and Defend", "A free skill that teaches AI assistants to assess and defend your own Linux machine with OpenVAPT: scope gate, read-only checks, CVSS, fixes, re-scan, report.", "machine", skillHTML)

	if len(g.problems) > 0 {
		log.Fatalf("%d page(s) break the title or description length rules (title with suffix <= %d, description %d to %d characters); fix them above", len(g.problems), maxTitle, minDesc, maxDesc)
	}

	writeSampleReports()
	copyDir("site/static", *outDir)
	writeCiteFiles()
	writeCatalogueJSON(checks)
	writeSecurityTxt()
	writeSEO(g.paths, g.mods, checks)
	writeMarkdownTwins(checks, g.mods)
	writeFeed(chans)
	writeManifest()
	writeCodemeta(checks)
	fmt.Printf("Built %d pages into %s (commit %s)\n", len(g.paths), *outDir, commit[:min(12, len(commit))])
}

type gen struct {
	paths    []string
	problems []string
	inputs   []string          // source files of the page being rendered (for lastmod)
	mods     map[string]string // path -> lastmod date
	pageCite []CiteBox         // Cite This Page boxes of the page being rendered, for the header and footer Cite panels
}

// Search snippet limits checked at build time for every page.
const (
	maxTitle = 65  // whole <title>, including the " - OpenVAPT" suffix
	minDesc  = 50  // shortest useful meta description
	maxDesc  = 160 // longest meta description before search engines cut it
	titleFit = 60 - len(titleSuffix)
)

const titleSuffix = " - OpenVAPT"

// fullTitle is the text of the <title> element the layout renders.
func fullTitle(path, title string) string {
	if path == "index.html" {
		return title
	}
	return title + titleSuffix
}

// shortTitle cuts a title at a word boundary so the whole <title> stays within
// 60 characters. It is used for <title> only; the page heading keeps the full text.
func shortTitle(s string) string {
	return cutWords(s, titleFit, "")
}

// trimDesc cuts a description at a word boundary to at most maxDesc characters.
func trimDesc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxDesc {
		return s
	}
	return cutWords(strings.TrimRight(s, "."), maxDesc-1, ".")
}

// padDesc appends a fixed sentence when a description is too short to be useful.
func padDesc(s, extra string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) >= minDesc {
		return s
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return trimDesc(s + " " + extra)
}

// cutWords shortens s to at most n bytes (including end) at a word boundary.
func cutWords(s string, n int, end string) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n-len(end)]
	if i := strings.LastIndex(cut, " "); i > 0 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,:;-") + end
}

// root is the absolute URL the site is served from, without a trailing slash:
// https://openvapt.com for the public site; a sub-path when -base is set.
func root() string {
	return siteURL + strings.TrimSuffix(*base, "/")
}

// pageURL is the absolute URL of a generated file, with index.html dropped.
func pageURL(path string) string {
	return root() + "/" + strings.TrimSuffix(path, "index.html")
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
	if m, ok := data.(map[string]any); ok {
		g.pageCite, _ = m["PageCite"].([]CiteBox)
	}
	g.page(file, path, title, desc, section, template.HTML(body.String())) // #nosec G203 -- output of html/template, already escaped
}

func (g *gen) page(_, path, title, desc, section string, body template.HTML) {
	if t := fullTitle(path, title); len(t) > maxTitle {
		g.problems = append(g.problems, path)
		log.Printf("%s: title is %d characters (max %d): %q", path, len(t), maxTitle, t)
	}
	if len(desc) < minDesc || len(desc) > maxDesc {
		g.problems = append(g.problems, path)
		log.Printf("%s: description is %d characters (want %d to %d): %q", path, len(desc), minDesc, maxDesc, desc)
	}
	p := pageFor(path, title, desc, section, body, nil)
	p.PageCite, g.pageCite = g.pageCite, nil
	if len(g.inputs) > 0 {
		p.LastMod = lastMod(g.inputs...)
		p.Published = firstMod(g.inputs...)
	}
	if p.Published == "" {
		p.Published = p.LastMod
	}
	if g.mods == nil {
		g.mods = map[string]string{}
	}
	g.mods[path] = p.LastMod
	if path != "404.html" {
		p.JSONLD = jsonLD(p)
	}
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
	p := Page{Title: title, Description: desc, Path: path, Section: section, Base: *base,
		Commit: commit, CommitShort: commit[:min(12, len(commit))], Version: "v" + citeVersion(),
		Built: built.Format("2006-01-02"), LastMod: built.Format("2006-01-02"), NoIndex: *noindex, Body: body, Data: data,
		Channel: siteChannel.Highest, PreRelease: !siteChannel.Stable,
		NoIndexPage: path == "404.html", Root: root()}
	if path != "404.html" {
		p.Canonical = pageURL(path)
	}
	if t := mdTwin(path); t != "" {
		p.Markdown = *base + t
	}
	p.Article = (strings.HasPrefix(path, "checks/") || strings.HasPrefix(path, "academy/")) && p.Markdown != ""
	if path == "checks/index.html" {
		p.AltJSON = *base + "checks/catalogue.json"
	}
	return p
}

func funcs() template.FuncMap {
	return template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"join":  strings.Join,
		"title": func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
		"repo":  func() string { return repoURL },
		// asset adds a content hash to a file under site/static/assets so a
		// deploy invalidates browser caches (the server caches assets for days).
		"asset":   assetVersioned,
		"vendorv": vendorVersion,
		"blob": func(file string) string {
			// GitHub serves folders under /tree/ and files under /blob/;
			// using the right one keeps every link exact (no redirect).
			if fi, err := os.Stat(file); err == nil && fi.IsDir() {
				return repoURL + "/tree/" + commit + "/" + file
			}
			return repoURL + "/blob/" + commit + "/" + file
		},
		"cwe": func(id string) string {
			return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(id, "CWE-") + ".html"
		},
		"icon":      icon,
		"tagline":   func() string { return terms.Tagline },
		"add":       func(a, b int) int { return a + b },
		"slug":      slug,
		"hasPrefix": strings.HasPrefix,
		"quick":     quickCite, "printCite": printCite,
		"json": func(v any) template.JS {
			b, err := json.Marshal(v) // escapes <, > and & so it is safe inside a script element
			must(err)
			return template.JS(b) // #nosec G203 -- json.Marshal escapes <, > and &
		},
		"catName":    func(c check.Category) string { return check.CategoryByID(c).Name },
		"chanName":   func(c channels.Channel) string { return channels.InfoFor(c).Name },
		"chartTable": chartTable,
		"ogImage":    func() string { return root() + "/assets/og-image.png" },
		"catInfo":    check.CategoryByID,
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

// gitCommit pins every code citation to the commit being built. A build that
// cannot resolve one fails, because unpinned links would silently drift from
// the quoted code; -allow-unpinned opts out for builds outside a git checkout.
func gitCommit() string {
	if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		if c := strings.TrimSpace(string(out)); c != "" {
			return c
		}
	}
	if *unpinned {
		log.Print("warning: no git commit found; code citations point at the main branch (-allow-unpinned)")
		return "main"
	}
	log.Fatal("cannot resolve the git commit (git rev-parse HEAD failed); run inside the git checkout, or pass -allow-unpinned to build with links to the main branch")
	return ""
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
		}
		matrix = append(matrix, row)
	}
	// Framework coverage counts each check toward the safeguard and the CSF
	// subcategories it maps itself (audit A2-08), never toward a whole
	// control through its category.
	for _, k := range cs {
		for _, x := range k.Standards.CIS {
			if x != check.CISNone {
				cis[x]++
			}
		}
		for _, x := range k.Standards.CSF {
			csf[x]++
		}
	}
	toNV := func(m map[string]int, label func(string) string) []nv {
		var out []nv
		for k, v := range m {
			out = append(out, nv{label(k), v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}
	cisNV := toNV(cis, func(k string) string { return "CIS " + k + " " + check.CISSafeguards[k] })
	sort.Slice(cisNV, func(i, j int) bool { return cisKey(cisNV[i].Name) < cisKey(cisNV[j].Name) })
	return map[string]any{"severity": sev, "domain": dom, "owasp": owasp, "categories": cats,
		"severities": []string{"Critical", "High", "Medium", "Low", "Info"}, "matrix": matrix,
		"cis": cisNV, "csf": toNV(csf, func(k string) string { return k + " " + check.CSFSubcategories[k] })}
}

// cisKey turns "CIS 12.3 ..." into 12003 for numeric sorting by control,
// then safeguard.
func cisKey(name string) int {
	f := strings.Fields(strings.TrimPrefix(name, "CIS "))
	if len(f) == 0 {
		return 0
	}
	ctl, sg, _ := strings.Cut(f[0], ".")
	n, err := strconv.Atoi(ctl)
	if err != nil {
		return 0
	}
	m, _ := strconv.Atoi(sg)
	return n*1000 + m
}

// ---------- SEO / GEO artefacts ----------

func jsonLD(p Page) template.JS {
	siteURL := root() // https://openvapt.com, plus the -base path if one is set
	url := pageURL(p.Path)
	org := map[string]any{"@type": "Organization", "@id": siteURL + "/#org", "name": "OpenVAPT",
		"url": siteURL + "/", "logo": map[string]any{"@type": "ImageObject", "url": siteURL + "/assets/icon-512.png", "width": 512, "height": 512}, "image": siteURL + "/assets/og-image.png", "sameAs": []string{"https://github.com/OpenVAPT", repoURL},
		"description": "An academic, non-commercial project that publishes OpenVAPT, a free vulnerability assessment learning tool with source-available code, researched, developed and built by AI Cybersecurity Engineers under human direction. Not a business; provides no services."}
	site := map[string]any{"@type": "WebSite", "@id": siteURL + "/#website", "name": "OpenVAPT", "url": siteURL + "/", "publisher": map[string]string{"@id": siteURL + "/#org"}, "inLanguage": "en"}
	app := map[string]any{"@type": "SoftwareApplication", "@id": siteURL + "/#software", "name": "OpenVAPT",
		"applicationCategory": "SecurityApplication", "applicationSubCategory": "Vulnerability Assessment Tool",
		"operatingSystem": "Linux", "audience": map[string]any{"@type": "Audience", "audienceType": "Students, teachers, system administrators and organisations worldwide", "geographicArea": map[string]string{"@type": "Place", "name": "Worldwide"}}, "url": siteURL + "/", "downloadUrl": siteURL + "/download.html", "softwareVersion": p.Version,
		"description":         terms.Tagline + " Read-only checks for the Linux machine it runs on: server, network exposure and websites.",
		"isAccessibleForFree": true, "offers": map[string]any{"@type": "Offer", "price": "0", "priceCurrency": "USD"},
		"license": siteURL + "/legal/licence-text.html", "publisher": map[string]string{"@id": siteURL + "/#org"},
		"author": map[string]string{"@id": siteURL + "/#org"}, "image": siteURL + "/assets/og-image.png", "sameAs": []string{repoURL},
		"releaseNotes": siteURL + "/channels.html", "softwareHelp": map[string]string{"@type": "CreativeWork", "url": siteURL + "/faq.html"},
		"installUrl": siteURL + "/download.html", "softwareRequirements": "Linux; no runtime dependencies (single static binary)",
		"keywords":    "free VAPT tool, VAPT learning, vulnerability assessment, source-available code, built by AI Cybersecurity Engineers, Linux security, server hardening, web security headers, academic, education",
		"featureList": []string{fmt.Sprintf("%d read-only checks", len(check.All())), "Server, network and web app coverage", "CVSS v3.1 ratings", "OWASP, CWE and NIST mapping", "HTML, JSON, SARIF and Markdown reports", "Loopback-only scope guard", "Simulated lab for learning", "Zero data collection"}}
	graph := []any{org, site}
	switch {
	case p.Path == "index.html":
		graph = append(graph, app, map[string]any{"@type": "SoftwareSourceCode", "name": "OpenVAPT source code", "codeRepository": repoURL,
			"programmingLanguage": "Go", "license": siteURL + "/legal/licence-text.html", "targetProduct": map[string]string{"@id": siteURL + "/#software"}},
			map[string]any{"@type": "WebPage", "@id": url + "#webpage", "url": url, "name": p.Title, "description": p.Description, "isPartOf": map[string]string{"@id": siteURL + "/#website"},
				"about": map[string]string{"@id": siteURL + "/#software"}, "datePublished": p.Published, "dateModified": p.LastMod, "inLanguage": "en",
				"speakable": map[string]any{"@type": "SpeakableSpecification", "cssSelector": []string{".hero h1", ".hero .lead"}}})
	case p.Path == "cite.html":
		v := citeVersion()
		graph = append(graph, map[string]any{"@type": "WebPage", "name": p.Title, "url": url, "description": p.Description,
			"isPartOf": map[string]string{"@id": siteURL + "/#website"}, "about": map[string]string{"@id": siteURL + "/#source"}, "dateModified": p.LastMod},
			map[string]any{"@type": "SoftwareSourceCode", "@id": siteURL + "/#source", "name": citeTitle, "alternateName": "OpenVAPT",
				"codeRepository": repoURL, "url": siteURL + "/", "programmingLanguage": "Go", "version": v, "softwareVersion": v,
				"author": map[string]string{"@id": siteURL + "/#org"}, "publisher": map[string]string{"@id": siteURL + "/#org"},
				"copyrightHolder": map[string]string{"@id": siteURL + "/#org"}, "copyrightYear": citeYear(),
				"license": siteURL + "/legal/licence-text.html", "isAccessibleForFree": true, "inLanguage": "en",
				"creditText": citeWork().APA(),
				"identifier": repoURL + "/tree/" + commit, "targetProduct": map[string]string{"@id": siteURL + "/#software"},
				"sameAs": []string{repoURL}})
	case p.Path == "checks/index.html":
		graph = append(graph, map[string]any{"@type": "Dataset", "name": "OpenVAPT Check Catalogue", "url": url, "description": p.Description,
			"license": siteURL + "/legal/licence-text.html", "isAccessibleForFree": true, "creator": map[string]string{"@id": siteURL + "/#org"},
			"dateModified": p.LastMod, "version": citeVersion(), "keywords": "vulnerability assessment, security checks, CWE, OWASP, NIST SP 800-53, CIS Controls",
			"distribution": []any{map[string]any{"@type": "DataDownload", "encodingFormat": "application/json", "contentUrl": siteURL + "/checks/catalogue.json"}}})
	case p.Path == "faq.html":
		var qs []any
		for _, f := range faqs {
			qs = append(qs, map[string]any{"@type": "Question", "name": f.Q, "acceptedAnswer": map[string]string{"@type": "Answer", "text": f.A}})
		}
		graph = append(graph, map[string]any{"@type": "FAQPage", "@id": url + "#faq", "url": url, "name": p.Title, "description": p.Description, "mainEntity": qs,
			"isPartOf": map[string]string{"@id": siteURL + "/#website"}, "about": map[string]string{"@id": siteURL + "/#software"}, "datePublished": p.Published, "dateModified": p.LastMod, "inLanguage": "en",
			"speakable": map[string]any{"@type": "SpeakableSpecification", "cssSelector": []string{"main .lead", "main section.card p"}}})
	case p.Path == "academy/index.html":
		var parts []any
		mins := 0
		for _, m := range academy.Modules {
			mins += m.Minutes
			parts = append(parts, map[string]any{"@type": "LearningResource", "name": m.ID + ": " + m.Title, "url": siteURL + "/academy/" + strings.ToLower(m.ID) + ".html", "educationalLevel": string(m.Level), "timeRequired": fmt.Sprintf("PT%dM", m.Minutes)})
		}
		graph = append(graph, map[string]any{"@type": "Course", "name": "OpenVAPT Academy", "url": url, "description": p.Description,
			"provider": map[string]string{"@id": siteURL + "/#org"}, "isAccessibleForFree": true, "inLanguage": "en", "educationalLevel": "Beginner to Intermediate",
			"teaches": "Vulnerability assessment (VAPT) from theory to application", "hasPart": parts,
			"offers":            map[string]any{"@type": "Offer", "price": "0", "priceCurrency": "USD", "category": "Free"},
			"hasCourseInstance": map[string]any{"@type": "CourseInstance", "courseMode": "online", "courseWorkload": isoDuration(mins)}})
	case strings.HasPrefix(p.Path, "academy/"):
		lr := map[string]any{"@type": "LearningResource", "name": p.Title, "description": p.Description, "url": url, "mainEntityOfPage": url,
			"isPartOf": map[string]string{"@type": "Course", "name": "OpenVAPT Academy", "url": siteURL + "/academy/"}, "isAccessibleForFree": true,
			"learningResourceType": "Lesson", "inLanguage": "en", "publisher": map[string]string{"@id": siteURL + "/#org"}, "author": map[string]string{"@id": siteURL + "/#org"},
			"image": siteURL + "/assets/og-image.png", "datePublished": p.Published, "dateModified": p.LastMod, "license": siteURL + "/legal/licence-text.html"}
		if m := academy.Get(strings.TrimSuffix(strings.TrimPrefix(p.Path, "academy/"), ".html")); m != nil {
			lr["educationalLevel"] = string(m.Level)
			lr["timeRequired"] = fmt.Sprintf("PT%dM", m.Minutes)
			lr["teaches"] = strings.Join(m.Objectives, "; ")
			lr["keywords"] = strings.Join(m.KeyTerms, ", ")
		}
		if p.Markdown != "" {
			lr["encoding"] = []any{map[string]string{"@type": "MediaObject", "encodingFormat": "text/markdown", "contentUrl": root() + "/" + strings.TrimPrefix(p.Markdown, *base)}}
		}
		graph = append(graph, lr)
	case p.Path == "glossary.html":
		var ts []any
		for _, t := range academy.Terms() {
			ts = append(ts, map[string]any{"@type": "DefinedTerm", "name": t, "description": academy.Glossary[t], "url": url + "#" + slug(t)})
		}
		graph = append(graph, map[string]any{"@type": "DefinedTermSet", "name": "VAPT Glossary", "url": url, "hasDefinedTerm": ts})
	case strings.HasPrefix(p.Path, "checks/") && p.Path != "checks/index.html":
		ta := map[string]any{"@type": "TechArticle", "headline": p.Title, "description": p.Description, "url": url, "mainEntityOfPage": url,
			"about": map[string]string{"@id": siteURL + "/#software"}, "publisher": map[string]string{"@id": siteURL + "/#org"}, "author": map[string]string{"@id": siteURL + "/#org"},
			"image": siteURL + "/assets/og-image.png", "datePublished": p.Published, "dateModified": p.LastMod, "inLanguage": "en",
			"isAccessibleForFree": true, "license": siteURL + "/legal/licence-text.html", "isPartOf": map[string]string{"@id": siteURL + "/#website"}}
		if c := check.Get(strings.TrimSuffix(strings.TrimPrefix(p.Path, "checks/"), ".html")); c != nil {
			kw := append([]string{c.ID, check.CategoryByID(c.Category).Name, string(c.Domain) + " security"}, c.Standards.CWE...)
			kw = append(kw, c.Standards.OWASP...)
			ta["keywords"] = strings.Join(kw, ", ")
			ta["articleSection"] = check.CategoryByID(c.Category).Name
			ta["proficiencyLevel"] = "Expert"
		}
		if p.Markdown != "" {
			ta["encoding"] = []any{map[string]string{"@type": "MediaObject", "encodingFormat": "text/markdown", "contentUrl": root() + "/" + strings.TrimPrefix(p.Markdown, *base)}}
		}
		graph = append(graph, ta)
	default:
		graph = append(graph, map[string]any{"@type": "WebPage", "name": p.Title, "url": url, "description": p.Description,
			"isPartOf": map[string]string{"@id": siteURL + "/#website"}, "about": map[string]string{"@id": siteURL + "/#software"}, "datePublished": p.Published, "dateModified": p.LastMod, "inLanguage": "en"})
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

// isoDuration formats minutes as an ISO 8601 duration such as PT5H30M.
func isoDuration(mins int) string {
	d := "PT"
	if h := mins / 60; h > 0 {
		d += fmt.Sprintf("%dH", h)
	}
	if m := mins % 60; m > 0 || mins == 0 {
		d += fmt.Sprintf("%dM", m)
	}
	return d
}

func writeSEO(paths []string, mods map[string]string, cs []*check.Check) {
	siteURL := root()
	var sm strings.Builder
	sm.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range paths {
		if p == "404.html" {
			continue
		}
		lm := mods[p]
		if lm == "" {
			lm = built.Format("2006-01-02")
		}
		fmt.Fprintf(&sm, "  <url><loc>%s/%s</loc><lastmod>%s</lastmod></url>\n", siteURL, strings.TrimSuffix(p, "index.html"), lm)
	}
	sm.WriteString("</urlset>\n")
	must(os.WriteFile(filepath.Join(*outDir, "sitemap.xml"), []byte(sm.String()), 0o644)) // #nosec G306 -- public website file

	// One group admits every search and AI crawler (GPTBot, ClaudeBot,
	// PerplexityBot, Google-Extended and the rest). Named groups are avoided
	// on purpose: under RFC 9309 a crawler obeys only its most specific group,
	// so a named block would silently override this one. Nothing is
	// disallowed: the admin path is already refused by the server and naming
	// it here would only advertise it.
	robots := "# Every search engine and AI crawler is welcome: one group applies to all.\nUser-agent: *\nAllow: /\n\n"
	robots += "Sitemap: " + siteURL + "/sitemap.xml\n"
	if *noindex {
		robots = "User-agent: *\nDisallow: /\n"
	}
	must(os.WriteFile(filepath.Join(*outDir, "robots.txt"), []byte(robots), 0o644)) // #nosec G306 -- public website file

	var l strings.Builder
	l.WriteString("# OpenVAPT\n\n> OpenVAPT is a free, academic, non-commercial vulnerability assessment (VA) tool for Linux servers with source-available code, researched, developed and built entirely by AI Cybersecurity Engineers under human direction. AI Cybersecurity Engineers are AI systems (Claude by Anthropic, through Claude Code, and OpenAI Codex) acting in a cyber security engineering role. They are not people, not registered or professional engineers, and provide no professional engineering or security service. It runs read-only checks on the machine it is installed on (and only that machine) to identify weaknesses in the server, its network exposure and its websites, rates findings with CVSS v3.1 and proposes cited fixes. It is made for learning how a VAPT tool works. It is not a business, not a penetration testing service and collects no data.\n\n")
	l.WriteString("Key facts:\n- Price: free. No account, no licence key.\n- Use: anyone in any country, including companies, may use it on machines they own or control, for their own use. It may not be sold or used to provide services.\n- Risk: a free gift provided as is, with no warranty; users carry 100% of the risk.\n- Licence: OpenVAPT Source-Available Licence 1.3 (LicenseRef-OpenVAPT-SAL-1.3): own use only, no services, no selling.\n- Platform: Linux. Single static Go binary, standard library only.\n- Scope: designed to be loopback-only, enforced in code. Detection only, no exploit code.\n- Standards: NIST SP 800-115, CVSS v3.1, OWASP Top 10 2021, OWASP ASVS 4.0.3, CWE, NIST SP 800-53.\n- Source: " + repoURL + "\n- Researched, developed and built entirely by AI Cybersecurity Engineers (Claude by Anthropic via Claude Code, with OpenAI Codex) under the owner's direction; not audited by a human security expert or reviewed by a human lawyer.\n- Third-party names identify those projects only; their owners do not sponsor, endorse or have any connection with OpenVAPT.\n\n## Docs\n\n")
	for _, p := range [][2]string{{"faq.html", "FAQ"}, {"how-it-works.html", "How It Is Built, With Code Citations"}, {"checks/", "Check Catalogue"}, {"standards.html", "Standards and Methodology"}, {"compare.html", "Comparison With Lynis, OpenSCAP, OpenVAS, Nuclei, Trivy, ZAP"}, {"limits.html", "What It Does Not Do"}, {"learn.html", "Lessons and Lab"}, {"teach.html", "For Teachers: Course Plans, Worksheets, Rubric, Practice Labs"}, {"legal/teaching.html", "Teaching Terms"}, {"download.html", "Download and Acknowledgements: Download Only, or Download and Scan in One Command"}, {"channels.html", "Release Channels and Promotion Gates"}, {"no-data.html", "No Data Collected"}, {"legal/eula.html", "EULA"}, {"legal/disclaimer.html", "Disclaimer"}, {"legal/privacy.html", "Privacy Policy"}, {"legal/licence.html", "Licence"}, {"cite.html", "How to Cite OpenVAPT (APA, IEEE, Harvard, MLA, Chicago, Vancouver, BibTeX, RIS, CSL-JSON)"}, {"legal/citing.html", "Citing OpenVAPT: Credit and Citation Guide"}, {"legal/credits.html", "Credits, Sources and Citations"}, {"legal/sources.html", "Every Source Cited, by Publisher"}, {"legal/governance.html", "Governance, Control and Assurance Framework"}, {"academy/", "OpenVAPT Academy: Free VAPT Course From Theory to Application"}, {"glossary.html", "VAPT Glossary"}, {"coverage.html", "Coverage Dashboard: Checks by Category, Severity and Framework"}, {"checks/catalogue.json", "Check Catalogue Dataset (JSON)"}, {"legal/ai-disclosure.html", "AI Disclosure"}, {"legal/agents.html", "AI Cybersecurity Engineer Policy"}, {".well-known/security.txt", "Security Contact (RFC 9116 security.txt)"}, {"machine-readable.html", "For Machines and AI: Every Data File (sitemap, feed, Markdown twins, datasets)"}, {"vapt-skill.html", "VAPT Skill for AI Assistants: assess and defend your own machine (SKILL.md)"}, {"skills/openvapt-vapt/SKILL.md", "VAPT Skill Source (Agent Skills SKILL.md)"}, {"feed.xml", "Releases Feed (Atom)"}, {"codemeta.json", "Research Software Metadata (codemeta.json)"}, {"llms-full.txt", "Full Text for Models: every check and FAQ (llms-full.txt)"}} {
		l.WriteString("- [" + p[1] + "](" + siteURL + "/" + p[0] + ")\n")
	}
	l.WriteString("\n## Markdown Versions\n\nEvery check page, every Academy module, the FAQ and the glossary have a Markdown twin at the same address with .md instead of .html, for example " + siteURL + "/checks/HOST-SSH-001.md and " + siteURL + "/academy/f1.md. Each twin starts with front matter naming the canonical HTML page, the licence and the last change date.\n")
	l.WriteString(llmsCite())
	// WebMCP: pages load /webmcp.js (static/webmcp.js), read-only agent tools.
	l.WriteString("\n" + `## WebMCP (AI Assistant Tools)

This site supports WebMCP (https://webmachinelearning.github.io/webmcp/), the W3C draft that lets a website offer tools to an AI assistant running in the visitor's browser. Every public page loads /webmcp.js, which registers these read-only tools through document.modelContext:

- get_site_overview: page title, description, structured data and this llms.txt summary
- list_site_pages: public pages from /sitemap.xml, optionally filtered by keyword
- get_faq: the questions and answers published on the open page (FAQ structured data and FAQ items)
- get_page_sections, read_page_section, search_page: outline, section text and search of the open page
- go_to_section, open_site_page: scroll to a section or open another page on this same site

openvapt.com has no forms, accounts or contact details. No tool sends data, submits anything, sets cookies or contacts any other website.` + "\n")
	l.WriteString("\n## FAQ\n\n")
	for _, f := range faqs {
		l.WriteString("### " + f.Q + "\n" + f.A + "\n\n")
	}
	must(os.WriteFile(filepath.Join(*outDir, "llms.txt"), []byte(l.String()), 0o644)) // #nosec G306 -- public website file

	var full strings.Builder
	full.WriteString(l.String() + "\n## VAPT Skill for AI Assistants\n\n" + siteURL + "/vapt-skill.html (source: " + siteURL + "/" + skillDir + "/SKILL.md). An Agent Skills folder that teaches an AI assistant to assess and defend a Linux machine the user owns or controls: a scope and authorisation gate, an OpenVAPT scan, read-only manual checks, CVSS v3.1 scoring with KEV and EPSS, remediation and hardening with backups and rollback, a re-scan to check each fix, detection and monitoring, incident first response and a report. Rules: own use only, this machine only over loopback, read-only assessment, no exploitation, secrets redacted, nothing leaves the machine. It reduces risk; it does not make a machine secure and is not a penetration test.\n\n## All checks\n\n")
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
