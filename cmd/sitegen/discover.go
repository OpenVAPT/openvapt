package main

// Discovery artefacts added in the 2026-10-14 SEO, GEO and AEO round: an Atom
// feed of releases, a web app manifest, codemeta.json for research-software
// indexers, the IndexNow key file, a Markdown twin of every article page for
// AI and answer engines, and first-publication dates for structured data.
// Everything here is static text generated at build time; the site still
// runs no server-side code and collects nothing.

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/channels"
	"github.com/openvapt/openvapt/internal/check"
)

// ---------- first publication date (datePublished) ----------

var pubCache = map[string]string{}

// firstMod returns the date (YYYY-MM-DD) of the oldest commit that touched any
// of the given files, for datePublished. Falls back to lastMod when git
// cannot answer.
func firstMod(files ...string) string {
	key := strings.Join(files, "\x00")
	if d, ok := pubCache[key]; ok {
		return d
	}
	d := lastMod(files...)
	args := append([]string{"log", "--reverse", "--format=%cI", "--"}, files...)
	if out, err := exec.Command("git", args...).Output(); err == nil {
		if lines := strings.Split(strings.TrimSpace(string(out)), "\n"); len(lines) > 0 && len(lines[0]) >= 10 {
			if t, err := time.Parse(time.RFC3339, lines[0]); err == nil {
				d = t.UTC().Format("2006-01-02")
			}
		}
	}
	pubCache[key] = d
	return d
}

// ---------- Markdown twins ----------

// mdTwin returns the path of the Markdown twin of an HTML page, or "" when
// the page has none. Twins exist for every check page, every Academy module,
// the FAQ and the glossary: the pages an answer engine is most likely to
// quote. They carry the same facts as the HTML, in plain Markdown.
func mdTwin(path string) string {
	switch {
	case path == "faq.html", path == "glossary.html":
		return strings.TrimSuffix(path, ".html") + ".md"
	case strings.HasPrefix(path, "checks/") && path != "checks/index.html":
		return strings.TrimSuffix(path, ".html") + ".md"
	case strings.HasPrefix(path, "academy/") && path != "academy/index.html" &&
		!strings.HasPrefix(path, "academy/worksheet-") && !strings.HasPrefix(path, "academy/key-"):
		return strings.TrimSuffix(path, ".html") + ".md"
	}
	return ""
}

// mdHeader is the front matter every twin starts with, so a reader (or a
// model) knows the canonical page, the licence and when it last changed.
func mdHeader(title, path, lastMod string) string {
	return "---\ntitle: " + mdQuote(title) + "\ncanonical: " + pageURL(path) + "\nhtml: " + pageURL(path) + "\nsite: OpenVAPT, " + root() + "/\nlicense: OpenVAPT Source-Available Licence 1.3, " + root() + "/legal/licence-text.html\nmodified: " + lastMod + "\nversion: " + citeVersion() + "\n---\n\n"
}

func mdQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func writeMD(path, body string) {
	dst := filepath.Join(*outDir, path)
	must(os.MkdirAll(filepath.Dir(dst), 0o755))  // #nosec G301 -- public website output
	must(os.WriteFile(dst, []byte(body), 0o644)) // #nosec G306 -- public website file
}

// checkMarkdown renders one check as Markdown.
func checkMarkdown(c *check.Check, lastMod string) string {
	var b strings.Builder
	b.WriteString(mdHeader(c.ID+" "+c.Title, "checks/"+c.ID+".html", lastMod))
	fmt.Fprintf(&b, "# %s %s\n\n%s\n\n", c.ID, c.Title, c.Summary)
	dom := map[check.Domain]string{"host": "Server", "network": "Network", "web": "Web Apps"}[c.Domain]
	fmt.Fprintf(&b, "- Domain: %s\n- Severity: %s\n- Control category: %s\n- Fix effort: %s\n- CVSS v3.1 vector: `%s`\n", dom, strings.ToUpper(string(c.Severity)[:1])+string(c.Severity)[1:], check.CategoryByID(c.Category).Name, string(c.Effort), c.CVSS)
	std := func(label string, v []string) {
		if len(v) > 0 {
			fmt.Fprintf(&b, "- %s: %s\n", label, strings.Join(v, ", "))
		}
	}
	std("CIS Controls v8", c.Standards.CIS)
	std("NIST CSF 2.0", c.Standards.CSF)
	std("CWE", c.Standards.CWE)
	std("OWASP Top 10 2021", c.Standards.OWASP)
	std("OWASP ASVS 4.0.3", c.Standards.ASVS)
	std("OWASP WSTG v4.2", c.Standards.WSTG)
	std("NIST SP 800-53 Rev. 5", c.Standards.NIST)
	if c.Standards.CISTopic != "" {
		fmt.Fprintf(&b, "- Benchmark topic: %s (topic only, no benchmark text)\n", c.Standards.CISTopic)
	}
	fmt.Fprintf(&b, "\n## Why It Matters\n\n%s\n\n## How It Detects\n\n%s\n\n## How to Fix\n\n%s\n\n## How to Verify\n\n```\n%s\n```\n\n", c.Rationale, c.Detection, c.Fix, c.Verify)
	if mods := academy.ForCheck(c.ID); len(mods) > 0 {
		b.WriteString("## Learn the Theory\n\n")
		for _, m := range mods {
			fmt.Fprintf(&b, "- [%s %s](%s/academy/%s.md)\n", m.ID, m.Title, root(), strings.ToLower(m.ID))
		}
		b.WriteString("\n")
	}
	b.WriteString("## References\n\n")
	for _, r := range c.Refs {
		fmt.Fprintf(&b, "- [%s](%s)\n", r.Title, r.URL)
	}
	fmt.Fprintf(&b, "\n## Source Code\n\n%s/blob/%s/%s\n\nRun it: `openvapt scan --only %s`. Read it offline: `openvapt explain %s`.\n\n%s", repoURL, commit, c.SourceFile, c.ID, c.ID, mdFooter("OpenVAPT Check Catalogue", "checks/"+c.ID+".html"))
	return b.String()
}

// moduleMarkdown renders one Academy module as Markdown.
func moduleMarkdown(m *academy.Module, lastMod string) string {
	var b strings.Builder
	path := "academy/" + strings.ToLower(m.ID) + ".html"
	b.WriteString(mdHeader(m.ID+": "+m.Title, path, lastMod))
	fmt.Fprintf(&b, "# %s: %s\n\n%s\n\n- Level: %s\n- Time: about %d minutes\n", m.ID, m.Title, m.Summary, m.Level, m.Minutes)
	if len(m.Prereqs) > 0 {
		fmt.Fprintf(&b, "- Read first: %s\n", strings.Join(m.Prereqs, ", "))
	}
	b.WriteString("\n## You Will Be Able To\n\n")
	for _, o := range m.Objectives {
		fmt.Fprintf(&b, "- %s\n", o)
	}
	for _, s := range m.Sections {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", s.Heading, strings.Join(s.Body, "\n\n"))
	}
	if cs := checksFor(m); len(cs) > 0 {
		b.WriteString("\n## Apply It\n\n")
		for _, c := range cs {
			fmt.Fprintf(&b, "- [%s %s](%s/checks/%s.md) (%s)\n", c.ID, c.Title, root(), c.ID, c.Severity)
		}
	}
	if len(m.Lab) > 0 {
		b.WriteString("\n## Lab\n\n")
		for i, l := range m.Lab {
			fmt.Fprintf(&b, "%d. `%s`\n", i+1, l)
		}
	}
	if len(m.Quiz) > 0 {
		b.WriteString("\n## Check Yourself\n\nAnswer keys are public for every channel (see Teaching With OpenVAPT).\n")
		for i, q := range m.Quiz {
			fmt.Fprintf(&b, "\n%d. %s\n", i+1, q.Q)
			for j, o := range q.Options {
				fmt.Fprintf(&b, "   - %c. %s\n", 'A'+j, o)
			}
			if q.Answer >= 0 && q.Answer < len(q.Options) {
				fmt.Fprintf(&b, "   - Answer: %c. %s\n", 'A'+q.Answer, q.Explain)
			}
		}
	}
	if len(m.KeyTerms) > 0 {
		b.WriteString("\n## Key Terms\n\n")
		for _, t := range m.KeyTerms {
			fmt.Fprintf(&b, "- %s: %s\n", t, academy.Glossary[t])
		}
	}
	if len(m.Refs) > 0 {
		b.WriteString("\n## References\n\n")
		for _, r := range m.Refs {
			fmt.Fprintf(&b, "- [%s](%s)\n", r.Title, r.URL)
		}
	}
	fmt.Fprintf(&b, "\nOffline: `openvapt learn %s`.\n\n%s", m.ID, mdFooter("OpenVAPT Academy", path))
	return b.String()
}

func faqMarkdown(lastMod string) string {
	var b strings.Builder
	b.WriteString(mdHeader("OpenVAPT FAQ", "faq.html", lastMod))
	b.WriteString("# Frequently Asked Questions\n\nShort, factual answers about OpenVAPT, the free academic vulnerability assessment learning tool for Linux. Each answer stands on its own and may be quoted alone.\n")
	for _, f := range faqs {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", f.Q, f.A)
	}
	b.WriteString("\n" + mdFooter("OpenVAPT", "faq.html"))
	return b.String()
}

func glossaryMarkdown(lastMod string) string {
	var b strings.Builder
	b.WriteString(mdHeader("VAPT Glossary", "glossary.html", lastMod))
	b.WriteString("# VAPT Glossary\n\nPlain-language definitions of the vulnerability assessment and penetration testing terms used across OpenVAPT and the Academy.\n\n")
	for _, t := range academy.Terms() {
		fmt.Fprintf(&b, "- **%s**: %s\n", t, academy.Glossary[t])
	}
	b.WriteString("\n" + mdFooter("OpenVAPT", "glossary.html"))
	return b.String()
}

// mdFooter closes every twin with the positioning line and the citation.
func mdFooter(container, path string) string {
	return "---\n\nOpenVAPT is academic, non-commercial, source-available and built by AI Cybersecurity Engineers (AI systems, not people). Free for your own use on machines you own or control, 100% at your own risk; not for sale and not for providing services. This page in HTML: " + pageURL(path) + ". Part of " + container + ". How to cite: " + root() + "/cite.html. Site summary for models: " + root() + "/llms.txt.\n"
}

// writeMarkdownTwins writes every twin. mods maps HTML paths to lastmod dates.
func writeMarkdownTwins(cs []*check.Check, mods map[string]string) {
	for _, c := range cs {
		p := "checks/" + c.ID + ".html"
		writeMD(mdTwin(p), checkMarkdown(c, mods[p]))
	}
	for i := range academy.Modules {
		m := &academy.Modules[i]
		p := "academy/" + strings.ToLower(m.ID) + ".html"
		writeMD(mdTwin(p), moduleMarkdown(m, mods[p]))
	}
	writeMD("faq.md", faqMarkdown(mods["faq.html"]))
	writeMD("glossary.md", glossaryMarkdown(mods["glossary.html"]))
}

// ---------- Atom feed of releases ----------

type atomFeed struct {
	XMLName  xml.Name    `xml:"feed"`
	NS       string      `xml:"xmlns,attr"`
	Title    string      `xml:"title"`
	Subtitle string      `xml:"subtitle"`
	ID       string      `xml:"id"`
	Updated  string      `xml:"updated"`
	Links    []atomLink  `xml:"link"`
	Author   atomAuthor  `xml:"author"`
	Rights   string      `xml:"rights"`
	Entries  []atomEntry `xml:"entry"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
}

type atomAuthor struct {
	Name string `xml:"name"`
	URI  string `xml:"uri"`
}

type atomEntry struct {
	Title   string     `xml:"title"`
	ID      string     `xml:"id"`
	Updated string     `xml:"updated"`
	Links   []atomLink `xml:"link"`
	Summary string     `xml:"summary"`
	Content atomText   `xml:"content"`
}

type atomText struct {
	Type string `xml:"type,attr"`
	Text string `xml:",chardata"`
}

// feedReleases lists every recorded release, newest first.
func feedReleases(sc siteChannels) []channels.Release {
	seen := map[string]bool{}
	var rs []channels.Release
	add := func(r channels.Release) {
		if r.Version == "" || seen[r.Version] {
			return
		}
		seen[r.Version] = true
		rs = append(rs, r)
	}
	if sc.State != nil {
		for _, c := range []channels.Channel{channels.Stable, channels.RC, channels.Beta, channels.Alpha} {
			if r, ok := sc.State.Current[c]; ok {
				add(r)
			}
		}
	}
	for _, r := range sc.History {
		add(r)
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Date != rs[j].Date {
			return rs[i].Date > rs[j].Date
		}
		return rs[i].Version > rs[j].Version
	})
	return rs
}

// buildFeed is the release feed as a struct (tested) and writeFeed stores it.
func buildFeed(sc siteChannels) atomFeed {
	siteURL := root()
	f := atomFeed{NS: "http://www.w3.org/2005/Atom", Title: "OpenVAPT Releases", ID: siteURL + "/feed.xml",
		Subtitle: "Every OpenVAPT release on the Alpha, Beta, Release Candidate and Stable channels, with the evidence each promotion gate recorded. Academic, non-commercial, source-available, built by AI Cybersecurity Engineers.",
		Links:    []atomLink{{Href: siteURL + "/feed.xml", Rel: "self", Type: "application/atom+xml"}, {Href: siteURL + "/channels.html", Rel: "alternate", Type: "text/html"}},
		Author:   atomAuthor{Name: "OpenVAPT", URI: siteURL + "/"},
		Rights:   "OpenVAPT Source-Available Licence 1.3: own use only, no services, no selling. Provided as is, at your own risk."}
	f.Updated = built.Format(time.RFC3339)
	for i, r := range feedReleases(sc) {
		name := channels.InfoFor(r.Channel).Name
		when := r.Date + "T00:00:00Z"
		if i == 0 {
			f.Updated = when
		}
		tag := repoURL + "/releases/tag/" + r.Version
		var c strings.Builder
		fmt.Fprintf(&c, "OpenVAPT %s was published on the %s channel on %s from commit %s. Decision: %s.", r.Version, name, r.Date, r.Commit, r.Decision)
		if len(r.Evidence) > 0 {
			c.WriteString(" Evidence: " + strings.Join(r.Evidence, "; ") + ".")
		}
		c.WriteString(" Release, checksums and build attestation: " + tag + ". Release channels and gates: " + siteURL + "/channels.html. Changelog: " + repoURL + "/blob/" + r.Commit + "/CHANGELOG.md.")
		f.Entries = append(f.Entries, atomEntry{Title: "OpenVAPT " + r.Version + " (" + name + ")", ID: tag, Updated: when,
			Links:   []atomLink{{Href: tag, Rel: "alternate", Type: "text/html"}},
			Summary: fmt.Sprintf("%s channel release %s, %s.", name, r.Version, r.Decision),
			Content: atomText{Type: "text", Text: c.String()}})
	}
	return f
}

func writeFeed(sc siteChannels) {
	b, err := xml.MarshalIndent(buildFeed(sc), "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(*outDir, "feed.xml"), append([]byte(xml.Header), append(b, '\n')...), 0o644)) // #nosec G306 -- public website file
}

// ---------- web app manifest ----------

func manifest() map[string]any {
	b := *base
	return map[string]any{
		"name": "OpenVAPT", "short_name": "OpenVAPT", "id": b, "start_url": b, "scope": b, "display": "browser", "lang": "en", "dir": "ltr",
		"description":      "Academic, non-commercial vulnerability assessment learning tool for Linux with source-available code, built by AI Cybersecurity Engineers. Free for your own use, 100% at your own risk.",
		"background_color": "#ffffff", "theme_color": "#ffffff",
		"icons": []any{
			map[string]any{"src": b + "assets/icon-192.png", "sizes": "192x192", "type": "image/png"},
			map[string]any{"src": b + "assets/icon-512.png", "sizes": "512x512", "type": "image/png"},
			map[string]any{"src": b + "assets/icon.svg", "sizes": "any", "type": "image/svg+xml"},
		},
		"categories": []string{"education", "security", "utilities"},
	}
}

func writeManifest() {
	b, err := json.MarshalIndent(manifest(), "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(*outDir, "site.webmanifest"), append(b, '\n'), 0o644)) // #nosec G306 -- public website file
}

// ---------- codemeta.json (research software metadata) ----------

func codemeta(cs []*check.Check) map[string]any {
	siteURL := root()
	v := citeVersion()
	return map[string]any{
		"@context": "https://w3id.org/codemeta/3.0", "@type": "SoftwareSourceCode", "@id": repoURL,
		"identifier": repoURL, "name": citeTitle, "alternateName": "OpenVAPT",
		"description":    "Academic, non-commercial vulnerability assessment (VA) learning tool for Linux servers with source-available code, researched, developed and built by AI Cybersecurity Engineers under human direction. Read-only checks on the machine it runs on, CVSS v3.1 ratings, cited fixes, local reports in HTML, JSON, SARIF and Markdown. Collects no data.",
		"codeRepository": repoURL, "url": siteURL + "/", "issueTracker": repoURL + "/issues",
		"readme": repoURL + "/blob/main/README.md", "license": siteURL + "/legal/licence-text.html",
		"version": v, "softwareVersion": v, "dateModified": built.Format("2006-01-02"), "developmentStatus": "active",
		"programmingLanguage": map[string]string{"@type": "ComputerLanguage", "name": "Go", "url": "https://go.dev/"},
		"runtimePlatform":     "Go 1.26", "operatingSystem": []string{"Linux"},
		"applicationCategory": "Security", "applicationSubCategory": "Vulnerability Assessment Tool",
		"isAccessibleForFree": true, "inLanguage": "en",
		"author":       []any{map[string]string{"@type": "Organization", "name": "OpenVAPT", "url": siteURL + "/"}},
		"publisher":    map[string]string{"@type": "Organization", "name": "OpenVAPT", "url": siteURL + "/"},
		"keywords":     []string{"vulnerability assessment", "VAPT", "Linux security", "server hardening", "CVSS", "OWASP", "CWE", "NIST SP 800-115", "CIS Controls", "security education", "AI assistant skill", "source-available", "built by AI Cybersecurity Engineers"},
		"featureList":  []string{fmt.Sprintf("%d read-only checks", len(cs)), fmt.Sprintf("%d Academy modules", len(academy.Modules)), "CVSS v3.1 ratings", "HTML, JSON, SARIF and Markdown reports", "Loopback-only scope guard", "Zero data collection"},
		"releaseNotes": siteURL + "/channels.html", "downloadUrl": siteURL + "/download.html",
		"referencePublication": siteURL + "/cite.html", "citation": siteURL + "/CITATION.cff",
		"funding": "None. OpenVAPT accepts no payments or donations.",
	}
}

func writeCodemeta(cs []*check.Check) {
	b, err := json.MarshalIndent(codemeta(cs), "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(*outDir, "codemeta.json"), append(b, '\n'), 0o644)) // #nosec G306 -- public website file
}

// ---------- IndexNow ----------

// indexNowKey reads site/indexnow-key.txt. The key is not a secret: IndexNow
// (Bing, Yandex, Naver, Seznam and others) verifies ownership by fetching
// https://openvapt.com/<key>.txt, which site/static publishes. The key only
// lets someone tell those engines that a page on this site changed; it grants
// no access to anything. scripts/indexnow.sh submits URLs after a deploy.
func indexNowKey() string {
	b, err := os.ReadFile("site/indexnow-key.txt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
