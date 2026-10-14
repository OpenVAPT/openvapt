package main

// Citation formats for the How to Cite page, the Cite This Page boxes on
// check and Academy module pages, and the downloadable reference files
// (openvapt.bib, openvapt.ris, openvapt.json, CITATION.cff). The wording
// follows CITING.md word for word; only the version, commit and dates are
// filled in from the build.

import (
	"github.com/openvapt/openvapt/internal/channels"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/openvapt/openvapt/internal/cite"
	"github.com/openvapt/openvapt/internal/version"
)

// CiteBox is one copyable citation.
type CiteBox struct {
	ID, Label, Hint string
	Text            template.HTML // escaped text; dates are wrapped in <span data-date> so the browser can show today's date
}

// CiteStyle is one tab of the style switcher.
type CiteStyle struct {
	ID, Label string
	Boxes     []CiteBox
}

// Date tokens replaced by a span the browser updates to the reader's own
// access date. Without scripts the build date stays.
const (
	dLong = "{DATE_LONG}" // 13 October 2026
	dUS   = "{DATE_US}"   // October 13, 2026
	dISO  = "{DATE_ISO}"  // 2026-10-13
	dVan  = "{DATE_VAN}"  // 2026 Oct 13
	dIEEE = "{DATE_IEEE}" // 13 Oct. 2026
)

// citeVersion is the version readers should cite: the build's own version
// when it is a real release, otherwise the most advanced published release
// (stable, then rc, beta, alpha), so a website built from a working copy
// never asks people to cite a "dev" version.
func citeVersion() string {
	if v := version.Version; !strings.HasSuffix(v, "-dev") {
		return strings.TrimPrefix(v, "v")
	}
	if siteChannel.State != nil {
		for _, c := range []channels.Channel{channels.Stable, channels.RC, channels.Beta, channels.Alpha} {
			if r, ok := siteChannel.State.Current[c]; ok {
				return strings.TrimPrefix(r.Version, "v")
			}
		}
	}
	return strings.TrimPrefix(version.Version, "v")
}
func citeYear() string { return built.Format("2006") }

// plainDates fills the date tokens with the build date (for files).
func plainDates(s string) string {
	return strings.NewReplacer(dLong, built.Format("2 January 2006"), dUS, built.Format("January 2, 2006"),
		dISO, built.Format("2006-01-02"), dVan, built.Format("2006 Jan 2"), dIEEE, built.Format("2 Jan. 2006")).Replace(s)
}

// htmlDates escapes s and wraps each date in a span the page script updates.
func htmlDates(s string) template.HTML {
	e := template.HTMLEscapeString(s)
	span := func(kind, val string) string { return `<span data-date="` + kind + `">` + val + `</span>` }
	e = strings.NewReplacer(
		template.HTMLEscapeString(dLong), span("long", built.Format("2 January 2006")),
		template.HTMLEscapeString(dUS), span("us", built.Format("January 2, 2006")),
		template.HTMLEscapeString(dISO), span("iso", built.Format("2006-01-02")),
		template.HTMLEscapeString(dVan), span("van", built.Format("2006 Jan 2")),
		template.HTMLEscapeString(dIEEE), span("ieee", built.Format("2 Jan. 2006")),
	).Replace(e)
	return template.HTML(e) // #nosec G203 -- escaped above; only fixed spans are added
}

func box(id, label, hint, text string) CiteBox {
	return CiteBox{ID: id, Label: label, Hint: hint, Text: htmlDates(text)}
}

const citeTitle = cite.Title

// citeWork is the work the website cites, with date tokens the page script
// (or plainDates, for files) fills in.
func citeWork() cite.Work {
	return cite.Work{Version: citeVersion(), Year: citeYear(), Date: cite.Dates{Long: dLong, US: dUS, ISO: dISO, Van: dVan, IEEE: dIEEE}}
}

// citeStyles is the style switcher on the How to Cite page.
func citeStyles() []CiteStyle {
	v, y, r := citeVersion(), citeYear(), repoURL
	w := citeWork()
	return []CiteStyle{
		{"apa", "APA 7", []CiteBox{box("c-apa", "APA 7", "In text: "+w.APAInText(), w.APA())}},
		{"ieee", "IEEE", []CiteBox{box("c-ieee", "IEEE", "", w.IEEE())}},
		{"harvard", "Harvard", []CiteBox{box("c-harvard", "Harvard", "In text: (OpenVAPT, "+y+")", w.Harvard())}},
		{"mla", "MLA 9", []CiteBox{box("c-mla", "MLA 9", "In text: (OpenVAPT)", w.MLA())}},
		{"chicago", "Chicago", []CiteBox{box("c-chicago", "Chicago (17th Edition, Author-Date)", "In text: (OpenVAPT "+y+")", w.Chicago())}},
		{"vancouver", "Vancouver", []CiteBox{box("c-vancouver", "Vancouver", "", w.Vancouver())}},
		{"bibtex", "BibTeX", []CiteBox{
			box("c-bibtex", "BibTeX (@software, for biblatex or Modern Styles)", "The double braces keep OpenVAPT as one group author.", w.BibTeX()),
			box("c-bibmisc", "BibTeX (@misc, for Classic Styles)", "Use this if your style does not know @software.", w.BibMisc())}},
		{"biblatex", "BibLaTeX", []CiteBox{box("c-biblatex", "BibLaTeX", "", w.BibLaTeX())}},
		{"ris", "RIS", []CiteBox{box("c-ris", "RIS (EndNote, Zotero, Mendeley)", "", w.RIS())}},
		{"csl", "CSL-JSON", []CiteBox{box("c-csl", "CSL-JSON (Zotero, Pandoc)", "", w.CSL())}},
		{"plain", "Plain Text", []CiteBox{
			box("c-plain", "Plain Text", "", "OpenVAPT ("+y+"). "+citeTitle+", version "+v+". Built by AI Cybersecurity Engineers. https://openvapt.com"),
			box("c-ack", "Acknowledgements Section of a Thesis or Paper", "", "This work used OpenVAPT (version "+v+", https://openvapt.com), an academic vulnerability assessment tool built by AI Cybersecurity Engineers.")}},
		{"slide", "Slide or Poster", []CiteBox{
			box("c-slide", "Slide, Poster or Figure Caption", "Add the full reference to your reference list or handout.", "Source: OpenVAPT "+v+", openvapt.com"),
			box("c-adapted", "Adapted Figure, Table or Text", "", "Adapted from OpenVAPT (openvapt.com), version "+v+", under the OpenVAPT Source-Available Licence 1.3."),
			box("c-spoken", "Spoken (Video, Talk or Podcast)", "", "This uses OpenVAPT, an academic vulnerability assessment tool from openvapt.com.")}},
		{"code", "Code Header", []CiteBox{box("c-code", "In Source Code", "Use the comment syntax of your language (# for shell and Python). Remove the word \"Modified.\" only if you changed nothing. Keep every Required Notice: line.",
			"// Contains code adapted from OpenVAPT ("+r+"), version "+v+",\n// Copyright (c) "+y+" OpenVAPT and contributors, used under the OpenVAPT Source-Available Licence 1.3\n// (LicenseRef-OpenVAPT-SAL-1.3). Modified.")}},
		{"teaching", "Teaching Credit", []CiteBox{box("c-teaching", "Adapted Teaching Material", "Exact wording required by TEACHING.md section 2.",
			"Adapted from the OpenVAPT Academy (openvapt.com), built by AI Cybersecurity Engineers, used under the OpenVAPT Source-Available Licence 1.3.")}},
	}
}

// citeExtras are the commit and Academy references on the How to Cite page.
func citeExtras() map[string][]CiteBox {
	v, y := citeVersion(), citeYear()
	short := commit[:min(12, len(commit))]
	return map[string][]CiteBox{
		"Commit": {
			box("x-commit", "APA 7 With Commit", "", "OpenVAPT. ("+y+"). OpenVAPT: An open academic vulnerability assessment tool (Version "+v+", commit "+short+") [Computer software]. "+repoURL+"/tree/"+commit),
			box("x-commit-bib", "BibTeX or BibLaTeX Field", "biblatex-software reads commit; for other styles put it in note.", "commit       = {"+commit+"},")},
		"Academy": {
			box("x-academy", "The Academy (APA 7)", "", "OpenVAPT. ("+y+"). OpenVAPT Academy [Online course]. Retrieved "+dUS+", from "+root()+"/academy/"),
			box("x-module-apa", "One Module or Page (APA 7)", "Replace the parts in angle brackets.", "OpenVAPT. ("+y+"). <Module or page title>. OpenVAPT Academy. Retrieved <Month Day, Year>, from <web address of the page>"),
			box("x-module-ieee", "One Module or Page (IEEE)", "", `OpenVAPT, "<Module or page title>," OpenVAPT Academy, `+y+". [Online]. Available: <web address of the page>. [Accessed: <Day Mon. Year>]."),
			box("x-module-harvard", "One Module or Page (Harvard)", "", "OpenVAPT ("+y+") <Module or page title>. OpenVAPT Academy. Available at: <web address of the page> (Accessed: <Day Month Year>).")},
		"Check": {
			box("x-check", "One Check, in Your Text", "Cite the software reference in your reference list and name the check ID in your text.", "check HOST-SSH-001 of OpenVAPT "+v+" (OpenVAPT, "+y+")")},
	}
}

// accessedHint labels the access date in page citations: cite.js fills in
// the reader's own date in the browser (nothing stored or sent); without
// scripts the build date stays.
const accessedHint = "Accessed: the date shown is today's date from your own browser (the site's build date without JavaScript); change it to the day you read the page."

// pageCite is the Cite This Page box for one check or Academy module page.
func pageCite(id, title, collection, path string) []CiteBox {
	w, p := citeWork(), cite.Page{ID: id, Title: title, Collection: collection, URL: pageURL(path)}
	return []CiteBox{
		box("p-apa", "APA 7", "In text: "+w.APAInText()+". "+accessedHint, w.PageAPA(p)),
		box("p-bib", "BibTeX", accessedHint, w.PageBibTeX(p)),
	}
}

// writeCiteFiles writes the downloadable reference files to the site root.
func writeCiteFiles() {
	w := citeWork()
	files := map[string]string{
		"openvapt.bib":  "% OpenVAPT citation. See https://openvapt.com/cite.html and CITING.md.\n% Classic BibTeX styles that do not know @software: use @misc (see the cite page).\n\n" + w.BibTeX() + "\n",
		"openvapt.ris":  w.RIS() + "\n",
		"openvapt.json": w.CSL() + "\n",
	}
	cff, err := os.ReadFile("CITATION.cff")
	must(err)
	files["CITATION.cff"] = string(cff)
	for name, body := range files {
		must(os.WriteFile(filepath.Join(*outDir, name), []byte(plainDates(body)), 0o644)) // #nosec G306 -- public website file
	}
}

// QuickCite is the compact Cite panel in the header and footer of every
// page. Prefix keeps element ids unique between the two copies.
type QuickCite struct {
	Prefix, Base, Request, DOINote string
	Styles                         []CiteStyle
	Page                           []CiteBox // set on check and Academy module pages
	PageKind                       string    // "Check" or "Module"
}

// quickCite builds the panel for page p.
func quickCite(prefix string, p Page) QuickCite {
	q := QuickCite{Prefix: prefix, Base: p.Base, Request: cite.Request, DOINote: cite.DOINote}
	re := func(b CiteBox) CiteBox { b.ID = prefix + "-" + b.ID; return b }
	all := citeStyles()
	for _, id := range cite.Styles {
		for _, s := range all {
			if s.ID == id {
				q.Styles = append(q.Styles, CiteStyle{ID: prefix + "-" + s.ID, Label: s.Label, Boxes: []CiteBox{re(s.Boxes[0])}})
			}
		}
	}
	for _, b := range p.PageCite {
		q.Page = append(q.Page, re(b))
	}
	if len(q.Page) > 0 {
		q.PageKind = "Module"
		if strings.HasPrefix(p.Path, "checks/") {
			q.PageKind = "Check"
		}
	}
	return q
}

// printCite is the APA citation printed at the bottom of every printed page.
func printCite() string { return plainDates(citeWork().APA()) }

// llmsCite is the How to Cite section of llms.txt.
func llmsCite() string {
	w := citeWork()
	return "\n## How to Cite\n\n" + cite.Request + " The author is the group author \"OpenVAPT\"; do not add personal names. " + cite.DOINote +
		"\n\nAPA 7: " + w.APA() + "\n\nBibTeX:\n\n```bibtex\n" + w.BibTeX() + "\n```\n\nEvery style, and when credit is required (licence section 5.4): " + siteURL + "/cite.html. " + citeCLILine(siteFeatures) + "\n"
}

// citeHero is the recommended APA citation at the top of the cite page.
func citeHero() map[string]any {
	return map[string]any{"APA": citeWork().APA(), "Request": cite.Request, "DOINote": cite.DOINote, "Unreleased": cite.Unreleased}
}
