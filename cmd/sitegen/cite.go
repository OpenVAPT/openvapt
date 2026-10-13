package main

// Citation formats for the How to Cite page, the Cite This Page boxes on
// check and Academy module pages, and the downloadable reference files
// (openvapt.bib, openvapt.ris, openvapt.json, CITATION.cff). The wording
// follows CITING.md word for word; only the version, commit and dates are
// filled in from the build.

import (
	"encoding/json"
	"github.com/openvapt/openvapt/internal/channels"
	"html/template"
	"os"
	"path/filepath"
	"strings"

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

const citeTitle = "OpenVAPT: An Open Academic Vulnerability Assessment Tool"

func bibSoftware(v, y string) string {
	return `@software{openvapt_` + y + `,
  author       = {{OpenVAPT}},
  title        = {{` + citeTitle + `}},
  year         = {` + y + `},
  version      = {` + v + `},
  url          = {` + repoURL + `},
  note         = {Built by AI Cybersecurity Engineers. https://openvapt.com},
  license      = {LicenseRef-OpenVAPT-SAL-1.3}
}`
}

func bibMisc(v, y string) string {
	return `@misc{openvapt_` + y + `,
  author       = {{OpenVAPT}},
  title        = {{` + citeTitle + `}},
  year         = {` + y + `},
  howpublished = {\url{` + repoURL + `}},
  note         = {Computer software, version ` + v + `. Accessed ` + dLong + `}
}`
}

func bibLaTeX(v, y string) string {
	return `@software{openvapt_` + y + `,
  author       = {{OpenVAPT}},
  title        = {` + citeTitle + `},
  date         = {` + y + `},
  version      = {` + v + `},
  url          = {` + repoURL + `},
  urldate      = {` + dISO + `},
  organization = {OpenVAPT},
  addendum     = {Built by AI Cybersecurity Engineers}
}`
}

func risText(v, y string) string {
	return "TY  - COMP\nAU  - OpenVAPT\nTI  - " + citeTitle + "\nPY  - " + y + "\nET  - " + v + "\nUR  - " + repoURL + "\nN1  - Built by AI Cybersecurity Engineers. https://openvapt.com\nER  - "
}

func cslJSON(v, y string) string {
	s := `[
  {
    "id": "openvapt_` + y + `",
    "type": "software",
    "author": [{ "literal": "OpenVAPT" }],
    "title": "` + citeTitle + `",
    "version": "` + v + `",
    "issued": { "date-parts": [[` + y + `]] },
    "URL": "` + repoURL + `",
    "note": "Built by AI Cybersecurity Engineers"
  }
]`
	if !json.Valid([]byte(s)) {
		panic("CSL-JSON citation is not valid JSON")
	}
	return s
}

// citeStyles is the style switcher on the How to Cite page.
func citeStyles() []CiteStyle {
	v, y, r := citeVersion(), citeYear(), repoURL
	return []CiteStyle{
		{"apa", "APA 7", []CiteBox{box("c-apa", "APA 7", "In text: (OpenVAPT, "+y+")",
			"OpenVAPT. ("+y+"). OpenVAPT: An open academic vulnerability assessment tool (Version "+v+") [Computer software]. "+r)}},
		{"ieee", "IEEE", []CiteBox{box("c-ieee", "IEEE", "",
			`OpenVAPT, "`+citeTitle+`," version `+v+", "+y+". [Online]. Available: "+r)}},
		{"harvard", "Harvard", []CiteBox{box("c-harvard", "Harvard", "In text: (OpenVAPT, "+y+")",
			"OpenVAPT ("+y+") "+citeTitle+". Version "+v+" [Computer program]. Available at: "+r+" (Accessed: "+dLong+").")}},
		{"mla", "MLA 9", []CiteBox{box("c-mla", "MLA 9", "In text: (OpenVAPT)",
			"OpenVAPT. "+citeTitle+". Version "+v+", "+y+". GitHub, github.com/OpenVAPT/openvapt.")}},
		{"chicago", "Chicago", []CiteBox{box("c-chicago", "Chicago (17th Edition, Author-Date)", "In text: (OpenVAPT "+y+")",
			"OpenVAPT. "+y+". "+citeTitle+". Version "+v+". Computer software. "+r+".")}},
		{"vancouver", "Vancouver", []CiteBox{box("c-vancouver", "Vancouver", "",
			"OpenVAPT. OpenVAPT: an open academic vulnerability assessment tool [Internet]. Version "+v+". "+y+" [cited "+dVan+"]. Available from: "+r)}},
		{"bibtex", "BibTeX", []CiteBox{
			box("c-bibtex", "BibTeX (@software, for biblatex or Modern Styles)", "The double braces keep OpenVAPT as one group author.", bibSoftware(v, y)),
			box("c-bibmisc", "BibTeX (@misc, for Classic Styles)", "Use this if your style does not know @software.", bibMisc(v, y))}},
		{"biblatex", "BibLaTeX", []CiteBox{box("c-biblatex", "BibLaTeX", "", bibLaTeX(v, y))}},
		{"ris", "RIS", []CiteBox{box("c-ris", "RIS (EndNote, Zotero, Mendeley)", "", risText(v, y))}},
		{"csl", "CSL-JSON", []CiteBox{box("c-csl", "CSL-JSON (Zotero, Pandoc)", "", cslJSON(v, y))}},
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

// texEscape escapes the characters BibTeX treats specially in a title.
func texEscape(s string) string {
	return strings.NewReplacer(`\`, `\textbackslash{}`, "{", `\{`, "}", `\}`, "&", `\&`, "%", `\%`, "$", `\$`, "#", `\#`, "_", `\_`).Replace(s)
}

// pageCite is the Cite This Page box for one check or Academy module page.
func pageCite(id, title, collection, path string) []CiteBox {
	v, y, u := citeVersion(), citeYear(), pageURL(path)
	key := "openvapt_" + strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(id))
	return []CiteBox{
		box("p-apa", "APA 7", "In text: (OpenVAPT, "+y+")", "OpenVAPT. ("+y+"). "+title+" (Version "+v+"). "+collection+". Retrieved "+dUS+", from "+u),
		box("p-bib", "BibTeX", "", "@misc{"+key+",\n  author       = {{OpenVAPT}},\n  title        = {{"+texEscape(title)+"}},\n  year         = {"+y+"},\n  howpublished = {\\url{"+u+"}},\n  note         = {"+collection+", version "+v+". Accessed "+dLong+"}\n}"),
	}
}

// writeCiteFiles writes the downloadable reference files to the site root.
func writeCiteFiles() {
	v, y := citeVersion(), citeYear()
	files := map[string]string{
		"openvapt.bib":  "% OpenVAPT citation. See https://openvapt.com/cite.html and CITING.md.\n% Classic BibTeX styles that do not know @software: use @misc (see the cite page).\n\n" + bibSoftware(v, y) + "\n",
		"openvapt.ris":  risText(v, y) + "\n",
		"openvapt.json": cslJSON(v, y) + "\n",
	}
	cff, err := os.ReadFile("CITATION.cff")
	must(err)
	files["CITATION.cff"] = string(cff)
	for name, body := range files {
		must(os.WriteFile(filepath.Join(*outDir, name), []byte(plainDates(body)), 0o644)) // #nosec G306 -- public website file
	}
}
