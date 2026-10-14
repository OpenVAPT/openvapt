// Package cite is the single source of truth for how OpenVAPT is cited.
// The website (cmd/sitegen), the command line (openvapt cite), every report
// (HTML, Markdown, JSON, SARIF) and the README all render their citations
// from these functions, so the wording cannot drift between them. The
// wording follows CITING.md; the author is always the group author
// "OpenVAPT", never a personal name.
package cite

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	Title   = "OpenVAPT: An Open Academic Vulnerability Assessment Tool"
	Author  = "OpenVAPT"
	RepoURL = "https://github.com/OpenVAPT/openvapt"
	SiteURL = "https://openvapt.com"
	// Made is the optional note CITING.md allows on how the work was made.
	Made = "Built by AI Cybersecurity Engineers"
	// Request is the one-line request shown wherever OpenVAPT asks to be cited.
	Request = "Using OpenVAPT in research, teaching or a report? Please cite it."
	// CLILine is printed after every scan and demo.
	CLILine = "Please cite OpenVAPT if you use these results: openvapt cite"
	// Credit is the credit line section 5.4 of the licence requires when
	// OpenVAPT material, such as a report, is shared.
	Credit = "Produced with OpenVAPT (https://openvapt.com), built by AI Cybersecurity Engineers, used under the OpenVAPT Source-Available Licence 1.3. Use does not imply endorsement."
	// Unreleased is the version text for a build made from source that is
	// not a published release.
	Unreleased = "unreleased build"
	// DOINote says honestly that there is no DOI.
	DOINote = "OpenVAPT has no DOI yet. Cite the version and the web address; the version identifies the exact code."
)

// Dates are the access date in each style's own format.
type Dates struct{ Long, US, ISO, Van, IEEE string }

// DatesFor formats t for every style.
func DatesFor(t time.Time) Dates {
	ieee := t.Format("2 Jan. 2006")
	if t.Month() == time.May {
		ieee = t.Format("2 Jan 2006")
	}
	return Dates{Long: t.Format("2 January 2006"), US: t.Format("January 2, 2006"), ISO: t.Format("2006-01-02"),
		Van: t.Format("2006 Jan 2"), IEEE: ieee}
}

// Work is one citable version of OpenVAPT.
type Work struct {
	Version string // without a leading v, or Unreleased
	Year    string
	Date    Dates // access date
}

// Version normalises a build version for citing: "v0.1.0-alpha.3" becomes
// "0.1.0-alpha.3", and an unreleased build made from source becomes Unreleased.
func Version(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || strings.HasSuffix(v, "-dev") || v == "unknown" {
		return Unreleased
	}
	return v
}

// New returns the work for build version v, accessed on t.
func New(v string, t time.Time) Work {
	return Work{Version: Version(v), Year: t.Format("2006"), Date: DatesFor(t)}
}

// Styles is the order of the quick style switcher.
var Styles = []string{"apa", "ieee", "harvard", "mla", "chicago", "bibtex"}

// Formats is every format openvapt cite accepts.
var Formats = []string{"apa", "ieee", "harvard", "mla", "chicago", "bibtex", "ris", "csl", "cff"}

func (w Work) APA() string {
	return "OpenVAPT. (" + w.Year + "). OpenVAPT: An open academic vulnerability assessment tool (Version " + w.Version + ") [Computer software]. " + RepoURL
}

func (w Work) APAInText() string { return "(OpenVAPT, " + w.Year + ")" }

func (w Work) IEEE() string {
	return `OpenVAPT, "` + Title + `," version ` + w.Version + ", " + w.Year + ". [Online]. Available: " + RepoURL
}

func (w Work) Harvard() string {
	return "OpenVAPT (" + w.Year + ") " + Title + ". Version " + w.Version + " [Computer program]. Available at: " + RepoURL + " (Accessed: " + w.Date.Long + ")."
}

func (w Work) MLA() string {
	return "OpenVAPT. " + Title + ". Version " + w.Version + ", " + w.Year + ". GitHub, github.com/OpenVAPT/openvapt."
}

func (w Work) Chicago() string {
	return "OpenVAPT. " + w.Year + ". " + Title + ". Version " + w.Version + ". Computer software. " + RepoURL + "."
}

func (w Work) Vancouver() string {
	return "OpenVAPT. OpenVAPT: an open academic vulnerability assessment tool [Internet]. Version " + w.Version + ". " + w.Year + " [cited " + w.Date.Van + "]. Available from: " + RepoURL
}

// BibTeX is the @software entry (biblatex and modern styles).
func (w Work) BibTeX() string {
	return `@software{openvapt_` + w.Year + `,
  author       = {{OpenVAPT}},
  title        = {{` + Title + `}},
  year         = {` + w.Year + `},
  version      = {` + w.Version + `},
  url          = {` + RepoURL + `},
  note         = {` + Made + `. ` + SiteURL + `},
  license      = {LicenseRef-OpenVAPT-SAL-1.3}
}`
}

// BibMisc is the @misc entry for classic BibTeX styles.
func (w Work) BibMisc() string {
	return `@misc{openvapt_` + w.Year + `,
  author       = {{OpenVAPT}},
  title        = {{` + Title + `}},
  year         = {` + w.Year + `},
  howpublished = {\url{` + RepoURL + `}},
  note         = {Computer software, version ` + w.Version + `. Accessed ` + w.Date.Long + `}
}`
}

func (w Work) BibLaTeX() string {
	return `@software{openvapt_` + w.Year + `,
  author       = {{OpenVAPT}},
  title        = {` + Title + `},
  date         = {` + w.Year + `},
  version      = {` + w.Version + `},
  url          = {` + RepoURL + `},
  urldate      = {` + w.Date.ISO + `},
  organization = {OpenVAPT},
  addendum     = {` + Made + `}
}`
}

func (w Work) RIS() string {
	return "TY  - COMP\nAU  - OpenVAPT\nTI  - " + Title + "\nPY  - " + w.Year + "\nET  - " + w.Version + "\nUR  - " + RepoURL + "\nN1  - " + Made + ". " + SiteURL + "\nER  - "
}

// CSL is CSL-JSON (Zotero, Pandoc).
func (w Work) CSL() string {
	type author struct {
		Literal string `json:"literal"`
	}
	type issued struct {
		DateParts [][]int `json:"date-parts"`
	}
	var y int
	_, _ = fmt.Sscan(w.Year, &y)
	item := []map[string]any{{
		"id": "openvapt_" + w.Year, "type": "software", "author": []author{{Author}}, "title": Title,
		"version": w.Version, "issued": issued{[][]int{{y}}}, "URL": RepoURL, "note": Made,
	}}
	b, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// CFF is a minimal CITATION.cff for this exact version. The repository's
// own CITATION.cff is kept by the release record step (cmd/channel).
func (w Work) CFF() string {
	s := "cff-version: 1.2.0\nmessage: \"Please cite OpenVAPT if you use it, and give the version you used.\"\ntitle: \"" + Title + "\"\ntype: software\nauthors:\n  - name: \"OpenVAPT\"\n    website: \"" + SiteURL + "\"\nrepository-code: \"" + RepoURL + "\"\nurl: \"" + SiteURL + "\"\nlicense-url: \"" + RepoURL + "/blob/main/LICENSE\"\n"
	if w.Version != Unreleased {
		s += "version: \"" + w.Version + "\"\n"
	}
	return s
}

// Format renders the work in one of Formats.
func (w Work) Format(f string) (string, error) {
	switch strings.ToLower(f) {
	case "apa":
		return w.APA(), nil
	case "ieee":
		return w.IEEE(), nil
	case "harvard":
		return w.Harvard(), nil
	case "mla":
		return w.MLA(), nil
	case "chicago":
		return w.Chicago(), nil
	case "bibtex", "bib":
		return w.BibTeX(), nil
	case "ris":
		return w.RIS(), nil
	case "csl", "csl-json", "json":
		return w.CSL(), nil
	case "cff":
		return w.CFF(), nil
	}
	return "", fmt.Errorf("unknown citation format %q (use %s)", f, strings.Join(Formats, ", "))
}

// Label is the display name of a style.
func Label(f string) string {
	return map[string]string{"apa": "APA 7", "ieee": "IEEE", "harvard": "Harvard", "mla": "MLA 9", "chicago": "Chicago",
		"bibtex": "BibTeX", "ris": "RIS", "csl": "CSL-JSON", "cff": "CITATION.cff"}[f]
}

// Page is one citable page: a check or an Academy module.
type Page struct {
	ID, Title, Collection, URL string
}

// TeXEscape escapes the characters BibTeX treats specially in a title.
func TeXEscape(s string) string {
	return strings.NewReplacer(`\`, `\textbackslash{}`, "{", `\{`, "}", `\}`, "&", `\&`, "%", `\%`, "$", `\$`, "#", `\#`, "_", `\_`).Replace(s)
}

func (w Work) PageAPA(p Page) string {
	return "OpenVAPT. (" + w.Year + "). " + p.Title + " (Version " + w.Version + "). " + p.Collection + ". Retrieved " + w.Date.US + ", from " + p.URL
}

func (w Work) PageBibTeX(p Page) string {
	key := "openvapt_" + strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(p.ID))
	return "@misc{" + key + ",\n  author       = {{OpenVAPT}},\n  title        = {{" + TeXEscape(p.Title) + "}},\n  year         = {" + w.Year + "},\n  howpublished = {\\url{" + p.URL + "}},\n  note         = {" + p.Collection + ", version " + w.Version + ". Accessed " + w.Date.Long + "}\n}"
}

// PageFormat renders a page citation; pages offer APA and BibTeX, and every
// other format falls back to the software citation with the page named.
func (w Work) PageFormat(p Page, f string) (string, error) {
	switch strings.ToLower(f) {
	case "apa":
		return w.PageAPA(p), nil
	case "bibtex", "bib":
		return w.PageBibTeX(p), nil
	}
	s, err := w.Format(f)
	if err != nil {
		return "", err
	}
	return s, nil
}

// CheckPage and ModulePage build the page for a check or Academy module.
func CheckPage(id, title string) Page {
	return Page{ID: id, Title: id + " " + title, Collection: "OpenVAPT Check Catalogue", URL: SiteURL + "/checks/" + id + ".html"}
}

func ModulePage(id, title string) Page {
	return Page{ID: id, Title: id + ": " + title, Collection: "OpenVAPT Academy", URL: SiteURL + "/academy/" + strings.ToLower(id) + ".html"}
}

// ReportLine is the report's own reference line.
func ReportLine(version string, t time.Time) string {
	v := Version(version)
	if v == Unreleased {
		v = "(" + v + ")"
	} else {
		v = "v" + v
	}
	return "Report generated by OpenVAPT " + v + " on " + t.UTC().Format("2006-01-02") + "."
}
