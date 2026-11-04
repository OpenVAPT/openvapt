package main

import (
	"html"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/cite"
)

// TestWebsiteCitationFromSingleSource: the cite page, the header and footer
// Cite panels, the Cite This Page boxes and llms.txt render the citation
// from internal/cite, the same source as the CLI, reports and README
// (cmd/openvapt/cite_test.go).
func TestWebsiteCitationFromSingleSource(t *testing.T) {
	w := citeWork()
	text := func(b CiteBox) string { return html.UnescapeString(string(b.Text)) }
	unspan := func(s string) string {
		for _, k := range []string{"long", "us", "iso", "van", "ieee"} {
			s = strings.NewReplacer(`<span data-date="`+k+`">`, "", "</span>", "").Replace(s)
		}
		return s
	}
	want := map[string]string{"apa": plainDates(w.APA()), "ieee": plainDates(w.IEEE()), "harvard": plainDates(w.Harvard()),
		"mla": plainDates(w.MLA()), "chicago": plainDates(w.Chicago()), "bibtex": plainDates(w.BibTeX())}
	for _, s := range citeStyles() {
		if exp, ok := want[s.ID]; ok && unspan(text(s.Boxes[0])) != exp {
			t.Errorf("cite page %s = %q, want %q", s.ID, unspan(text(s.Boxes[0])), exp)
		}
	}
	q := quickCite("h", Page{Path: "checks/HOST-SSH-001.html", PageCite: pageCite("HOST-SSH-001", "HOST-SSH-001 Title", "OpenVAPT Check Catalogue", "checks/HOST-SSH-001.html")})
	if len(q.Styles) != len(cite.Styles) || q.PageKind != "Check" || len(q.Page) != 2 {
		t.Fatalf("quick panel: %d styles, kind %q, %d page boxes", len(q.Styles), q.PageKind, len(q.Page))
	}
	for i, s := range q.Styles {
		if s.ID != "h-"+cite.Styles[i] || unspan(text(s.Boxes[0])) != want[cite.Styles[i]] {
			t.Errorf("quick panel style %s differs from internal/cite", s.ID)
		}
	}
	if m := quickCite("f", Page{Path: "academy/f1.html", PageCite: pageCite("F1", "F1: X", "OpenVAPT Academy", "academy/f1.html")}); m.PageKind != "Module" {
		t.Error("module page should offer Cite This Module")
	}
	if quickCite("f", Page{Path: "index.html"}).Page != nil {
		t.Error("plain pages cite only OpenVAPT")
	}
	if l := llmsCite(); !strings.Contains(l, "## How to Cite") || !strings.Contains(l, w.APA()) || !strings.Contains(l, w.BibTeX()) {
		t.Error("llms.txt How to Cite section differs from internal/cite")
	}
	if printCite() != plainDates(w.APA()) {
		t.Error("print citation differs")
	}
}
