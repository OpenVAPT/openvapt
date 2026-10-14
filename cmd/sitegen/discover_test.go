package main

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/channels"
	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
)

// TestMarkdownTwins: every check and module page has a twin, index, worksheet
// and legal pages do not, and a twin carries the facts of its page plus the
// front matter that names the canonical HTML address.
func TestMarkdownTwins(t *testing.T) {
	for path, want := range map[string]string{
		"checks/HOST-SSH-001.html": "checks/HOST-SSH-001.md", "academy/f1.html": "academy/f1.md",
		"faq.html": "faq.md", "glossary.html": "glossary.md",
		"checks/index.html": "", "academy/index.html": "", "academy/worksheet-f1.html": "", "academy/key-f1.html": "",
		"legal/eula.html": "", "index.html": "", "download.html": "",
	} {
		if got := mdTwin(path); got != want {
			t.Errorf("mdTwin(%q) = %q, want %q", path, got, want)
		}
	}
	c := check.Get("HOST-SSH-001")
	if c == nil {
		t.Fatal("HOST-SSH-001 missing")
	}
	md := checkMarkdown(c, "2026-10-14")
	for _, want := range []string{"---\ntitle: \"HOST-SSH-001 ", "canonical: https://openvapt.com/checks/HOST-SSH-001.html", "modified: 2026-10-14",
		"# HOST-SSH-001 " + c.Title, c.Summary, "## How to Fix", c.Fix, "## How to Verify", c.Verify, "## Source Code", c.SourceFile, "## References", "built by AI Cybersecurity Engineers"} {
		if !strings.Contains(md, want) {
			t.Errorf("check twin lacks %q", want)
		}
	}
	m := academy.Get("F1")
	mm := moduleMarkdown(m, "2026-10-14")
	for _, want := range []string{"# F1: " + m.Title, "## You Will Be Able To", m.Objectives[0], "## " + m.Sections[0].Heading, "## Check Yourself", "## Key Terms", "canonical: https://openvapt.com/academy/f1.html"} {
		if !strings.Contains(mm, want) {
			t.Errorf("module twin lacks %q", want)
		}
	}
	if f := faqMarkdown("2026-10-14"); !strings.Contains(f, "## "+faqs[0].Q) || !strings.Contains(f, faqs[0].A) {
		t.Error("FAQ twin lacks the first entry")
	}
}

// TestFeed: the Atom feed lists every recorded release, newest first, parses
// as XML and links the GitHub release of each.
func TestFeed(t *testing.T) {
	sc := siteChannels{State: &channels.State{Current: map[channels.Channel]channels.Release{
		channels.Alpha: {Channel: channels.Alpha, Version: "v0.1.0-alpha.2", Commit: "abc", Date: "2026-10-13", Decision: "promoted automatically: every gate passed", Evidence: []string{"CI Green"}}}},
		History: []channels.Release{{Channel: channels.Alpha, Version: "v0.1.0-alpha.1", Commit: "def", Date: "2026-10-12", Decision: "promoted"}, {Channel: channels.Alpha, Version: "v0.1.0-alpha.2", Commit: "abc", Date: "2026-10-13"}}}
	f := buildFeed(sc)
	if len(f.Entries) != 2 || f.Entries[0].Title != "OpenVAPT v0.1.0-alpha.2 (Alpha)" || f.Entries[1].ID != repoURL+"/releases/tag/v0.1.0-alpha.1" {
		t.Fatalf("entries: %+v", f.Entries)
	}
	if f.Updated != "2026-10-13T00:00:00Z" || f.Entries[0].Updated != "2026-10-13T00:00:00Z" {
		t.Errorf("updated = %q / %q", f.Updated, f.Entries[0].Updated)
	}
	if !strings.Contains(f.Entries[0].Content.Text, "CI Green") || !strings.Contains(f.Entries[0].Content.Text, "/channels.html") {
		t.Error("entry content lacks evidence or the channels page")
	}
	b, err := xml.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back atomFeed
	if err := xml.Unmarshal(b, &back); err != nil || back.NS != "http://www.w3.org/2005/Atom" || len(back.Entries) != 2 {
		t.Fatalf("feed does not round-trip: %v", err)
	}
	if len(buildFeed(siteChannels{}).Entries) != 0 {
		t.Error("empty state should give an empty feed, not a crash")
	}
}

// TestManifestAndCodemeta: both files are valid JSON with the fields the
// consumers (browsers, Bing, research-software catalogues) read, and the
// icons they name exist in site/static.
func TestManifestAndCodemeta(t *testing.T) {
	m := manifest()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"name", "short_name", "start_url", "icons", "theme_color", "display"} {
		if back[k] == nil {
			t.Errorf("manifest lacks %s", k)
		}
	}
	for _, f := range []string{"../../site/static/assets/icon-192.png", "../../site/static/assets/icon-512.png", "../../site/static/assets/apple-touch-icon.png", "../../site/static/favicon.ico", "../../site/static/assets/og-image.png"} {
		if !fileExists(f) {
			t.Errorf("%s missing", f)
		}
	}
	cm := codemeta(check.All())
	if _, err := json.Marshal(cm); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"@context", "name", "codeRepository", "license", "version", "programmingLanguage", "author", "isAccessibleForFree"} {
		if cm[k] == nil {
			t.Errorf("codemeta lacks %s", k)
		}
	}
	if cm["funding"] != "None. OpenVAPT accepts no payments or donations." {
		t.Error("codemeta must say there is no funding")
	}
}

// TestIndexNowKey: the key file in site/ matches a published key file in
// site/static, as IndexNow requires.
func TestIndexNowKey(t *testing.T) {
	b, err := readFile("../../site/indexnow-key.txt")
	if err != nil {
		t.Skip("no key file")
	}
	k := strings.TrimSpace(b)
	if len(k) < 8 || strings.Trim(k, "0123456789abcdef") != "" {
		t.Fatalf("key %q is not lowercase hex", k)
	}
	if pub, err := readFile("../../site/static/" + k + ".txt"); err != nil || strings.TrimSpace(pub) != k {
		t.Errorf("site/static/%s.txt must contain the key", k)
	}
}
