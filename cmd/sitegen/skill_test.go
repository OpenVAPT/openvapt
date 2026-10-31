package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSkillPage: the VAPT skill page has one h1, a section per document, links
// between documents point inside the page, no front matter leaks, and every
// raw file is published byte for byte.
func TestSkillPage(t *testing.T) {
	out := t.TempDir()
	t.Chdir("../..")
	body, inputs := renderSkill(out)
	html := string(body)
	if n := strings.Count(html, "<h1"); n != 1 {
		t.Errorf("want one h1, got %d", n)
	}
	for _, p := range skillParts {
		id := strings.TrimSuffix(filepath.Base(p.file), ".md")
		if !strings.Contains(html, `<section id="`+id+`">`) || !strings.Contains(html, `href="#`+id+`"`) {
			t.Errorf("section or contents link for %s missing", id)
		}
	}
	for _, bad := range []string{"## RHEL", "## Uses the local", "](references/", "name: openvapt-vapt", "license: LicenseRef"} {
		if strings.Contains(html, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	if len(inputs) != len(skillParts)+1 {
		t.Errorf("inputs = %d, want %d", len(inputs), len(skillParts)+1)
	}
	for _, src := range inputs {
		want, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(out, src))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s not published byte for byte", src)
		}
	}
	if stripFrontMatter("---\na: b\n---\nbody") != "body" {
		t.Error("front matter not stripped")
	}
}
