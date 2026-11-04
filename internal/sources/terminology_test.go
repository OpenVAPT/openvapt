package sources

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTerminology enforces GCA invariants I5 and I7 (AGENTS.md 4.7): public
// text never describes OpenVAPT as "open source" or "non-profit", and never
// as "AI-generated" or built by "AI agents". A banned phrase is allowed only
// when the line plainly negates or quotes it, or names a third party
// (e.g. OSV, "Open Source Vulnerabilities").
func TestTerminology(t *testing.T) {
	banned := regexp.MustCompile(`(?i)\b(open[- ]source|non-?profit|ai-generated|ai agents?)\b`)
	allowed := regexp.MustCompile(`(?i)\bnot\b|\bnever\b|rather than|"open source"|"non-profit"|open source vulnerabilit|is openvapt open source\?`)
	var files []string
	for _, pattern := range []string{"../../*.md", "../../docs/*.md", "../../docs/adr/*.md", "../../site/content/*.html", "../../site/templates/*.html", "../../cmd/sitegen/*.go", "../../internal/terms/*.go", "../../internal/academy/*.go"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 20 {
		t.Fatalf("only %d files matched; the globs are wrong", len(files))
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if banned.MatchString(line) && !allowed.MatchString(line) {
				t.Errorf("%s:%d uses banned wording (AGENTS.md 4.7): %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
