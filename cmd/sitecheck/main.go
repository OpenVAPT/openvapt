// Command sitecheck verifies a built website folder: every local link and
// asset reference resolves to a file, the SEO and security artefacts exist,
// and no page carries a long dash or a banned phrase.
//
//	go run ./cmd/sitecheck dist/site
//
// It exits non-zero on the first class of problem found, listing each one.
package main

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	attrRe   = regexp.MustCompile(`(?i)\s(?:href|src)="([^"]*)"`)
	required = []string{"index.html", "404.html", "sitemap.xml", "robots.txt", "llms.txt", "llms-full.txt",
		".well-known/security.txt", "checks/index.html", "checks/catalogue.json", "assets/site.css", "assets/og-image.png",
		"assets/charts.js", "assets/catalogue.js", "assets/vendor/echarts.min.js", "assets/vendor/ag-grid-community.min.js",
		"CITATION.cff", "openvapt.bib", "openvapt.ris", "openvapt.json"}
	banned = []string{"\u2014", "\u2013", "AI-generated", "AI agents"} // em dash, en dash, banned phrases
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sitecheck <site folder>")
		os.Exit(2)
	}
	root := os.Args[1]
	var problems []string
	for _, r := range required {
		if _, err := os.Stat(filepath.Join(root, r)); err != nil {
			problems = append(problems, "missing required file: "+r)
		}
	}
	pages, links, broken := 0, 0, 0
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		if strings.HasPrefix(filepath.ToSlash(strings.TrimPrefix(p, root)), "/sample/") {
			return nil // engine-written reports are checked by their own tests
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		pages++
		text := string(b)
		rel, _ := filepath.Rel(root, p)
		for _, bad := range banned {
			// The governance and policy documents quote the banned phrases
			// in the rule that bans them; every other page must not use them.
			if strings.Contains(text, bad) && !strings.HasPrefix(filepath.ToSlash(rel), "legal/") {
				problems = append(problems, fmt.Sprintf("%s: contains %q", rel, bad))
			}
		}
		for _, m := range attrRe.FindAllStringSubmatch(text, -1) {
			raw := m[1]
			if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "data:") || strings.ContainsAny(raw, " ") {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "" || u.Host != "" || u.Path == "" {
				continue
			}
			links++
			target := u.Path
			var fsPath string
			if strings.HasPrefix(target, "/") {
				fsPath = filepath.Join(root, filepath.FromSlash(target))
			} else {
				fsPath = filepath.Join(filepath.Dir(p), filepath.FromSlash(target))
			}
			if strings.HasSuffix(target, "/") {
				fsPath = filepath.Join(fsPath, "index.html")
			}
			key := rel + " -> " + raw
			if seen[key] {
				continue
			}
			seen[key] = true
			if fi, err := os.Stat(fsPath); err != nil || fi.IsDir() {
				broken++
				problems = append(problems, fmt.Sprintf("%s: broken link %s", rel, raw))
			}
		}
		return nil
	})
	if err != nil {
		problems = append(problems, err.Error())
	}
	sort.Strings(problems)
	for _, p := range problems {
		fmt.Println(p)
	}
	fmt.Printf("sitecheck: %d pages, %d local references, %d broken, %d problem(s) in %s\n", pages, links, broken, len(problems), path.Clean(root))
	if len(problems) > 0 {
		os.Exit(1)
	}
}
