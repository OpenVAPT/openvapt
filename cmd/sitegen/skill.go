package main

import (
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// skillDir holds the VAPT skill for AI assistants (Agent Skills format).
const skillDir = "skills/openvapt-vapt"

// skillParts lists the skill's documents in reading order, with the section
// title the web page gives each one. LICENSE.md is published raw only.
var skillParts = []struct{ file, title string }{
	{"SKILL.md", "The Skill"},
	{"references/scope-and-authorisation.md", "Scope and Authorisation"},
	{"references/assessment-playbook.md", "Assessment Playbook"},
	{"references/defence-playbook.md", "Defence Playbook"},
	{"references/reporting.md", "Scoring and Reporting"},
}

var skillRefLink = regexp.MustCompile(`\]\(references/([a-z-]+)\.md(#[a-z0-9-]+)?\)`)

// renderSkill copies the raw skill files into outDir and returns the page body
// and the source files it was built from. Each document becomes one section;
// headings drop one level so each section starts at h2, and links between the
// documents point at the matching place on this page.
func renderSkill(outDir string) (template.HTML, []string) {
	var inputs []string
	toc := `<nav aria-label="On This Page" class="muted"><p><strong>On This Page:</strong> `
	body := ""
	for i, part := range append(skillParts, struct{ file, title string }{"LICENSE.md", ""}) {
		src := filepath.Join(skillDir, part.file)
		b, err := os.ReadFile(src) // #nosec G304 -- fixed build-time paths
		must(err)
		inputs = append(inputs, src)
		must(os.MkdirAll(filepath.Join(outDir, skillDir, filepath.Dir(part.file)), 0o755)) // #nosec G301 -- public website directory
		must(os.WriteFile(filepath.Join(outDir, skillDir, part.file), b, 0o644))           // #nosec G306 -- public website file
		if part.title == "" {
			continue
		}
		text := stripFrontMatter(strings.ReplaceAll(string(b), "\r\n", "\n"))
		text = skillRefLink.ReplaceAllStringFunc(text, func(m string) string {
			sm := skillRefLink.FindStringSubmatch(m)
			if sm[2] != "" {
				return "](" + sm[2] + ")"
			}
			return "](#" + sm[1] + ")"
		})
		text = strings.ReplaceAll(text, "](LICENSE.md)", "]("+skillDir+"/LICENSE.md)")
		var lines []string
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, "#") {
				l = "#" + l
			}
			lines = append(lines, l)
		}
		id := strings.TrimSuffix(filepath.Base(part.file), ".md")
		if i > 0 {
			toc += " &middot; "
		}
		toc += `<a href="#` + id + `">` + template.HTMLEscapeString(part.title) + `</a>`
		body += `<section id="` + id + `">` + markdown(strings.Join(lines, "\n")) + `<p class="muted"><a href="#top">Back to Top</a> &middot; <a href="` + repoURL + `/blob/main/` + src + `">View Source</a></p></section>`
	}
	toc += `</p></nav>`
	head := `<div class="legal" id="top"><h1>VAPT Skill for AI Assistants</h1>` +
		`<p class="lead">A free Agent Skills folder that teaches an AI assistant to assess and defend a Linux machine you own or control, with OpenVAPT and read-only checks. Detection and defence only: this machine only, no exploit code. It helps reduce risk; it does not make a machine secure.</p>` +
		`<h2 id="install">Install</h2><p>Copy the folder <a href="` + skillDir + `/SKILL.md">` + skillDir + `</a> (SKILL.md, LICENSE.md and references/) into your assistant's skills folder, for example <code>~/.claude/skills/</code> or <code>.claude/skills/</code> in a project, or clone it from <a href="` + repoURL + `/tree/main/` + skillDir + `">GitHub</a>. Own Use only: keep LICENSE.md with the folder, and do not bundle it into a product or run it for clients or as a service. Version 0.1 is served from the main branch and is not yet part of a tagged release.</p>`
	return template.HTML(head + toc + body + `</div>`), inputs // #nosec G203 -- markdown() HTML-escapes all text first
}

// stripFrontMatter removes a leading YAML front matter block.
func stripFrontMatter(s string) string {
	if strings.HasPrefix(s, "---\n") {
		if i := strings.Index(s[4:], "\n---\n"); i >= 0 {
			return s[4+i+5:]
		}
	}
	return s
}
