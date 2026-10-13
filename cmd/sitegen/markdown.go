package main

import (
	"html"
	"regexp"
	"strings"
)

// markdown converts the small Markdown subset used by the legal documents
// (headings, paragraphs, bullet and numbered lists, bold, inline code, links,
// blockquotes) into HTML. All text is HTML-escaped first, so a document can
// never inject markup into the website.
func markdown(src string) string {
	var out strings.Builder
	var para []string
	list := "" // "ul" or "ol" while inside a list
	flush := func() {
		if len(para) > 0 {
			out.WriteString("<p>" + inline(strings.Join(para, " ")) + "</p>\n")
			para = nil
		}
	}
	closeList := func() {
		if list != "" {
			out.WriteString("</" + list + ">\n")
			list = ""
		}
	}
	olRe := regexp.MustCompile(`^\d+\.\s+`)
	var table [][]string
	flushTable := func() {
		if len(table) == 0 {
			return
		}
		out.WriteString(`<div class="table-wrap"><table class="table"><thead><tr>`)
		for _, c := range table[0] {
			out.WriteString("<th>" + inline(c) + "</th>")
		}
		out.WriteString("</tr></thead><tbody>")
		for _, row := range table[1:] {
			out.WriteString("<tr>")
			for _, c := range row {
				out.WriteString("<td>" + inline(c) + "</td>")
			}
			out.WriteString("</tr>")
		}
		out.WriteString("</tbody></table></div>\n")
		table = nil
	}
	sepRe := regexp.MustCompile(`^\|[\s:|-]+\|$`)
	for _, raw := range strings.Split(src, "\n") {
		if t := strings.TrimSpace(raw); strings.HasPrefix(t, "|") && strings.HasSuffix(t, "|") {
			flush()
			closeList()
			if !sepRe.MatchString(t) {
				cells := strings.Split(strings.Trim(t, "|"), "|")
				for i := range cells {
					cells[i] = strings.TrimSpace(cells[i])
				}
				table = append(table, cells)
			}
			continue
		}
		flushTable()
		line := strings.TrimRight(raw, " ")
		t := strings.TrimSpace(line)
		switch {
		case t == "":
			flush()
			closeList()
		case strings.HasPrefix(t, "#"):
			flush()
			closeList()
			level := len(t) - len(strings.TrimLeft(t, "#"))
			if level == 1 {
				continue // the page layout already prints the title as the only h1
			}
			if level > 4 {
				level = 4
			}
			text := strings.TrimSpace(t[level:])
			out.WriteString("<h" + string(rune('0'+level)) + " id=\"" + slug(text) + "\">" + inline(text) + "</h" + string(rune('0'+level)) + ">\n")
		case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* "):
			flush()
			if list != "ul" {
				closeList()
				out.WriteString("<ul>\n")
				list = "ul"
			}
			out.WriteString("<li>" + inline(t[2:]) + "</li>\n")
		case olRe.MatchString(t):
			flush()
			if list != "ol" {
				closeList()
				out.WriteString("<ol>\n")
				list = "ol"
			}
			out.WriteString("<li>" + inline(olRe.ReplaceAllString(t, "")) + "</li>\n")
		case strings.HasPrefix(t, "> "):
			flush()
			closeList()
			out.WriteString("<blockquote>" + inline(t[2:]) + "</blockquote>\n")
		default:
			if list != "" && (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")) {
				continue
			}
			closeList()
			para = append(para, t)
		}
	}
	flush()
	closeList()
	flushTable()
	return out.String()
}

var (
	reCode = regexp.MustCompile("`([^`]+)`")
	reBold = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	reLink = regexp.MustCompile(`\[([^\]]+)\]\((https?://[^)\s]+|[a-zA-Z0-9_./#-]+)\)`)
)

// mdPages maps a repository Markdown file to the file name of the legal page
// it is rendered as, so links between legal documents resolve on the site.
var mdPages = map[string]string{}

func inline(s string) string {
	s = html.EscapeString(s)
	s = reCode.ReplaceAllString(s, "<code>$1</code>")
	s = reBold.ReplaceAllString(s, "<strong>$1</strong>")
	s = reLink.ReplaceAllStringFunc(s, func(m string) string {
		p := reLink.FindStringSubmatch(m)
		href := p[2]
		if strings.HasPrefix(href, "//") {
			return m // protocol-relative URL: could point at any site, so leave it as plain text
		}
		if page, ok := mdPages[href]; ok {
			href = page // a repository document that has its own legal page
		} else if strings.HasSuffix(href, ".md") {
			href = strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(href, "_", "-")), ".md") + ".html"
		}
		return `<a href="` + href + `" rel="noreferrer">` + p[1] + `</a>`
	})
	return s
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
