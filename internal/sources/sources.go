// Package sources builds the complete, generated list of every public source
// that OpenVAPT's checks and Academy modules cite, grouped by publisher, with
// each publisher's terms and any credit line those terms ask for. SOURCES.md
// at the repository root is generated from it; a test fails if SOURCES.md is
// stale or if a check cites a website that has no publisher entry here.
//
// Regenerate with: go test ./internal/sources -update
package sources

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
)

// Publisher describes who publishes a cited source and on what terms.
// Terms describes how OpenVAPT uses the material, never more than titles,
// identifiers and links; Credit is the attribution line the publisher's terms
// ask for, or empty when none is required for linking.
type Publisher struct {
	Name   string
	Hosts  []string
	Terms  string
	Credit string
}

const linkOnly = "Copyright of the publisher. Cited by title and link only; no text is copied."

// Publishers is ordered as it is printed. Every host cited anywhere must
// appear in exactly one entry (TestEveryHostHasPublisher).
var Publishers = []Publisher{
	{"NIST (National Institute of Standards and Technology)", []string{"csrc.nist.gov", "nvd.nist.gov", "pages.nist.gov"},
		"Works of the U.S. Government, not subject to copyright in the United States. Cited by title, identifier and link.",
		"Includes references to NIST publications and the National Vulnerability Database (NVD). Use of NIST material does not imply endorsement by NIST."},
	{"The MITRE Corporation (ATT&CK, CWE, CVE)", []string{"attack.mitre.org", "cwe.mitre.org", "www.cve.org"},
		"Identifiers, names and links only, under the published ATT&CK, CWE and CVE terms of use.",
		"© The MITRE Corporation. ATT&CK®, CVE® and CWE™ are trademarks of The MITRE Corporation; identifiers are cited under MITRE's published terms of use, and their use does not imply endorsement by MITRE."},
	{"FIRST (Forum of Incident Response and Security Teams)", []string{"www.first.org"},
		"The CVSS v3.1 scale and vector notation are applied; the specification text is not copied.",
		"CVSS is owned by FIRST.Org, Inc. and is used under the terms FIRST publishes for public use of CVSS, with attribution and a link to https://www.first.org/cvss/. FIRST does not endorse OpenVAPT."},
	{"OWASP Foundation", []string{"owasp.org", "cheatsheetseries.owasp.org", "top10.owasp.org", "wstg.owasp.org"},
		"The cited OWASP projects are published under CC BY-SA 4.0. Cited by title, identifier and link; no text is copied.",
		"References OWASP Top 10, ASVS, WSTG and Cheat Sheet Series, © OWASP Foundation, CC BY-SA 4.0."},
	{"Center for Internet Security (CIS)", []string{"www.cisecurity.org"},
		"CIS Controls v8 is published by the Center for Internet Security, Inc. under CC BY-NC-ND 4.0. Referred to by Control number and link only; no CIS text is reproduced.",
		"CIS Controls® is a trademark of the Center for Internet Security, Inc. Use does not imply endorsement by CIS."},
	{"IETF / RFC Editor", []string{"www.rfc-editor.org"},
		"RFCs are © IETF Trust and the persons identified as authors (BCP 78). Cited by number, title and link.", ""},
	{"CISA (U.S. Cybersecurity and Infrastructure Security Agency)", []string{"www.cisa.gov"},
		"U.S. Government work. Cited by title and link; the KEV catalogue is used only by the release pipeline.", ""},
	{"OSV (Open Source Vulnerabilities, osv.dev)", []string{"osv.dev"},
		"Cited by link. Advisory data is downloaded only by the release pipeline; licences vary by originating database and are recorded per release (docs/VULNDB.md).", ""},
	{"OASIS Open", []string{"docs.oasis-open.org"}, "The SARIF 2.1.0 format is implemented; the specification text is not copied.", ""},
	{"W3C", []string{"www.w3.org"}, linkOnly, ""},
	{"IANA", []string{"www.iana.org"}, "Public registry data (port numbers) consulted; cited by link.", ""},
	{"PTES (Penetration Testing Execution Standard)", []string{"www.pentest-standard.org", "pentest-standard.readthedocs.io"}, linkOnly, ""},
	{"Linux Kernel Documentation", []string{"docs.kernel.org"}, "Kernel documentation is generally distributed under GPL-2.0; individual files may carry other licences. Cited by title and link only.", ""},
	{"Linux Manual Pages (man7.org, Ubuntu and Debian Manpages)", []string{"man7.org", "manpages.ubuntu.com", "manpages.debian.org"}, "Man pages carry per-page licences. Cited by page name and link only.", ""},
	{"OpenBSD (OpenSSH Manual Pages)", []string{"man.openbsd.org"}, "Manual pages generally under BSD or ISC style licences. Cited by page name and link only.", ""},
	{"freedesktop.org and systemd", []string{"www.freedesktop.org", "systemd.io"}, linkOnly, ""},
	{"GNU Project", []string{"www.gnu.org"}, "Most GNU manuals are published under the GNU FDL. Cited by title and link only.", ""},
	{"sudo Project", []string{"www.sudo.ws"}, linkOnly, ""},
	{"nftables Project", []string{"wiki.nftables.org"}, linkOnly, ""},
	{"chrony Project", []string{"chrony-project.org"}, linkOnly, ""},
	{"Linux Distributions (Debian, Ubuntu, Red Hat)", []string{"www.debian.org", "wiki.debian.org", "ubuntu.com", "access.redhat.com"}, linkOnly, ""},
	{"endoflife.date (Community-Maintained)", []string{"endoflife.date"}, "Community-maintained data, published by the project under its stated open licence, consulted for release dates, cross-checked with vendor pages.", ""},
	{"Mozilla (MDN Web Docs and Mozilla Wiki)", []string{"developer.mozilla.org", "wiki.mozilla.org"}, "MDN prose is published by Mozilla Contributors under CC BY-SA 2.5; Mozilla wiki pages carry the licence stated on the wiki. Cited by title and link only.", ""},
	{"Let's Encrypt (ISRG)", []string{"letsencrypt.org"}, linkOnly, ""},
	{"Apache Software Foundation (HTTP Server, Tomcat)", []string{"httpd.apache.org", "tomcat.apache.org"}, "Apache documentation is published under the Apache License 2.0. Cited by title and link only.", ""},
	{"PHP Documentation", []string{"www.php.net"}, "The PHP manual is published under CC BY 3.0. Cited by title and link only.", ""},
	{"Web Frameworks and Runtimes (Django, Flask, Werkzeug, Node.js, Express, Gunicorn)", []string{"docs.djangoproject.com", "flask.palletsprojects.com", "werkzeug.palletsprojects.com", "nodejs.org", "expressjs.com", "docs.gunicorn.org", "gunicorn.org"}, linkOnly, ""},
	{"Content Management Systems (WordPress, Drupal, Joomla)", []string{"developer.wordpress.org", "www.drupal.org", "docs.joomla.org"}, linkOnly, ""},
	{"Containers and Orchestration (Docker, Kubernetes)", []string{"docs.docker.com", "kubernetes.io"}, linkOnly, ""},
	{"Databases and Data Services (MySQL, PostgreSQL, MongoDB, Redis, Memcached, Elastic)", []string{"dev.mysql.com", "www.postgresql.org", "www.mongodb.com", "redis.io", "docs.memcached.org", "www.elastic.co"}, linkOnly, ""},
	{"Network Services (BIND 9, Samba, Postfix, Dovecot)", []string{"bind9.readthedocs.io", "www.samba.org", "www.postfix.org", "doc.dovecot.org"}, linkOnly, ""},
	{"Projects Hosted on GitHub (Publisher Named in Each Title)", []string{"github.com"}, linkOnly, ""},
}

// Citation is one distinct cited source and everything that cites it.
type Citation struct {
	Title, URL string
	UsedBy     []string // check and module ids
}

// Host returns the lower-case host of a URL, or "" if it does not parse.
func Host(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// PublisherFor returns the publisher entry for a host, or nil.
func PublisherFor(host string) *Publisher {
	for i := range Publishers {
		for _, h := range Publishers[i].Hosts {
			if h == host {
				return &Publishers[i]
			}
		}
	}
	return nil
}

// Collect gathers every reference from the registered checks and the Academy
// modules, de-duplicated by URL. Callers must import internal/checks/all.
func Collect() []Citation {
	byURL := map[string]*Citation{}
	add := func(title, u, by string) {
		c := byURL[u]
		if c == nil {
			c = &Citation{Title: title, URL: u}
			byURL[u] = c
		}
		c.UsedBy = append(c.UsedBy, by)
	}
	for _, c := range check.All() {
		for _, r := range c.Refs {
			add(r.Title, r.URL, c.ID)
		}
	}
	for _, m := range academy.Modules {
		for _, r := range m.Refs {
			add(r.Title, r.URL, "Academy "+m.ID)
		}
	}
	out := make([]Citation, 0, len(byURL))
	for _, c := range byURL {
		sort.Strings(c.UsedBy)
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		return out[i].URL < out[j].URL
	})
	return out
}

// Markdown renders SOURCES.md.
func Markdown(cs []Citation) string {
	var b strings.Builder
	b.WriteString("# Sources Cited by Checks and the Academy\n\n")
	b.WriteString("Generated from the code by `internal/sources` (regenerate with `go test ./internal/sources -update`); do not edit by hand. ")
	b.WriteString("Every reference that any check or Academy module cites is listed here, grouped by publisher, with the publisher's terms and any credit line those terms ask for. ")
	b.WriteString("OpenVAPT cites sources by title, identifier and link; it does not copy their text. Use of a source does not imply that its publisher endorses OpenVAPT.\n\n")
	checks := 0
	for _, c := range check.All() {
		if len(c.Refs) > 0 {
			checks++
		}
	}
	fmt.Fprintf(&b, "Totals: %d distinct sources from %d publishers, cited by %d checks and %d Academy modules.\n\n", len(cs), usedPublishers(cs), checks, len(academy.Modules))
	for _, p := range Publishers {
		var mine []Citation
		for _, c := range cs {
			if pub := PublisherFor(Host(c.URL)); pub != nil && pub.Name == p.Name {
				mine = append(mine, c)
			}
		}
		if len(mine) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s\n\n- Terms: %s\n", p.Name, p.Terms)
		if p.Credit != "" {
			fmt.Fprintf(&b, "- Credit: %s\n", p.Credit)
		}
		b.WriteString("\n| Source | Cited By |\n|---|---|\n")
		for _, c := range mine {
			fmt.Fprintf(&b, "| [%s](%s) | %s |\n", cell(c.Title), c.URL, strings.Join(c.UsedBy, ", "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func usedPublishers(cs []Citation) int {
	seen := map[*Publisher]bool{}
	for _, c := range cs {
		if p := PublisherFor(Host(c.URL)); p != nil {
			seen[p] = true
		}
	}
	return len(seen)
}

func cell(s string) string {
	return strings.NewReplacer("|", "\\|", "[", "\\[", "]", "\\]").Replace(s)
}
