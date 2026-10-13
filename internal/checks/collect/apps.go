package collect

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// ---------- Application stacks: Tomcat, Python, CMS ----------

var xmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// StripXMLComments removes <!-- --> blocks, so commented-out Tomcat
// connectors and users are never mistaken for active configuration.
func StripXMLComments(s string) string { return xmlComment.ReplaceAllString(s, "") }

var xmlAttr = regexp.MustCompile(`([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*("([^"]*)"|'([^']*)')`)

// XMLElements returns the attributes of every <tag ...> element in an XML
// document (comments removed). Attribute names are lower-cased. It is a small
// scanner for flat configuration files such as server.xml, not a full parser.
func XMLElements(doc, tag string) []map[string]string {
	re := regexp.MustCompile(`(?is)<` + regexp.QuoteMeta(tag) + `\b([^>]*)>`)
	var out []map[string]string
	for _, m := range re.FindAllStringSubmatch(StripXMLComments(doc), -1) {
		attrs := map[string]string{}
		for _, a := range xmlAttr.FindAllStringSubmatch(m[1], -1) {
			v := a[3]
			if a[4] != "" {
				v = a[4]
			}
			attrs[strings.ToLower(a[1])] = v
		}
		out = append(out, attrs)
	}
	return out
}

// TomcatInstance is one Apache Tomcat installation found on disk.
type TomcatInstance struct {
	Conf    string   // folder holding server.xml and tomcat-users.xml
	Webapps []string // folders whose sub-folders are deployed applications
}

// Tomcats finds Tomcat installations from their server.xml, covering the
// Debian/Ubuntu packages (/etc/tomcatN with /var/lib/tomcatN/webapps), the
// RHEL package (/etc/tomcat with /var/lib/tomcat/webapps) and tarball
// installs under /opt, /usr/share and /usr/local.
func Tomcats(s sys.System) []TomcatInstance {
	var confs []string
	for _, pat := range []string{"/etc/tomcat*/server.xml", "/opt/tomcat*/conf/server.xml", "/opt/*/tomcat*/conf/server.xml",
		"/usr/share/tomcat*/conf/server.xml", "/usr/local/tomcat*/conf/server.xml", "/var/lib/tomcat*/conf/server.xml"} {
		m, _ := s.Glob(pat)
		confs = append(confs, m...)
	}
	sort.Strings(confs)
	seen := map[string]bool{}
	var out []TomcatInstance
	for _, c := range confs {
		dir := filepath.Dir(c)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		t := TomcatInstance{Conf: dir}
		if strings.HasPrefix(dir, "/etc/") {
			name := filepath.Base(dir) // tomcat9, tomcat10, tomcat
			t.Webapps = []string{"/var/lib/" + name + "/webapps", "/usr/share/" + name + "-admin", "/usr/share/" + name + "-examples", "/usr/share/" + name + "-docs"}
		} else {
			t.Webapps = []string{filepath.Join(filepath.Dir(dir), "webapps")}
		}
		out = append(out, t)
		if len(out) >= 10 {
			break
		}
	}
	return out
}

// Exists reports whether a path exists (as a file or directory).
func Exists(s sys.System, path string) bool {
	_, err := s.Stat(path)
	return err == nil
}

// ProjectFiles finds files with the given base name in typical application
// locations, up to three folders deep: /srv, /opt, /var/www and home
// directories, plus every web document root. At most 60 paths are returned.
func ProjectFiles(ctx context.Context, s sys.System, names ...string) []string {
	bases := []string{"/srv", "/opt", "/var/www", "/home/*"}
	for _, r := range DocRoots(ctx, s) {
		bases = append(bases, r, filepath.Dir(r))
	}
	set := map[string]bool{}
	for _, b := range bases {
		for _, depth := range []string{"/", "/*/", "/*/*/", "/*/*/*/"} {
			for _, n := range names {
				m, _ := s.Glob(b + depth + n)
				for _, p := range m {
					set[p] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

// CMSConfig is the main configuration file of a content management system.
type CMSConfig struct {
	CMS  string // WordPress, Joomla or Drupal
	Path string
	Text string
}

// CMSConfigs finds WordPress wp-config.php (in a document root or the folder
// above it, where WordPress also looks), Joomla configuration.php and Drupal
// sites/*/settings.php for every local document root. The files hold
// database passwords, so their text is used only for pattern matching and is
// never copied into a report.
func CMSConfigs(ctx context.Context, s sys.System) []CMSConfig {
	var out []CMSConfig
	seen := map[string]bool{}
	add := func(cms, p, marker string) {
		if seen[p] {
			return
		}
		r, err := sys.ReadFileNoFollow(ctx, s, p)
		if err != nil || !strings.Contains(string(r.Data), marker) {
			return
		}
		seen[p] = true
		out = append(out, CMSConfig{CMS: cms, Path: p, Text: string(r.Data)})
	}
	for _, root := range DocRoots(ctx, s) {
		add("WordPress", root+"/wp-config.php", "DB_NAME")
		add("WordPress", filepath.Dir(root)+"/wp-config.php", "DB_NAME")
		add("Joomla", root+"/configuration.php", "JConfig")
		drupal, _ := s.Glob(root + "/sites/*/settings.php")
		sort.Strings(drupal)
		for _, d := range drupal {
			add("Drupal", d, "$databases")
		}
	}
	return out
}
