package web

import (
	"bufio"
	"context"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// serverConf is the merged, comment-free configuration of one web server
// (nginx or Apache) as read from its main file and every include it names
// under the server's own configuration folder. It is read-only input for the
// WEB-NGX and WEB-APA hardening checks; nothing is executed or reloaded.
type serverConf struct {
	Paths      []string     // files that were read, in include order
	Lines      []confLine   // directives with comments removed
	Complete   bool         // false when any file was truncated
	Found      bool         // at least one configuration file was readable
	Present    bool         // the server appears installed (folder or binary exists)
	kind       serverKind   // nginx or apache
	skip       check.Result // ready-made Skip or Incomplete result when !Found
	serverRoot string       // Apache ServerRoot when set and under the prefixes
	// tlsFloor is the system crypto library floor, read only for rules that
	// set wantFloor. A directive that lists TLS 1.0 or 1.1 cannot take
	// effect when the library already refuses those versions.
	tlsFloor collect.TLSFloor
}

type confLine struct {
	Key   string // lower-case directive name
	Value string // the rest of the line, trimmed, without a trailing ';'
	Raw   string // the trimmed original line, for evidence
	File  string
}

type serverKind struct {
	name     string
	roots    []string // configuration entry points (globs allowed)
	includes []string // directive names that pull in other files
	prefixes []string // include targets must stay under these folders
	markers  []string // paths whose existence means the server is installed
}

var nginxKind = serverKind{
	name:     "nginx",
	roots:    []string{"/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"},
	includes: []string{"include"},
	prefixes: []string{"/etc/nginx/", "/usr/local/nginx/conf/"},
	markers:  []string{"/etc/nginx", "/usr/sbin/nginx", "/usr/local/nginx"},
}

var apacheKind = serverKind{
	name:     "Apache",
	roots:    []string{"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/httpd.conf"},
	includes: []string{"include", "includeoptional"},
	prefixes: []string{"/etc/apache2/", "/etc/httpd/"},
	markers:  []string{"/etc/apache2", "/etc/httpd", "/usr/sbin/apache2", "/usr/sbin/httpd"},
}

// readServerConf reads the configuration tree of one web server. Includes are
// followed only when they stay under the server's own configuration folders,
// to a bounded depth, and each file is read once.
func readServerConf(ctx context.Context, s sys.System, k serverKind) serverConf {
	c := serverConf{kind: k}
	for _, m := range k.markers {
		if _, err := s.Stat(m); err == nil {
			c.Present = true
			break
		}
	}
	c.Complete = true
	seen := map[string]bool{}
	for _, root := range k.roots {
		for _, p := range expand(s, root) {
			readConfTree(ctx, s, &c, p, seen, 0)
		}
	}
	c.Found = len(c.Paths) > 0
	if !c.Found {
		target := strings.Join(k.roots, ", ")
		if c.Present {
			c.skip = check.IncompleteR(target, k.name+" appears installed but its configuration could not be read")
		} else {
			c.skip = check.SkipR(target, k.name+" is not installed")
		}
	}
	return c
}

func expand(s sys.System, pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}
	}
	m, _ := s.Glob(pattern)
	sort.Strings(m)
	return m
}

func readConfTree(ctx context.Context, s sys.System, c *serverConf, path string, seen map[string]bool, depth int) {
	if depth > 16 || seen[path] || len(c.Paths) >= 200 {
		return
	}
	seen[path] = true
	r, err := s.ReadFile(ctx, path)
	if err != nil {
		return
	}
	c.Paths = append(c.Paths, path)
	c.Complete = c.Complete && r.Complete
	sc := bufio.NewScanner(strings.NewReader(string(r.Data)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if i := strings.Index(raw, "#"); i >= 0 {
			raw = strings.TrimSpace(raw[:i])
		}
		if raw == "" {
			continue
		}
		for _, stmt := range splitStatements(c.kind, raw) {
			c.addLine(ctx, s, path, stmt, seen, depth)
		}
	}
}

// splitStatements breaks one nginx line into its statements, so that
// "server { listen 443 ssl; root /srv; }" yields the block opener and each
// directive separately. Apache lines are one directive each and are returned
// unchanged (its regex patterns may legitimately contain braces).
func splitStatements(k serverKind, raw string) []string {
	if k.name != nginxKind.name {
		return []string{raw}
	}
	var out []string
	var cur strings.Builder
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for _, r := range raw {
		switch r {
		case ';', '{', '}':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// addLine records one statement and follows it when it is an include.
func (c *serverConf) addLine(ctx context.Context, s sys.System, path, raw string, seen map[string]bool, depth int) {
	line := strings.TrimSpace(strings.TrimSuffix(raw, ";"))
	f := strings.Fields(line)
	if len(f) == 0 {
		return
	}
	key := strings.ToLower(f[0])
	val := strings.TrimSpace(strings.TrimPrefix(line, f[0]))
	c.Lines = append(c.Lines, confLine{Key: key, Value: val, Raw: raw, File: path})
	if key == "serverroot" {
		if root := strings.Trim(val, `"'`); underPrefixes(root+"/", c.kind.prefixes) {
			c.serverRoot = strings.TrimSuffix(root, "/")
		}
		return
	}
	if !isInclude(c.kind, key) {
		return
	}
	for _, p := range f[1:] {
		p = strings.Trim(p, `"'`)
		if !strings.HasPrefix(p, "/") {
			// Relative includes resolve against the server root: an
			// explicit ServerRoot when seen, otherwise the configuration
			// folder the current file lives in (/etc/nginx, /etc/httpd).
			p = c.baseDir(path) + "/" + p
		}
		if !underPrefixes(p, c.kind.prefixes) {
			continue
		}
		for _, file := range expand(s, p) {
			readConfTree(ctx, s, c, file, seen, depth+1)
		}
	}
}

func (c *serverConf) baseDir(current string) string {
	if c.serverRoot != "" {
		return c.serverRoot
	}
	for _, pre := range c.kind.prefixes {
		if strings.HasPrefix(current, pre) {
			return strings.TrimSuffix(pre, "/")
		}
	}
	return strings.TrimSuffix(c.kind.prefixes[0], "/")
}

func isInclude(k serverKind, key string) bool {
	for _, i := range k.includes {
		if key == i {
			return true
		}
	}
	return false
}

func underPrefixes(p string, prefixes []string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// directive returns every line whose directive name matches key.
func (c serverConf) directive(key string) []confLine {
	var out []confLine
	for _, l := range c.Lines {
		if l.Key == strings.ToLower(key) {
			out = append(out, l)
		}
	}
	return out
}

// has reports whether any directive named key has a value for which want
// returns true. Values are compared in lower case.
func (c serverConf) has(key string, want func(string) bool) bool {
	for _, l := range c.directive(key) {
		if want(strings.ToLower(l.Value)) {
			return true
		}
	}
	return false
}

// anyValue reports whether any directive named key is present at all.
func (c serverConf) anyValue(key string) bool { return len(c.directive(key)) > 0 }

// evidenceFor renders the matching lines as "file: line" evidence.
func (c serverConf) evidenceFor(keys ...string) []string {
	var out []string
	for _, k := range keys {
		for _, l := range c.directive(k) {
			out = append(out, l.File+": "+l.Raw)
		}
	}
	return out
}

// containsBlock reports whether a block opener matching all needles exists,
// for example a "location ~ /\." block in nginx or a <DirectoryMatch "^\.|\/\.">
// in Apache. The comparison is case-insensitive on the raw line.
func (c serverConf) containsBlock(needles ...string) bool {
	for _, l := range c.Lines {
		raw := strings.ToLower(l.Raw)
		ok := true
		for _, n := range needles {
			if !strings.Contains(raw, strings.ToLower(n)) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// serverRule is one configuration-file hardening check for nginx or Apache.
// evaluate returns bad=true with evidence when the weakness is present.
type serverRule struct {
	id, title                                string
	sev                                      check.Severity
	cat                                      check.Category
	cvss, summary, rationale, detection, fix string
	verify                                   string
	refs                                     []check.Ref
	std                                      check.Standards
	kind                                     serverKind
	evaluate                                 func(c serverConf) (bad bool, ev []string)
	// evaluateSys, when set, replaces evaluate for rules that must also look
	// at the file system (for example whether a document root holds the
	// files a missing deny rule would expose).
	evaluateSys func(ctx context.Context, s sys.System, c serverConf) (bad bool, ev []string)
	// skip, when set and true, reports Skip with the message before anything
	// is evaluated (for example a TLS rule when no site is served over TLS).
	skip func(c serverConf) (bool, string)
	// wantFloor asks for the system TLS floor to be read into c.tlsFloor.
	wantFloor bool
	// pass, when set, replaces passMsg so a Pass can say why (for example
	// that the library floor, not the directive, forbids TLS 1.0).
	pass func(c serverConf) string
	// incomplete, when set, turns a would-be Pass into Incomplete when the
	// configuration leaves the setting undecidable (for example a default
	// that depends on the software version). It never changes a Fail.
	incomplete func(c serverConf) (bool, string)
	passMsg    string
}

func registerServerRule(r serverRule) {
	effort := check.EffortLow
	check.Register(&check.Check{
		ID: r.id, Title: r.title, Domain: check.DomainWeb, Severity: r.sev, Category: r.cat, Effort: effort, CVSS: r.cvss,
		Summary: r.summary, Rationale: r.rationale, Detection: r.detection, Fix: r.fix, Verify: r.verify, Refs: r.refs, Standards: r.std,
		Run: func(ctx context.Context, s sys.System) []check.Result {
			c := readServerConf(ctx, s, r.kind)
			if !c.Found {
				return []check.Result{c.skip}
			}
			target := c.Paths[0]
			if r.skip != nil {
				if hit, msg := r.skip(c); hit {
					return []check.Result{check.SkipR(target, msg)}
				}
			}
			if r.wantFloor {
				c.tlsFloor = collect.SystemTLSFloor(ctx, s)
			}
			var bad bool
			var ev []string
			if r.evaluateSys != nil {
				bad, ev = r.evaluateSys(ctx, s, c)
			} else {
				bad, ev = r.evaluate(c)
			}
			if bad {
				return []check.Result{check.FailR(target, r.summary, ev...)}
			}
			if !c.Complete {
				return []check.Result{check.IncompleteR(target, "Configuration input was truncated; the setting could not be confirmed")}
			}
			if r.incomplete != nil {
				if hit, msg := r.incomplete(c); hit {
					return []check.Result{check.IncompleteR(target, msg, ev...)}
				}
			}
			msg := r.passMsg
			if r.pass != nil {
				msg = r.pass(c)
			}
			if msg == "" {
				msg = "The hardening setting is present"
			}
			return []check.Result{check.PassR(target, msg, ev...)}
		},
	})
}

// Shared TLS judgement for nginx ssl_protocols / Apache SSLProtocol values.

// weakTLSProtocols returns the protocol names in v that are below TLS 1.2.
// nginx lists the allowed versions ("TLSv1 TLSv1.1 TLSv1.2"); Apache uses
// "+TLSv1.2" and "-all" style tokens. Both are handled: an Apache value
// starting with "all" or "-all" is expanded to the explicit list first.
func weakTLSProtocols(v string) []string {
	v = strings.ToLower(v)
	allowed := map[string]bool{}
	fields := strings.Fields(v)
	for _, f := range fields {
		switch {
		case f == "all" || f == "+all":
			for _, p := range []string{"sslv3", "tlsv1", "tlsv1.1", "tlsv1.2", "tlsv1.3"} {
				allowed[p] = true
			}
		case f == "-all":
			allowed = map[string]bool{}
		case strings.HasPrefix(f, "-"):
			delete(allowed, strings.TrimPrefix(f, "-"))
		case strings.HasPrefix(f, "+"):
			allowed[strings.TrimPrefix(f, "+")] = true
		default:
			allowed[f] = true
		}
	}
	var weak []string
	for _, p := range []string{"sslv2", "sslv3", "tlsv1", "tlsv1.1"} {
		if allowed[p] {
			weak = append(weak, p)
		}
	}
	return weak
}

// weakCipherTokens are substrings whose presence in a cipher list marks a
// suite the Mozilla TLS guidelines and RFC 7525 advise against. A list that
// starts with "!" or "-" for the token is an exclusion and is not flagged.
var weakCipherTokens = []string{"null", "export", "des", "rc4", "md5", "anon", "adh", "aecdh", "psk", "srp", "idea", "seed", "camellia"}

// weakCiphers returns the offending tokens in an OpenSSL cipher list. "des"
// also matches 3DES suites, which is intended: both are legacy.
func weakCiphers(list string) []string {
	var out []string
	for _, tok := range strings.Split(strings.ToLower(list), ":") {
		tok = strings.TrimSpace(tok)
		if tok == "" || strings.HasPrefix(tok, "!") || strings.HasPrefix(tok, "-") {
			continue
		}
		if tok == "all" || tok == "default" || tok == "complementofdefault" || tok == "complementofall" {
			out = append(out, tok)
			continue
		}
		for _, w := range weakCipherTokens {
			if strings.Contains(tok, w) {
				out = append(out, tok)
				break
			}
		}
	}
	return out
}

// weakProtocolLines returns the directive lines (ssl_protocols or
// SSLProtocol) that still allow a version below TLS 1.2, rendered as
// evidence.
func weakProtocolLines(c serverConf, key string) []string {
	var ev []string
	for _, l := range c.directive(key) {
		if w := weakTLSProtocols(l.Value); len(w) > 0 {
			ev = append(ev, l.File+": "+l.Raw+" (allows "+strings.Join(w, ", ")+")")
		}
	}
	return ev
}

// floorOverrides reports whether the system crypto library floor already
// refuses TLS 1.0 and 1.1, so a permissive directive has no effect.
func floorOverrides(c serverConf) bool { return c.tlsFloor.Known && c.tlsFloor.Forbids }

const floorPassMsg = "The directive still lists TLS 1.0 or 1.1, but the system crypto library floor refuses them, so they cannot be negotiated; tidy the directive so the configuration says what it does"
