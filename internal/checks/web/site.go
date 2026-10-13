// Package web contains checks against the websites this machine serves.
//
// Sites are discovered from the local Apache, nginx or LiteSpeed config
// (collect.VHosts). Every request goes to 127.0.0.1 with the site name in the
// Host header, so the scan never leaves the machine, and only safe GET
// requests for fixed paths are sent: no payloads, no form submissions, no
// guessing of passwords.
package web

import (
	"context"
	"strings"
	"sync"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

var refSecureHeaders = check.Ref{Title: "OWASP Secure Headers Project", URL: "https://owasp.org/www-project-secure-headers/"}
var refHTTPHeadersCS = check.Ref{Title: "OWASP HTTP Headers Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"}
var refMDN = func(h string) check.Ref {
	return check.Ref{Title: "MDN Web Docs, " + h, URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/" + h}
}

// Site is one website with its home page response over HTTPS (preferred)
// or HTTP.
type Site struct {
	Name  string
	HTTPS bool
	Home  sys.HTTPResponse
}

var cache sync.Map // key: System -> []Site

// Sites fetches the home page of every local site once per scan and caches
// it, so twenty header checks cost one request per site, not twenty.
func Sites(ctx context.Context, s sys.System) []Site {
	if v, ok := cache.Load(s); ok {
		return v.([]Site)
	}
	var out []Site
	for _, target := range collect.WebTargets(s) {
		if r, err := s.HTTP(ctx, target.Scheme, target.Name, "/"); err == nil {
			out = append(out, Site{Name: target.Name, HTTPS: target.Scheme == "https", Home: r})
		}
	}
	cache.Store(s, out)
	return out
}

// ForEachSite runs fn for every reachable site, or returns a single Skip.
func ForEachSite(ctx context.Context, s sys.System, fn func(Site) check.Result) []check.Result {
	sites := Sites(ctx, s)
	if len(sites) == 0 {
		return []check.Result{check.SkipR("web", "No websites found in the local web server configuration")}
	}
	out := make([]check.Result, 0, len(sites))
	for _, site := range sites {
		out = append(out, fn(site))
	}
	return out
}

// Get fetches a path from a site using the same scheme as its home page.
func (st Site) Get(ctx context.Context, s sys.System, path string) (sys.HTTPResponse, error) {
	scheme := "http"
	if st.HTTPS {
		scheme = "https"
	}
	return s.HTTP(ctx, scheme, st.Name, path)
}

// HTML reports whether a response looks like an HTML page (used to ignore
// "soft 404" pages that return 200 for every path).
func HTML(r sys.HTTPResponse) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/html") ||
		strings.Contains(strings.ToLower(r.Body[:min(len(r.Body), 512)]), "<html")
}

// Redirected reports whether the home page answered with a redirect. Body
// and header checks then skip the site (WEB-CK-001 and WEB-HDR-001 do not,
// because browsers store cookies and honour HSTS on redirects): a redirect response says little
// about the headers of the page users finally see, and following it would
// leave the fixed set of local requests this scan makes.
func (st Site) Redirected() (check.Result, bool) {
	if st.Home.Status >= 300 && st.Home.Status < 400 {
		loc := st.Home.Header.Get("Location")
		return check.SkipR(st.Name, "Home page redirects (HTTP "+itoa(st.Home.Status)+") to "+orNone(loc)+"; headers of the final page were not evaluated"), true
	}
	return check.Result{}, false
}

func orNone(s string) string {
	if s == "" {
		return "(no Location header)"
	}
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
