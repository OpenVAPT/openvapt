package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

const shop = "shop.example.test"

func webFake(conf string, resp map[string]sys.HTTPResponse) *sys.Fake {
	f := &sys.Fake{Files: map[string]string{"/etc/apache2/sites-enabled/shop.conf": conf}, HTTPResp: resp, Infos: map[string]sys.FileInfo{}}
	return f
}

func html(body string) sys.HTTPResponse {
	return sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: body}
}

func one(t *testing.T, id string, f sys.System) check.Result {
	t.Helper()
	rs := check.Get(id).Run(context.Background(), f)
	if len(rs) != 1 {
		t.Fatalf("%s: want one result, got %+v", id, rs)
	}
	return rs[0]
}

// C-05: only a refused connection proves plain HTTP is not served.
func TestPlainHTTPErrorsAreIncompleteUnlessRefused(t *testing.T) {
	conf := "<VirtualHost *:443>\n ServerName " + shop + "\n</VirtualHost>\n"
	f := webFake(conf, map[string]sys.HTTPResponse{"https://" + shop + "/": html("<html>ok</html>")})
	if r := one(t, "WEB-TLS-001", f); r.Status != check.Pass || !strings.Contains(r.Message, "refused") {
		t.Errorf("nothing on port 80 should pass as refused, got %+v", r)
	}
	f.HTTPErr = map[string]error{"http://" + shop + "/": context.DeadlineExceeded}
	if r := one(t, "WEB-TLS-001", f); r.Status != check.Incomplete {
		t.Errorf("timeout must be Incomplete, got %+v", r)
	}
}

// C-06: the scheme is decided per block, and a configured site that does
// not answer is reported, not dropped.
func TestVhostSchemePerBlockAndUnansweredSites(t *testing.T) {
	conf := "server {\n listen 443 ssl;\n server_name secure.example.test;\n}\nserver {\n listen 80;\n server_name plain.example.test;\n}\n"
	f := &sys.Fake{Files: map[string]string{"/etc/nginx/sites-enabled/sites": conf}, HTTPResp: map[string]sys.HTTPResponse{
		"https://secure.example.test/": html("<html>s</html>"), "http://plain.example.test/": html("<html>p</html>")}}
	targets := collect.WebTargets(f)
	want := map[string]string{"secure.example.test": "https", "plain.example.test": "http"}
	for _, tg := range targets {
		if want[tg.Name] != tg.Scheme {
			t.Errorf("%s: want %s, got %s", tg.Name, want[tg.Name], tg.Scheme)
		}
	}
	if len(targets) != 2 {
		t.Fatalf("want 2 targets, got %+v", targets)
	}
	rs := check.Get("WEB-SEC-001").Run(context.Background(), f)
	if len(rs) != 2 {
		t.Fatalf("both sites should be assessed: %+v", rs)
	}
	// A configured name that never answers is Incomplete, not silence.
	f2 := &sys.Fake{Files: map[string]string{"/etc/nginx/sites-enabled/sites": conf}, HTTPResp: map[string]sys.HTTPResponse{"https://secure.example.test/": html("<html>s</html>")}}
	rs = check.Get("WEB-SEC-001").Run(context.Background(), f2)
	inc := 0
	for _, r := range rs {
		if r.Status == check.Incomplete && r.Target == "plain.example.test" {
			inc++
		}
	}
	if inc != 1 {
		t.Errorf("unanswered site must be Incomplete once, got %+v", rs)
	}
	// Apache: :80 and :443 blocks for one name give one https site.
	conf = "<VirtualHost *:80>\n ServerName " + shop + "\n</VirtualHost>\n<VirtualHost *:443>\n ServerName " + shop + "\n SSLEngine on\n</VirtualHost>\n"
	f3 := webFake(conf, map[string]sys.HTTPResponse{"https://" + shop + "/": html("<html>s</html>"), "http://" + shop + "/": {Status: 301, Header: http.Header{"Location": {"https://" + shop + "/"}}}})
	sites := Sites(context.Background(), f3)
	if len(sites) != 1 || !sites[0].HTTPS {
		t.Errorf("want one https site, got %+v", sites)
	}
}

// C-07: only WordPress's own readme signature counts.
func TestWordPressReadmeNeedsSignature(t *testing.T) {
	conf := "<VirtualHost *:443>\n ServerName " + shop + "\n</VirtualHost>\n"
	soft := webFake(conf, map[string]sys.HTTPResponse{"https://" + shop + "/": html("<html>ok</html>"), "https://" + shop + "/readme.html": html("<html>Our shop runs on WordPress. Page not found.</html>")})
	if r := one(t, "WEB-CMS-001", soft); r.Status != check.Pass {
		t.Errorf("soft-404 mentioning WordPress must not fire, got %+v", r)
	}
	real := webFake(conf, map[string]sys.HTTPResponse{"https://" + shop + "/": html("<html>ok</html>"), "https://" + shop + "/readme.html": html(`<h1 id="logo"><a href="https://wordpress.org/">WordPress</a><br /> Version 6.4.3</h1>`)})
	if r := one(t, "WEB-CMS-001", real); r.Status != check.Fail || !strings.Contains(strings.Join(r.Evidence, " "), "WordPress 6.4.3") {
		t.Errorf("real readme must fire with the version, got %+v", r)
	}
}

// C-04: a status page that answers from 127.0.0.1 passes when the
// configuration restricts it to local clients, and fails otherwise.
func TestStatusPageLocalOnlyNuance(t *testing.T) {
	conf := "<VirtualHost *:443>\n ServerName " + shop + "\n</VirtualHost>\n"
	resp := map[string]sys.HTTPResponse{"https://" + shop + "/": html("<html>ok</html>"), "https://" + shop + "/server-status": html("<h1>Apache Server Status for shop</h1>")}
	open := webFake(conf, resp)
	if r := one(t, "WEB-EXP-006", open); r.Status != check.Fail || !strings.Contains(strings.Join(r.Evidence, " "), "confirm from another machine") {
		t.Errorf("unrestricted status page must fail with the nuance, got %+v", r)
	}
	local := webFake(conf, resp)
	local.Files["/etc/apache2/mods-enabled/status.conf"] = "<Location /server-status>\n SetHandler server-status\n Require local\n</Location>\n"
	if r := one(t, "WEB-EXP-006", local); r.Status != check.Pass || !strings.Contains(strings.Join(r.Evidence, " "), "Require local") {
		t.Errorf("Require local must pass with evidence, got %+v", r)
	}
	nginx := &sys.Fake{Files: map[string]string{"/etc/nginx/sites-enabled/s": "server {\n listen 443 ssl;\n server_name " + shop + ";\n location /nginx_status {\n stub_status;\n allow 127.0.0.1;\n deny all;\n }\n}\n"},
		HTTPResp: map[string]sys.HTTPResponse{"https://" + shop + "/": html("<html>ok</html>"), "https://" + shop + "/nginx_status": {Status: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: "Active connections: 1"}}}
	if r := one(t, "WEB-EXP-006", nginx); r.Status != check.Pass {
		t.Errorf("nginx allow/deny must pass, got %+v", r)
	}
}

// C-09: archives and certificates are Medium review items; keys, dumps and
// backups stay High; download folders are expected.
func TestDocRootArchiveSplit(t *testing.T) {
	conf := "<VirtualHost *:443>\n DocumentRoot /var/www/shop\n ServerName " + shop + "\n</VirtualHost>\n"
	f := webFake(conf, nil)
	for _, p := range []string{"/var/www/shop/index.php", "/var/www/shop/site.tar.gz", "/var/www/shop/chain.pem", "/var/www/shop/downloads/release-1.0.tgz"} {
		f.Infos[p] = sys.FileInfo{Path: p, Mode: 0o644}
	}
	if r := one(t, "WEB-DOC-001", f); r.Status != check.Pass {
		t.Errorf("plain archives and certificates must not be High, got %+v", r)
	}
	r := one(t, "WEB-DOC-003", f)
	ev := strings.Join(r.Evidence, "\n")
	if r.Status != check.Fail || !strings.Contains(ev, "site.tar.gz") || !strings.Contains(ev, "chain.pem") || !strings.Contains(ev, "release-1.0.tgz (in a download folder, expected)") {
		t.Errorf("review items wrong: %+v", r)
	}
	f.Infos["/var/www/shop/server-key.pem"] = sys.FileInfo{Path: "/var/www/shop/server-key.pem", Mode: 0o600}
	f.Infos["/var/www/shop/backup-2026.tar.gz"] = sys.FileInfo{Path: "/var/www/shop/backup-2026.tar.gz", Mode: 0o644}
	r = one(t, "WEB-DOC-001", f)
	ev = strings.Join(r.Evidence, "\n")
	if r.Status != check.Fail || !strings.Contains(ev, "server-key.pem (private key)") || !strings.Contains(ev, "backup-2026.tar.gz (backup archive)") || strings.Contains(ev, "chain.pem") {
		t.Errorf("High items wrong: %+v", r)
	}
	// A download-only root passes WEB-DOC-003 and lists what it saw.
	g := webFake(conf, nil)
	g.Infos["/var/www/shop/downloads/a.tar.gz"] = sys.FileInfo{Path: "/var/www/shop/downloads/a.tar.gz", Mode: 0o644}
	if r := one(t, "WEB-DOC-003", g); r.Status != check.Pass || len(r.Evidence) != 1 {
		t.Errorf("download folder should pass with a note, got %+v", r)
	}
}
