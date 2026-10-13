package web

import (
	"context"
	"net/http"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func TestWPDefineIgnoresCommentsAndKeepsFirst(t *testing.T) {
	cfg := "<?php\n// define('WP_DEBUG', true);\n/* define('AUTOMATIC_UPDATER_DISABLED', true); */\n# define('X', 1);\ndefine('WP_HOME', 'http://example.test');\ndefine( 'WP_DEBUG', false );\ndefine('WP_DEBUG', true);\ndefine('Y', (bool) getenv('Y'));\n"
	if v, ok := wpDefine(cfg, "WP_DEBUG"); !ok || v != "false" {
		t.Errorf("WP_DEBUG = %q %v, want the first active value false", v, ok)
	}
	if _, ok := wpDefine(cfg, "AUTOMATIC_UPDATER_DISABLED"); ok {
		t.Error("a commented-out define must not count")
	}
	if v, _ := wpDefine(cfg, "WP_HOME"); v != "http://example.test" {
		t.Errorf("URLs must survive comment stripping, got %q", v)
	}
	if v, _ := wpDefine(cfg, "Y"); v != "(bool) getenv('y'" && v != "(bool) getenv('y')" {
		t.Errorf("expression value read as %q", v)
	}
}

func TestInspectPortIsNotTheInspector(t *testing.T) {
	if inspectFlag.MatchString("node --inspect-port=9230 app.js") {
		t.Error("--inspect-port does not start the inspector")
	}
	for _, s := range []string{"node --inspect app.js", "node --inspect=0.0.0.0:9229 app.js", "node --inspect-brk"} {
		if !inspectFlag.MatchString(s) {
			t.Errorf("%q starts the inspector", s)
		}
	}
}

func TestDjangoLastDebugAssignmentWins(t *testing.T) {
	run := func(settings string) string {
		f := &sys.Fake{Files: map[string]string{"/srv/app/app/settings.py": "INSTALLED_APPS = []\n" + settings}}
		for _, c := range check.All() {
			if c.ID == "WEB-PY-001" {
				return string(c.Run(context.Background(), f)[0].Status)
			}
		}
		return ""
	}
	if got := run("DEBUG = False\nDEBUG = True\n"); got != "fail" {
		t.Errorf("a later DEBUG = True is what Python uses, got %s", got)
	}
	if got := run("DEBUG = True\nDEBUG = os.environ.get('D') == '1'\n"); got != "pass" {
		t.Errorf("a final environment-driven DEBUG is safe, got %s", got)
	}
}

// linkFake refuses no-follow reads of the paths in links, like the live
// system does for a symlink.
type linkFake struct {
	*sys.Fake
	links map[string]bool
}

func (l linkFake) ReadFileNoFollow(ctx context.Context, p string) (sys.ReadResult, error) {
	if l.links[p] {
		return sys.ReadResult{}, sys.ErrNotRegular
	}
	return l.Fake.ReadFile(ctx, p)
}

func TestDjangoSettingsLinkIsNotFollowed(t *testing.T) {
	p := "/srv/app/app/settings.py"
	f := linkFake{&sys.Fake{Files: map[string]string{p: "INSTALLED_APPS = []\nDEBUG = True\n"}}, map[string]bool{p: true}}
	if got := djangoSettings(context.Background(), f); len(got) != 0 {
		t.Fatalf("a symlinked settings.py was read: %v", got)
	}
	f.links = nil
	if got := djangoSettings(context.Background(), f); len(got) != 1 {
		t.Fatalf("a regular settings.py was not read: %v", got)
	}
}

func runOn(t *testing.T, id string, f sys.System) []check.Result {
	t.Helper()
	for _, c := range check.All() {
		if c.ID == id {
			return c.Run(context.Background(), f)
		}
	}
	t.Fatalf("check %s not registered", id)
	return nil
}

func TestRedirectStillEvaluatesCookiesAndHSTS(t *testing.T) {
	redirect := func(scheme string) *sys.Fake {
		listen := "80"
		if scheme == "https" {
			listen = "443 ssl"
		}
		return &sys.Fake{
			Files: map[string]string{"/etc/nginx/nginx.conf": "server {\n listen " + listen + ";\n server_name r.test;\n}\n"},
			HTTPResp: map[string]sys.HTTPResponse{scheme + "://r.test/": {
				Status:  301,
				Header:  http.Header{"Location": {scheme + "://www.r.test/"}},
				Cookies: []*http.Cookie{{Name: "sid", Value: "x"}},
			}},
		}
	}
	if r := runOn(t, "WEB-CK-001", redirect("https")); len(r) != 1 || r[0].Status != check.Fail {
		t.Errorf("cookie without flags on a redirect must fail: %+v", r)
	}
	if r := runOn(t, "WEB-HDR-001", redirect("https")); len(r) != 1 || r[0].Status != check.Fail {
		t.Errorf("HTTPS redirect without HSTS must fail: %+v", r)
	}
	if r := runOn(t, "WEB-HDR-001", redirect("http")); len(r) != 1 || r[0].Status != check.Skip {
		t.Errorf("HSTS is not evaluated over plain HTTP: %+v", r)
	}
	ok := redirect("https")
	resp := ok.HTTPResp["https://r.test/"]
	resp.Header.Set("Strict-Transport-Security", "max-age=31536000")
	resp.Cookies = []*http.Cookie{{Name: "sid", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}}
	ok.HTTPResp["https://r.test/"] = resp
	if r := runOn(t, "WEB-CK-001", ok); r[0].Status != check.Pass {
		t.Errorf("flagged cookie on a redirect must pass: %+v", r)
	}
	if r := runOn(t, "WEB-HDR-001", ok); r[0].Status != check.Pass {
		t.Errorf("HSTS on a redirect must pass: %+v", r)
	}
	if r := runOn(t, "WEB-HDR-002", ok); r[0].Status != check.Skip {
		t.Errorf("other header checks keep skipping redirects: %+v", r)
	}
}
