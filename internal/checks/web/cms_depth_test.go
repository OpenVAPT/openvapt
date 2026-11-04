package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func TestDrupalCoreLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		want             check.Status
	}{
		{"drupal 8", "/var/www/app/core/lib/Drupal.php", "class Drupal {\n  const VERSION = '8.9.20';\n}\n", check.Fail},
		{"drupal 9", "/var/www/app/core/lib/Drupal.php", "const VERSION = '9.5.11';\n", check.Fail},
		{"drupal 10", "/var/www/app/core/lib/Drupal.php", "const VERSION = '10.3.1';\n", check.Pass},
		{"drupal 11 dev", "/var/www/app/core/lib/Drupal.php", "const VERSION = '11.1.0-dev';\n", check.Pass},
		{"drupal 7", "/var/www/app/includes/bootstrap.inc", "define('VERSION', '7.98');\n", check.Fail},
		{"drupal 6", "/var/www/app/includes/bootstrap.inc", "define('VERSION', '6.38');\n", check.Fail},
		{"unrecognised", "/var/www/app/core/lib/Drupal.php", "class Drupal {}\n", check.Incomplete},
	} {
		f := appFake(map[string]string{tc.path: tc.text})
		if got := one(t, "WEB-CMS-012", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.name, got.Status, got.Message, tc.want)
		}
	}
	if got := one(t, "WEB-CMS-012", appFake(nil)); got.Status != check.Skip {
		t.Errorf("no drupal: got %s, want skip", got.Status)
	}
}

func TestDrupalSettings(t *testing.T) {
	base := "<?php\n$databases['default']['default'] = ['password' => 'x'];\n"
	for _, tc := range []struct {
		id, extra string
		want      check.Status
	}{
		{"WEB-CMS-013", "", check.Fail},
		{"WEB-CMS-013", "# $settings['trusted_host_patterns'] = ['^example\\.com$'];\n", check.Fail},
		{"WEB-CMS-013", "$settings['trusted_host_patterns'] = ['^example\\.com$'];\n", check.Pass},
		{"WEB-CMS-019", "$settings['update_free_access'] = TRUE;\n", check.Fail},
		{"WEB-CMS-019", "$settings['update_free_access'] = FALSE;\n", check.Pass},
		{"WEB-CMS-019", "// $settings['update_free_access'] = TRUE;\n", check.Pass},
		{"WEB-CMS-019", "", check.Pass},
	} {
		f := appFake(map[string]string{"/var/www/app/sites/default/settings.php": base + tc.extra})
		got := one(t, tc.id, f)
		if got.Status != tc.want {
			t.Errorf("%s with %q: got %s (%s %v), want %s", tc.id, tc.extra, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
}

func TestJoomlaCoreLifecycle(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    check.Status
	}{
		{"3.10.12", check.Fail}, {"4.4.9", check.Fail}, {"2.5.28", check.Fail}, {"1.5.26", check.Fail}, {"5.2.0", check.Pass}, {"6.0.0", check.Pass},
	} {
		f := appFake(map[string]string{"/var/www/app/administrator/manifests/files/joomla.xml": "<extension type=\"file\"><name>files_joomla</name><version>" + tc.version + "</version></extension>"})
		if got := one(t, "WEB-CMS-014", f); got.Status != tc.want {
			t.Errorf("joomla %s: got %s (%s), want %s", tc.version, got.Status, got.Message, tc.want)
		}
	}
	f := appFake(map[string]string{"/var/www/app/administrator/manifests/files/joomla.xml": "<extension><!-- <version>3.9.0</version> --></extension>"})
	if got := one(t, "WEB-CMS-014", f); got.Status != check.Incomplete {
		t.Errorf("commented version: got %s, want incomplete", got.Status)
	}
}

func TestMagentoMode(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		want             check.Status
	}{
		{"developer", "/var/www/app/app/etc/env.php", "<?php\nreturn ['MAGE_MODE' => 'developer'];\n", check.Fail},
		{"default", "/var/www/app/app/etc/env.php", "<?php\nreturn ['MAGE_MODE' => 'default'];\n", check.Fail},
		{"missing", "/var/www/app/app/etc/env.php", "<?php\nreturn ['db' => []];\n", check.Fail},
		{"production", "/var/www/app/app/etc/env.php", "<?php\nreturn ['MAGE_MODE' => 'production'];\n", check.Pass},
		{"commented developer", "/var/www/app/app/etc/env.php", "<?php\nreturn [\n  // 'MAGE_MODE' => 'developer',\n  'MAGE_MODE' => 'production',\n];\n", check.Pass},
	} {
		f := appFake(map[string]string{tc.path: tc.text})
		if got := one(t, "WEB-CMS-015", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.name, got.Status, got.Message, tc.want)
		}
	}
	// Magento served from pub/: env.php sits one folder above the root.
	f := &sys.Fake{Files: map[string]string{
		"/etc/nginx/sites-enabled/shop":    "server {\n  root /var/www/magento/pub;\n  server_name shop.example.test;\n}\n",
		"/var/www/magento/app/etc/env.php": "<?php\nreturn ['MAGE_MODE' => 'developer'];\n",
	}}
	if got := one(t, "WEB-CMS-015", f); got.Status != check.Fail {
		t.Errorf("pub/ root: got %s (%s), want fail", got.Status, got.Message)
	}
}

func TestGhostURL(t *testing.T) {
	ghost := func(url string) string {
		return `{"url": "` + url + `", "server": {"port": 2368}, "database": {"client": "sqlite3"}}`
	}
	for _, tc := range []struct {
		text string
		want check.Status
	}{
		{ghost("http://blog.example.test"), check.Fail},
		{ghost("https://blog.example.test"), check.Pass},
		{`{"server": {"port": 2368}, "database": {}}`, check.Incomplete},
	} {
		f := appFake(map[string]string{"/srv/blog/config.production.json": tc.text})
		if got := one(t, "WEB-CMS-016", f); got.Status != tc.want {
			t.Errorf("%q: got %s (%s), want %s", tc.text, got.Status, got.Message, tc.want)
		}
	}
	// A config.production.json that is not Ghost is ignored.
	f := appFake(map[string]string{"/srv/other/config.production.json": `{"url": "http://x"}`})
	if got := one(t, "WEB-CMS-016", f); got.Status != check.Skip {
		t.Errorf("non-ghost file: got %s, want skip", got.Status)
	}
}

func TestWordPressCronAndAuthor(t *testing.T) {
	html := http.Header{"Content-Type": {"text/html; charset=UTF-8"}}
	for _, tc := range []struct {
		name string
		resp sys.HTTPResponse
		want check.Status
	}{
		{"empty 200 body", sys.HTTPResponse{Status: 200, Header: html, Body: ""}, check.Fail},
		{"plain text 200", sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: "ok"}, check.Fail},
		{"soft 404 html page", sys.HTTPResponse{Status: 200, Header: html, Body: "<html>Not found</html>"}, check.Pass},
		{"403", sys.HTTPResponse{Status: 403, Header: html, Body: "<html>Forbidden</html>"}, check.Pass},
	} {
		f := appFake(nil)
		f.HTTPResp["https://app.example.test/wp-cron.php"] = tc.resp
		if got := one(t, "WEB-CMS-017", f); got.Status != tc.want {
			t.Errorf("wp-cron %s: got %s, want %s", tc.name, got.Status, tc.want)
		}
	}
	for _, tc := range []struct {
		name string
		resp sys.HTTPResponse
		want check.Status
	}{
		{"301 to author archive", sys.HTTPResponse{Status: 301, Header: http.Header{"Location": {"https://app.example.test/author/admin/"}}}, check.Fail},
		{"302 to author archive", sys.HTTPResponse{Status: 302, Header: http.Header{"Location": {"/author/admin/"}}}, check.Fail},
		{"redirect elsewhere", sys.HTTPResponse{Status: 301, Header: http.Header{"Location": {"https://app.example.test/"}}}, check.Pass},
		{"404", sys.HTTPResponse{Status: 404, Header: html, Body: "<html>Not found</html>"}, check.Pass},
	} {
		f := appFake(nil)
		f.HTTPResp["https://app.example.test/?author=1"] = tc.resp
		got := one(t, "WEB-CMS-018", f)
		if got.Status != tc.want {
			t.Errorf("author %s: got %s, want %s", tc.name, got.Status, tc.want)
		}
		for _, e := range got.Evidence {
			if strings.Contains(e, "admin") {
				t.Errorf("author %s: evidence reveals the login name: %q", tc.name, e)
			}
		}
	}
}
