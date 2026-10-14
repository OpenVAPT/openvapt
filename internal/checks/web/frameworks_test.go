package web

import (
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// appFake returns a fake with one Apache site whose document root is
// /var/www/app and the given project files (path -> text, all mode 0644
// unless an Infos entry overrides it).
func appFake(files map[string]string) *sys.Fake {
	f := &sys.Fake{Files: map[string]string{
		"/etc/apache2/sites-enabled/app.conf": "<VirtualHost *:443>\n  DocumentRoot /var/www/app\n  ServerName app.example.test\n</VirtualHost>\n",
	}, Infos: map[string]sys.FileInfo{}, HTTPResp: map[string]sys.HTTPResponse{
		"https://app.example.test/": {Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: "<html>app</html>"},
	}}
	for p, t := range files {
		f.Files[p] = t
	}
	return f
}

func TestParseDotenv(t *testing.T) {
	v := parseDotenv("# comment\nexport APP_ENV=prod\nAPP_DEBUG=\"true\" # trailing\nAPP_KEY='base64:abc'\nBAD LINE\n")
	for k, want := range map[string]string{"APP_ENV": "prod", "APP_DEBUG": "true", "APP_KEY": "base64:abc"} {
		if v[k] != want {
			t.Errorf("%s = %q, want %q", k, v[k], want)
		}
	}
}

func TestLaravelAndSymfonyEnv(t *testing.T) {
	for _, tc := range []struct {
		id, env string
		want    check.Status
	}{
		{"WEB-APP-001", "APP_KEY=base64:abc\nAPP_DEBUG=true\n", check.Fail},
		{"WEB-APP-001", "APP_KEY=\nAPP_DEBUG=false\n", check.Fail},
		{"WEB-APP-001", "APP_KEY=base64:abc\nAPP_DEBUG=false\n", check.Pass},
		{"WEB-APP-001", "APP_KEY=base64:abc\n", check.Pass},
		{"WEB-APP-001", "APP_SECRET=abc\nAPP_DEBUG=1\n", check.Skip}, // Symfony file is not Laravel
		{"WEB-APP-003", "APP_SECRET=abc\nAPP_ENV=dev\n", check.Fail},
		{"WEB-APP-003", "APP_SECRET=abc\nAPP_ENV=prod\nAPP_DEBUG=1\n", check.Fail},
		{"WEB-APP-003", "APP_SECRET=abc\nAPP_ENV=prod\nAPP_DEBUG=0\n", check.Pass},
		{"WEB-APP-003", "APP_KEY=base64:abc\nAPP_ENV=local\n", check.Skip}, // Laravel file is not Symfony
	} {
		f := appFake(map[string]string{"/srv/app/.env": tc.env})
		got := one(t, tc.id, f)
		if got.Status != tc.want {
			t.Errorf("%s with %q: got %s (%s %v), want %s", tc.id, tc.env, got.Status, got.Message, got.Evidence, tc.want)
		}
		for _, e := range got.Evidence {
			if strings.Contains(e, "abc") {
				t.Errorf("%s: evidence leaks a value: %q", tc.id, e)
			}
		}
	}
}

func TestEnvFilePermissions(t *testing.T) {
	for _, tc := range []struct {
		mode fs.FileMode
		want check.Status
	}{
		{0o644, check.Fail}, {0o604, check.Fail}, {0o640, check.Pass}, {0o600, check.Pass},
	} {
		f := appFake(map[string]string{"/srv/app/.env": "DB_PASSWORD=x\n"})
		f.Infos["/srv/app/.env"] = sys.FileInfo{Path: "/srv/app/.env", Mode: tc.mode}
		if got := one(t, "WEB-APP-002", f); got.Status != tc.want {
			t.Errorf("mode %04o: got %s, want %s", tc.mode, got.Status, tc.want)
		}
	}
	if got := one(t, "WEB-APP-002", appFake(nil)); got.Status != check.Skip {
		t.Errorf("no .env: got %s, want skip", got.Status)
	}
}

func TestRailsKeyAndForceSSL(t *testing.T) {
	// master.key: mode and location.
	for _, tc := range []struct {
		name, path string
		mode       fs.FileMode
		want       check.Status
	}{
		{"600 outside web root", "/srv/app/config/master.key", 0o600, check.Pass},
		{"world readable", "/srv/app/config/master.key", 0o644, check.Fail},
		{"inside web root", "/var/www/app/config/master.key", 0o600, check.Fail},
		{"credentials key readable", "/srv/app/config/credentials/production.key", 0o644, check.Fail},
		{"secrets.yml readable", "/srv/app/config/secrets.yml", 0o644, check.Fail},
	} {
		f := appFake(map[string]string{tc.path: "k\n"})
		f.Infos[tc.path] = sys.FileInfo{Path: tc.path, Mode: tc.mode}
		if got := one(t, "WEB-APP-004", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// force_ssl.
	for _, tc := range []struct {
		rb   string
		want check.Status
	}{
		{"Rails.application.configure do\n  config.force_ssl = true\nend\n", check.Pass},
		{"Rails.application.configure do\n  config.force_ssl = false\nend\n", check.Fail},
		{"Rails.application.configure do\n  # config.force_ssl = true\nend\n", check.Fail},
		{"Rails.application.configure do\nend\n", check.Fail},
	} {
		f := appFake(map[string]string{"/srv/app/config/environments/production.rb": tc.rb})
		if got := one(t, "WEB-APP-005", f); got.Status != tc.want {
			t.Errorf("production.rb %q: got %s, want %s", tc.rb, got.Status, tc.want)
		}
	}
}

func TestSpringActuator(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		want             check.Status
	}{
		{"properties wildcard", "/opt/api/application.properties", "management.endpoints.web.exposure.include=*\n", check.Fail},
		{"properties env listed", "/opt/api/application.properties", "management.endpoints.web.exposure.include=health,env\n", check.Fail},
		{"properties health only", "/opt/api/application.properties", "management.endpoints.web.exposure.include=health,info\n", check.Pass},
		{"wildcard on management port", "/opt/api/application.properties", "management.endpoints.web.exposure.include=*\nmanagement.server.port=9090\n", check.Pass},
		{"yaml wildcard", "/opt/api/application.yml", "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n", check.Fail},
		{"yaml health", "/opt/api/application.yml", "management:\n  endpoints:\n    web:\n      exposure:\n        include: health\n", check.Pass},
	} {
		f := appFake(map[string]string{tc.path: tc.text})
		if got := one(t, "WEB-APP-006", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// Loopback probe: /actuator/env answering fails even with no properties file.
	f := appFake(nil)
	f.HTTPResp["https://app.example.test/actuator/env"] = sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: `{"activeProfiles":[],"propertySources":[]}`}
	if got := one(t, "WEB-APP-006", f); got.Status != check.Fail {
		t.Errorf("actuator probe: got %s, want fail", got.Status)
	}
	if got := one(t, "WEB-APP-006", appFake(nil)); got.Status != check.Skip {
		t.Errorf("nothing found: got %s, want skip", got.Status)
	}
}

func TestFlaskDebugInCode(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       check.Status
	}{
		{"run debug", "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0', debug=True)\n", check.Fail},
		{"attribute", "import flask\napp = flask.Flask(__name__)\napp.debug = True\n", check.Fail},
		{"commented", "from flask import Flask\napp = Flask(__name__)\n# app.run(debug=True)\napp.run()\n", check.Pass},
		{"from environment", "import os\nfrom flask import Flask\napp = Flask(__name__)\napp.run(debug=os.environ.get('FLASK_DEBUG') == '1')\n", check.Pass},
		{"not flask", "import django\nDEBUG = True\n", check.Skip},
	} {
		f := appFake(map[string]string{"/srv/app/app.py": tc.text})
		if got := one(t, "WEB-APP-007", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
}

func TestLockFileAge(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want check.Status
	}{
		{30 * 24 * time.Hour, check.Pass}, {364 * 24 * time.Hour, check.Pass}, {366 * 24 * time.Hour, check.Fail}, {0, check.Incomplete},
	} {
		f := appFake(map[string]string{"/srv/app/composer.lock": "{}"})
		info := sys.FileInfo{Path: "/srv/app/composer.lock", Mode: 0o644}
		if tc.age > 0 {
			info.ModTime = time.Now().Add(-tc.age)
		}
		f.Infos["/srv/app/composer.lock"] = info
		if got := one(t, "WEB-APP-008", f); got.Status != tc.want {
			t.Errorf("age %v: got %s (%s), want %s", tc.age, got.Status, got.Message, tc.want)
		}
	}
	if got := one(t, "WEB-APP-008", appFake(nil)); got.Status != check.Skip {
		t.Errorf("no lock files: got %s, want skip", got.Status)
	}
}

func TestGitInsideWebRoot(t *testing.T) {
	if got := one(t, "WEB-APP-009", appFake(map[string]string{"/var/www/app/.git/HEAD": "ref: refs/heads/main\n"})); got.Status != check.Fail {
		t.Errorf(".git in root: got %s, want fail", got.Status)
	}
	if got := one(t, "WEB-APP-009", appFake(map[string]string{"/var/www/.git/HEAD": "ref: refs/heads/main\n"})); got.Status != check.Pass {
		t.Errorf(".git above root: got %s, want pass", got.Status)
	}
	if got := one(t, "WEB-APP-009", &sys.Fake{Files: map[string]string{}}); got.Status != check.Skip {
		t.Errorf("no roots: got %s, want skip", got.Status)
	}
}

func TestFrameworkWritableFolders(t *testing.T) {
	for _, tc := range []struct {
		name string
		dirs map[string]fs.FileMode
		want check.Status
	}{
		{"775 group writable", map[string]fs.FileMode{"/srv/app/storage": 0o775, "/srv/app/bootstrap/cache": 0o775}, check.Pass},
		{"777 storage", map[string]fs.FileMode{"/srv/app/storage": 0o777}, check.Fail},
		{"777 symfony cache", map[string]fs.FileMode{"/srv/app/var/cache": 0o777}, check.Fail},
		{"no folders present", map[string]fs.FileMode{}, check.Pass},
	} {
		f := appFake(map[string]string{"/srv/app/.env": "APP_KEY=base64:abc\n"})
		for p, m := range tc.dirs {
			f.Infos[p] = sys.FileInfo{Path: p, Mode: fs.ModeDir | m, IsDir: true}
		}
		if got := one(t, "WEB-APP-010", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
}
