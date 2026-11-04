package lab

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// Fixtures for web root, CORS, security.txt, PHP session and the extended
// exposure checks.

func addDocRoot(f *sys.Fake) {
	for k, v := range f.Files {
		if strings.HasPrefix(k, "/etc/apache2/sites-enabled/") && strings.Contains(v, "ServerName") && !strings.Contains(v, "DocumentRoot") {
			f.Files[k] = strings.Replace(v, "ServerName", "DocumentRoot /var/www/shop\n  ServerName", 1)
		}
	}
}

func phpSessionKey() string {
	var b strings.Builder
	for _, k := range []string{"session.cookie_httponly", "session.use_strict_mode", "session.cookie_samesite"} {
		b.WriteString("echo ini_get('" + k + "'),\"\\n\";")
	}
	return "php -r " + b.String()
}

func init() {
	Register(func(f *sys.Fake) {
		addDocRoot(f)
		for path, mode := range map[string]fs.FileMode{"/var/www/shop/index.php": 0o666, "/var/www/shop/.env": 0o644, "/var/www/shop/backup.sql": 0o644} {
			f.Infos[path] = sys.FileInfo{Path: path, Mode: mode}
		}
		home := f.HTTPResp["https://"+site+"/"]
		home.Body += "<h1>It works!</h1>"
		h := home.Header.Clone()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		home.Header = h
		f.HTTPResp["https://"+site+"/"] = home
		text := func(body string) sys.HTTPResponse {
			return sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: body}
		}
		js := func(body string) sys.HTTPResponse {
			return sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: body}
		}
		f.HTTPResp["https://"+site+"/.svn/entries"] = text("12\n\ndir\n0\n")
		f.HTTPResp["https://"+site+"/wp-content/debug.log"] = text("[13-Oct-2026] PHP Warning: Undefined variable $x in /var/www/shop/wp-content/plugins/a.php")
		f.HTTPResp["https://"+site+"/composer.lock"] = js(`{"packages": [{"name": "laravel/framework", "version": "v8.0.0"}]}`)
		f.HTTPResp["https://"+site+"/phpmyadmin/"] = sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: "<html><title>phpMyAdmin</title></html>"}
		f.HTTPResp["https://"+site+"/_profiler/"] = sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: "<html><title>Symfony Profiler</title></html>"}
		f.HTTPResp["https://"+site+"/wp-json/wp/v2/users"] = js(`[{"id":1,"name":"admin","slug":"admin"}]`)
		f.Commands[phpSessionKey()] = "\n0\n\n"
	}, func(f *sys.Fake) {
		addDocRoot(f)
		f.Infos["/var/www/shop/index.php"] = sys.FileInfo{Path: "/var/www/shop/index.php", Mode: 0o644}
		f.HTTPResp["https://"+site+"/.well-known/security.txt"] = sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}},
			Body: "Contact: https://github.com/OpenVAPT/openvapt/security/advisories/new\nExpires: 2027-10-13T00:00:00Z\n"}
		f.Commands[phpSessionKey()] = "1\n1\nLax\n"
	})
}
