package web

import (
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// V-03: a protocol directive that still lists TLS 1.0 or 1.1 is not a
// finding when the system crypto library already refuses those versions.
func TestTLSDirectiveRespectsLibraryFloor(t *testing.T) {
	nginxTLS := "http { ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; server { listen 443 ssl; ssl_certificate /etc/ssl/certs/a.pem; } }\n"
	cases := []struct {
		name  string
		id    string
		files map[string]string
		want  check.Status
	}{
		{"nginx weak, no floor", "WEB-NGX-003", map[string]string{"/etc/nginx/nginx.conf": nginxTLS}, check.Fail},
		{"nginx weak, debian floor", "WEB-NGX-003", map[string]string{"/etc/nginx/nginx.conf": nginxTLS, "/etc/ssl/openssl.cnf": "[system_default_sect]\nMinProtocol = TLSv1.2\n"}, check.Pass},
		{"nginx weak, legacy policy", "WEB-NGX-003", map[string]string{"/etc/nginx/nginx.conf": nginxTLS, "/etc/crypto-policies/config": "LEGACY\n"}, check.Fail},
		{"nginx weak, low floor", "WEB-NGX-003", map[string]string{"/etc/nginx/nginx.conf": nginxTLS, "/etc/ssl/openssl.cnf": "MinProtocol = TLSv1\n"}, check.Fail},
		{"nginx unset, rhel floor", "WEB-NGX-003", map[string]string{"/etc/nginx/nginx.conf": "http { server { listen 443 ssl; ssl_certificate /a.pem; } }\n", "/etc/crypto-policies/config": "DEFAULT\n"}, check.Pass},
		{"nginx unset, no floor", "WEB-NGX-003", map[string]string{"/etc/nginx/nginx.conf": "http { server { listen 443 ssl; ssl_certificate /a.pem; } }\n"}, check.Incomplete},
		{"nginx no TLS block", "WEB-NGX-003", map[string]string{"/etc/nginx/nginx.conf": "http { ssl_protocols TLSv1 TLSv1.1; server { listen 80; root /srv; } }\n"}, check.Skip},
		{"apache default, no floor", "WEB-APA-005", map[string]string{"/etc/apache2/apache2.conf": "SSLEngine on\nSSLProtocol all -SSLv3\n"}, check.Fail},
		{"apache default, rhel floor", "WEB-APA-005", map[string]string{"/etc/apache2/apache2.conf": "SSLEngine on\nSSLProtocol all -SSLv3\n", "/etc/crypto-policies/config": "DEFAULT:SHA1\n"}, check.Pass},
		{"apache unset, debian floor", "WEB-APA-005", map[string]string{"/etc/apache2/apache2.conf": "SSLEngine on\n", "/etc/ssl/openssl.cnf": "MinProtocol = TLSv1.2\n"}, check.Pass},
		{"apache strict stays pass", "WEB-APA-005", map[string]string{"/etc/apache2/apache2.conf": "SSLEngine on\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n", "/etc/crypto-policies/config": "LEGACY\n"}, check.Pass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runOne(t, c.id, &sys.Fake{Files: c.files})
			if r.Status != c.want {
				t.Fatalf("want %s, got %s %q %v", c.want, r.Status, r.Message, r.Evidence)
			}
			if c.want == check.Pass && len(c.files) > 1 && !containsFloor(r.Evidence) {
				t.Fatalf("pass without naming the floor: %v", r.Evidence)
			}
		})
	}
}

func containsFloor(ev []string) bool {
	for _, e := range ev {
		if strings.Contains(e, "/etc/ssl/openssl.cnf") || strings.Contains(e, "/etc/crypto-policies/config") {
			return true
		}
	}
	return false
}

// V-08: WEB-APA-010 fails only when a document root actually holds a
// repository or environment file; otherwise the missing rule is a note.
func TestApacheDotFilesNeedAPresentFile(t *testing.T) {
	conf := map[string]string{
		"/etc/apache2/apache2.conf":            "IncludeOptional sites-enabled/*.conf\n",
		"/etc/apache2/sites-enabled/shop.conf": "<VirtualHost *:80>\nDocumentRoot /var/www/shop\n</VirtualHost>\n",
	}
	if r := runOne(t, "WEB-APA-010", &sys.Fake{Files: conf}); r.Status != check.Pass {
		t.Fatalf("empty docroot: want Pass, got %s %v", r.Status, r.Evidence)
	}
	for _, p := range []string{"/var/www/shop/.env", "/var/www/shop/.git/HEAD", "/var/www/shop/.env.production"} {
		f := &sys.Fake{Files: map[string]string{}}
		for k, v := range conf {
			f.Files[k] = v
		}
		f.Files[p] = "x"
		if r := runOne(t, "WEB-APA-010", f); r.Status != check.Fail {
			t.Fatalf("%s present: want Fail, got %s %v", p, r.Status, r.Evidence)
		}
		f.Files["/etc/apache2/apache2.conf"] += "<FilesMatch \"^\\.\">\nRequire all denied\n</FilesMatch>\n"
		if r := runOne(t, "WEB-APA-010", f); r.Status != check.Pass {
			t.Fatalf("%s present but denied: want Pass, got %s %v", p, r.Status, r.Evidence)
		}
	}
}
