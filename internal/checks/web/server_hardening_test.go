package web

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
)

func runOne(t *testing.T, id string, f *sys.Fake) check.Result {
	t.Helper()
	c := check.Get(id)
	if c == nil {
		t.Fatalf("%s not registered", id)
	}
	r := c.Run(context.Background(), f)
	if len(r) != 1 {
		t.Fatalf("%s: want one result, got %+v", id, r)
	}
	return r[0]
}

var serverIDs = []string{"WEB-NGX-001", "WEB-NGX-002", "WEB-NGX-003", "WEB-NGX-004", "WEB-NGX-005", "WEB-NGX-006", "WEB-NGX-007",
	"WEB-APA-001", "WEB-APA-002", "WEB-APA-003", "WEB-APA-004", "WEB-APA-005", "WEB-APA-006", "WEB-APA-007", "WEB-APA-008", "WEB-APA-009", "WEB-APA-010"}

func TestServerHardeningLabPair(t *testing.T) {
	for _, id := range serverIDs {
		if r := runOne(t, id, lab.Vulnerable()); r.Status != check.Fail {
			t.Errorf("%s vulnerable: want Fail, got %s %q %v", id, r.Status, r.Message, r.Evidence)
		}
		if r := runOne(t, id, lab.Hardened()); r.Status != check.Pass {
			t.Errorf("%s hardened: want Pass, got %s %q %v", id, r.Status, r.Message, r.Evidence)
		}
	}
}

func TestServerHardeningSkipAndIncomplete(t *testing.T) {
	for _, id := range serverIDs {
		// Nothing installed: Skip.
		if r := runOne(t, id, &sys.Fake{Files: map[string]string{}}); r.Status != check.Skip {
			t.Errorf("%s empty: want Skip, got %s", id, r.Status)
		}
	}
	// Installed (folder exists) but unreadable configuration: Incomplete.
	f := &sys.Fake{Files: map[string]string{}, Infos: map[string]sys.FileInfo{"/etc/nginx": {Path: "/etc/nginx", IsDir: true}, "/etc/apache2": {Path: "/etc/apache2", IsDir: true}}}
	for _, id := range serverIDs {
		if r := runOne(t, id, f); r.Status != check.Incomplete {
			t.Errorf("%s unreadable: want Incomplete, got %s", id, r.Status)
		}
	}
	// Truncated file on a passing configuration: Incomplete, never Pass.
	tr := lab.Hardened()
	tr.IncompleteFiles = map[string]bool{"/etc/nginx/nginx.conf": true, "/etc/apache2/apache2.conf": true}
	for _, id := range serverIDs {
		if r := runOne(t, id, tr); r.Status != check.Incomplete {
			t.Errorf("%s truncated: want Incomplete, got %s %q", id, r.Status, r.Message)
		}
	}
}

func TestNginxIncludesAndDefaults(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/etc/nginx/nginx.conf":      "http {\n  include sites-enabled/*;\n  include /etc/outside/*.conf; # not followed\n}\n",
		"/etc/nginx/sites-enabled/a": "server { listen 443 ssl; ssl_certificate /c.pem; root /srv; }\n",
		"/etc/outside/evil.conf":     "server_tokens off;\nautoindex off;\n",
		"/etc/nginx/sites-enabled/b": "server_tokens off; # comment\n",
	}}
	c := readServerConf(context.Background(), f, nginxKind)
	if len(c.Paths) != 3 {
		t.Fatalf("want 3 files read (nginx.conf and two sites), got %v", c.Paths)
	}
	if !c.has("server_tokens", func(v string) bool { return v == "off" }) {
		t.Error("relative include was not followed")
	}
	for _, p := range c.Paths {
		if strings.HasPrefix(p, "/etc/outside") {
			t.Error("include outside /etc/nginx must not be followed")
		}
	}
	// TLS on, ssl_protocols unset: Incomplete, not Pass.
	if r := runOne(t, "WEB-NGX-003", f); r.Status != check.Incomplete {
		t.Errorf("WEB-NGX-003 without ssl_protocols: want Incomplete, got %s", r.Status)
	}
	// No TLS at all: stapling check passes with a note, hidden-file check fails because files are served.
	g := &sys.Fake{Files: map[string]string{"/etc/nginx/nginx.conf": "http { server { listen 80; root /srv; } }\n"}}
	if r := runOne(t, "WEB-NGX-005", g); r.Status != check.Pass {
		t.Errorf("WEB-NGX-005 without TLS: want Pass, got %s", r.Status)
	}
	if r := runOne(t, "WEB-NGX-007", g); r.Status != check.Fail {
		t.Errorf("WEB-NGX-007 serving files without a dot rule: want Fail, got %s", r.Status)
	}
	// Proxy-only nginx (no root): nothing to deny.
	h := &sys.Fake{Files: map[string]string{"/etc/nginx/nginx.conf": "http { server { listen 80; location / { proxy_pass http://127.0.0.1:3000; } } }\n"}}
	if r := runOne(t, "WEB-NGX-007", h); r.Status != check.Pass {
		t.Errorf("WEB-NGX-007 proxy only: want Pass, got %s", r.Status)
	}
}

func TestWeakTLSProtocolsTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		weak bool
	}{
		{"TLSv1.2 TLSv1.3", false}, {"TLSv1 TLSv1.1 TLSv1.2", true}, {"-all +TLSv1.2 +TLSv1.3", false}, {"all -SSLv3", true},
		{"all -SSLv3 -TLSv1 -TLSv1.1", false}, {"+TLSv1.3", false}, {"SSLv3 TLSv1.2", true}, {"all", true}, {"-all +TLSv1.1", true},
	} {
		if got := len(weakTLSProtocols(tc.in)) > 0; got != tc.weak {
			t.Errorf("%q: weak=%v, want %v", tc.in, got, tc.weak)
		}
	}
}

func TestWeakCiphersTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		weak bool
	}{
		{"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305", false},
		{"HIGH:!aNULL:!MD5", false}, // exclusions are not flagged
		{"ALL:!aNULL", true}, {"DEFAULT", true}, {"ECDHE-RSA-DES-CBC3-SHA", true}, {"RC4-SHA", true},
		{"ECDHE-RSA-AES256-SHA:ADH-AES128-SHA", true}, {"TLS_AES_128_GCM_SHA256", false}, {"EXP-RC2-CBC-MD5", true},
	} {
		if got := len(weakCiphers(tc.in)) > 0; got != tc.weak {
			t.Errorf("%q: weak=%v, want %v", tc.in, got, tc.weak)
		}
	}
}

func TestApacheRulesTable(t *testing.T) {
	base := func(conf string) *sys.Fake {
		return &sys.Fake{Files: map[string]string{"/etc/apache2/apache2.conf": conf}}
	}
	for _, tc := range []struct {
		id, conf string
		want     check.Status
	}{
		{"WEB-APA-001", "ServerTokens Prod\nServerSignature Off\n", check.Pass},
		{"WEB-APA-001", "ServerTokens Prod\n", check.Pass},   // signature defaults to Off
		{"WEB-APA-001", "ServerSignature Off\n", check.Fail}, // tokens default to Full
		{"WEB-APA-001", "ServerTokens Prod\nServerSignature EMail\n", check.Fail},
		{"WEB-APA-002", "TraceEnable Off\n", check.Pass}, {"WEB-APA-002", "TraceEnable Extended\n", check.Fail}, {"WEB-APA-002", "", check.Fail},
		{"WEB-APA-003", "Options -Indexes +FollowSymLinks\n", check.Pass}, {"WEB-APA-003", "Options +Indexes\n", check.Fail}, {"WEB-APA-003", "Options All\n", check.Fail}, {"WEB-APA-003", "# Options Indexes\n", check.Pass},
		{"WEB-APA-004", "AllowOverride None\n", check.Pass}, {"WEB-APA-004", "AllowOverride FileInfo Limit\n", check.Pass}, {"WEB-APA-004", "AllowOverride All\n", check.Fail},
		{"WEB-APA-005", "SSLEngine on\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n", check.Pass}, {"WEB-APA-005", "SSLEngine on\n", check.Fail}, {"WEB-APA-005", "SSLProtocol all -SSLv3\n", check.Fail}, {"WEB-APA-005", "ServerTokens Prod\n", check.Pass},
		{"WEB-APA-006", "SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256\n", check.Pass}, {"WEB-APA-006", "SSLCipherSuite ALL:!aNULL\n", check.Fail},
		{"WEB-APA-007", "SSLEngine on\nSSLUseStapling On\n", check.Pass}, {"WEB-APA-007", "SSLEngine on\n", check.Fail}, {"WEB-APA-007", "", check.Pass},
		{"WEB-APA-008", "LoadModule security2_module mod_security2.so\n", check.Pass}, {"WEB-APA-008", "LoadModule php_module mod_php.so\n", check.Fail},
		{"WEB-APA-009", "FileETag MTime Size\n", check.Pass}, {"WEB-APA-009", "FileETag INode MTime Size\n", check.Fail}, {"WEB-APA-009", "FileETag All\n", check.Fail}, {"WEB-APA-009", "", check.Pass},
		{"WEB-APA-010", "<FilesMatch \"^\\.ht\">\nRequire all denied\n</FilesMatch>\n", check.Fail},
		{"WEB-APA-010", "<FilesMatch \"^\\.\">\nRequire all denied\n</FilesMatch>\n", check.Pass},
		{"WEB-APA-010", "<DirectoryMatch \"/\\.git\">\nRequire all denied\n</DirectoryMatch>\n", check.Pass},
		{"WEB-APA-010", "RedirectMatch 404 /\\.env\n", check.Pass},
	} {
		if r := runOne(t, tc.id, base(tc.conf)); r.Status != tc.want {
			t.Errorf("%s with %q: want %s, got %s %v", tc.id, tc.conf, tc.want, r.Status, r.Evidence)
		}
	}
}

func TestApacheIncludeTreeAndMarkers(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/etc/httpd/conf/httpd.conf": "ServerRoot /etc/httpd\nIncludeOptional conf.d/*.conf\nInclude /etc/elsewhere/x.conf\n",
		"/etc/httpd/conf.d/ssl.conf": "SSLEngine on\nSSLProtocol -all +TLSv1.2\nSSLUseStapling On\n",
		"/etc/elsewhere/x.conf":      "TraceEnable Off\nServerTokens Prod\n",
	}}
	c := readServerConf(context.Background(), f, apacheKind)
	if len(c.Paths) != 2 {
		t.Fatalf("want httpd.conf and conf.d/ssl.conf, got %v", c.Paths)
	}
	if r := runOne(t, "WEB-APA-005", f); r.Status != check.Pass {
		t.Errorf("RHEL layout SSLProtocol: want Pass, got %s %v", r.Status, r.Evidence)
	}
	if r := runOne(t, "WEB-APA-002", f); r.Status != check.Fail {
		t.Error("TraceEnable from an include outside /etc/httpd must not count")
	}
}

func TestServerHardeningMetadata(t *testing.T) {
	for _, id := range serverIDs {
		c := check.Get(id)
		if c == nil {
			t.Fatalf("%s missing", id)
		}
		if len(c.Standards.CWE) == 0 || len(c.Standards.NIST) == 0 || len(c.Standards.OWASP) == 0 || c.Standards.CISTopic == "" || c.Category == "" || c.Effort == "" {
			t.Errorf("%s is missing standards metadata", id)
		}
		for _, s := range []string{c.Summary, c.Rationale, c.Detection, c.Fix, c.Verify, c.Title} {
			if strings.ContainsAny(s, "–—") || strings.Contains(s, "--") {
				t.Errorf("%s text contains a long dash or double hyphen", id)
			}
		}
	}
}
