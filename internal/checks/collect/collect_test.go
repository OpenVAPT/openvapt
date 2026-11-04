package collect

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/sys"
)

func TestParseProcAddr(t *testing.T) {
	ip, port, err := parseProcAddr("0100007F:0CEA")
	if err != nil || ip.String() != "127.0.0.1" || port != 3306 {
		t.Fatalf("got %v %d %v", ip, port, err)
	}
	ip, port, err = parseProcAddr("00000000000000000000000001000000:0016")
	if err != nil || ip.String() != "::1" || port != 22 {
		t.Fatalf("ipv6: got %v %d %v", ip, port, err)
	}
}

func TestVHostNames(t *testing.T) {
	conf := "server {\n  server_name example.com www.example.com _;\n}\n<VirtualHost *:443>\n ServerName shop.test:443\n ServerAlias *.wild.test\n</VirtualHost>\n"
	got := parseVHostNames(conf)
	want := map[string]bool{"example.com": true, "www.example.com": true, "shop.test": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected %q", g)
		}
	}
}

func TestSSHDFallbackParsesFiles(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/etc/ssh/sshd_config.d/10-hard.conf": "PasswordAuthentication no\n",
		"/etc/ssh/sshd_config":                "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin yes\nMatch User x\nPermitRootLogin no\n",
	}}
	cfg, ok := SSHD(context.Background(), f)
	if !ok || cfg["passwordauthentication"] != "no" || cfg["permitrootlogin"] != "yes" {
		t.Fatalf("drop-in should win and Match blocks be ignored: %v", cfg)
	}
}

func TestSSHDFallbackIgnoresDormantDropIn(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{"/etc/ssh/sshd_config.d/10-hard.conf": "PasswordAuthentication no\n", "/etc/ssh/sshd_config": "PasswordAuthentication yes\nPermitRootLogin no\n"}}
	cfg, ok := SSHD(context.Background(), f)
	if !ok || cfg["passwordauthentication"] != "yes" {
		t.Fatalf("dormant drop-in affected config: %v", cfg)
	}
}

func TestSSHDMergesDangerousMatchContext(t *testing.T) {
	base := "permitrootlogin no\npasswordauthentication no\n"
	f := &sys.Fake{Commands: map[string]string{
		"sshd -T -C user=root,host=localhost,addr=127.0.0.1":   "permitrootlogin yes\npasswordauthentication no\n",
		"sshd -T -C user=nobody,host=localhost,addr=127.0.0.1": base,
		"sshd -T -C user=root,host=localhost,addr=192.0.2.1":   base,
		"sshd -T -C user=nobody,host=localhost,addr=192.0.2.1": base,
	}}
	cfg, ok := SSHD(context.Background(), f)
	if !ok || cfg["permitrootlogin"] != "yes" {
		t.Fatalf("dangerous Match context was hidden: %v", cfg)
	}
}

func TestWebTargetsExpandIncludesAndStripComments(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/etc/nginx/nginx.conf":       "include /etc/nginx/custom/*.conf;\n",
		"/etc/nginx/custom/site.conf": "server {\n listen 443 ssl;\n server_name example.test www.example.test; # production\n ssl_certificate x;\n}\n",
	}}
	got := WebTargets(f)
	if len(got) != 2 || got[0].Scheme != "https" || got[0].Name != "example.test" || got[1].Name != "www.example.test" {
		t.Fatalf("got %+v", got)
	}
}
