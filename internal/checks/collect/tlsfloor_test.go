package collect

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/sys"
)

func TestSystemTLSFloor(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		files   map[string]string
		known   bool
		forbids bool
	}{
		{"nothing readable", map[string]string{}, false, false},
		{"debian min protocol", map[string]string{"/etc/ssl/openssl.cnf": "openssl_conf = default_conf\n[default_conf]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = system_default_sect\n[system_default_sect]\nMinProtocol = TLSv1.2\nCipherString = DEFAULT:@SECLEVEL=2\n"}, true, true},
		{"commented out", map[string]string{"/etc/ssl/openssl.cnf": "# MinProtocol = TLSv1.2\n"}, false, false},
		{"low floor", map[string]string{"/etc/ssl/openssl.cnf": "MinProtocol = TLSv1\n"}, true, false},
		{"rhel default policy", map[string]string{"/etc/crypto-policies/config": "# comment\nDEFAULT\n"}, true, true},
		{"rhel subpolicy", map[string]string{"/etc/crypto-policies/config": "DEFAULT:SHA1\n"}, true, true},
		{"rhel legacy", map[string]string{"/etc/crypto-policies/config": "LEGACY\n"}, true, false},
		{"include file", map[string]string{
			"/etc/pki/tls/openssl.cnf":                         ".include /etc/crypto-policies/back-ends/opensslcnf.config\n",
			"/etc/crypto-policies/back-ends/opensslcnf.config": "[ crypto_policy ]\nMinProtocol = TLSv1.2\n",
		}, true, true},
		{"include outside prefixes ignored", map[string]string{
			"/etc/ssl/openssl.cnf": ".include /tmp/evil.cnf\n",
			"/tmp/evil.cnf":        "MinProtocol = TLSv1.2\n",
		}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &sys.Fake{Files: c.files, Infos: map[string]sys.FileInfo{}, IncompleteFiles: map[string]bool{}}
			got := SystemTLSFloor(ctx, f)
			if got.Known != c.known || got.Forbids != c.forbids {
				t.Fatalf("want known=%v forbids=%v, got %+v", c.known, c.forbids, got)
			}
			if got.Known && got.Evidence == "" {
				t.Fatalf("known floor without evidence")
			}
		})
	}
}
