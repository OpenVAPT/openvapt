package network

import (
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// V-03: Postfix protocol settings that still allow TLS 1.0 or 1.1 are not a
// finding when the system crypto library already refuses those versions.
func TestPostfixProtocolsRespectLibraryFloor(t *testing.T) {
	weak := "smtpd_tls_security_level = may\nsmtpd_tls_cert_file = /c.pem\n"
	for _, tc := range []struct {
		name  string
		extra map[string]string
		want  check.Status
	}{
		{"no floor", nil, check.Fail},
		{"debian floor", map[string]string{"/etc/ssl/openssl.cnf": "MinProtocol = TLSv1.2\n"}, check.Pass},
		{"rhel floor", map[string]string{"/etc/crypto-policies/config": "FUTURE\n"}, check.Pass},
		{"legacy policy", map[string]string{"/etc/crypto-policies/config": "LEGACY\n"}, check.Fail},
	} {
		f := &sys.Fake{Files: map[string]string{"/etc/postfix/main.cf": weak}}
		for k, v := range tc.extra {
			f.Files[k] = v
		}
		r := runDepth(t, "NET-MAIL-002", f)
		if r.Status != tc.want {
			t.Errorf("%s: want %s, got %s %q %v", tc.name, tc.want, r.Status, r.Message, r.Evidence)
		}
	}
}
