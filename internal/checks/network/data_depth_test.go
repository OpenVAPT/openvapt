package network

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
)

func runDepth(t *testing.T, id string, f *sys.Fake) check.Result {
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

var depthIDs = []string{"NET-DB-014", "NET-DB-015", "NET-DB-016", "NET-DB-017", "NET-DB-018", "NET-DB-019", "NET-DB-020", "NET-DB-021", "NET-DB-022", "NET-DB-023",
	"NET-MAIL-001", "NET-MAIL-002", "NET-MAIL-003", "NET-MAIL-004", "NET-DNS-001", "NET-DNS-002"}

func TestDepthLabPair(t *testing.T) {
	for _, id := range depthIDs {
		if r := runDepth(t, id, lab.Vulnerable()); r.Status != check.Fail {
			t.Errorf("%s vulnerable: want Fail, got %s %q %v", id, r.Status, r.Message, r.Evidence)
		}
		if r := runDepth(t, id, lab.Hardened()); r.Status != check.Pass {
			t.Errorf("%s hardened: want Pass, got %s %q %v", id, r.Status, r.Message, r.Evidence)
		}
	}
}

func TestDepthSkipIncompleteAndMetadata(t *testing.T) {
	empty := &sys.Fake{Files: map[string]string{}}
	installed := &sys.Fake{Files: map[string]string{}, Infos: map[string]sys.FileInfo{
		"/etc/mysql": {IsDir: true}, "/etc/postgresql": {IsDir: true}, "/etc/redis": {IsDir: true}, "/etc/postfix": {IsDir: true}, "/etc/dovecot": {IsDir: true}, "/etc/bind": {IsDir: true}}}
	for _, id := range depthIDs {
		if r := runDepth(t, id, empty); r.Status != check.Skip {
			t.Errorf("%s absent: want Skip, got %s", id, r.Status)
		}
		if r := runDepth(t, id, installed); r.Status != check.Incomplete {
			t.Errorf("%s installed but unreadable: want Incomplete, got %s", id, r.Status)
		}
		c := check.Get(id)
		if len(c.Standards.CWE) == 0 || len(c.Standards.NIST) == 0 || c.Standards.CISTopic == "" || len(c.Refs) == 0 {
			t.Errorf("%s is missing standards metadata", id)
		}
		for _, s := range []string{c.Summary, c.Rationale, c.Detection, c.Fix, c.Verify, c.Title} {
			if strings.ContainsAny(s, "–—") || strings.Contains(s, "--") {
				t.Errorf("%s text contains a long dash or double hyphen", id)
			}
		}
	}
	// A truncated but otherwise good file is Incomplete, never Pass.
	tr := lab.Hardened()
	tr.IncompleteFiles = map[string]bool{"/etc/mysql/conf.d/hardening.cnf": true}
	if r := runDepth(t, "NET-DB-015", tr); r.Status != check.Incomplete {
		t.Errorf("truncated option file: want Incomplete, got %s", r.Status)
	}
}

func TestMySQLDepthTable(t *testing.T) {
	my := func(body string) *sys.Fake {
		return &sys.Fake{Files: map[string]string{"/etc/my.cnf": "[mysqld]\n" + body}}
	}
	for _, tc := range []struct {
		id, body string
		want     check.Status
	}{
		{"NET-DB-014", "symbolic-links=0\n", check.Pass}, {"NET-DB-014", "skip-symbolic-links\n", check.Pass}, {"NET-DB-014", "symbolic-links=1\n", check.Fail}, {"NET-DB-014", "", check.Fail},
		{"NET-DB-015", "secure_file_priv=NULL\n", check.Pass}, {"NET-DB-015", "secure-file-priv=/var/lib/mysql-files\n", check.Pass}, {"NET-DB-015", "secure_file_priv=\n", check.Fail}, {"NET-DB-015", "secure_file_priv=\"\"\n", check.Fail}, {"NET-DB-015", "", check.Fail},
		{"NET-DB-016", "require_secure_transport=ON\n", check.Pass}, {"NET-DB-016", "require-secure-transport=1\n", check.Pass}, {"NET-DB-016", "require_secure_transport=OFF\n", check.Fail}, {"NET-DB-016", "skip-networking\n", check.Pass}, {"NET-DB-016", "skip_networking=ON\n", check.Pass}, {"NET-DB-016", "skip-networking=OFF\n", check.Fail},
		{"NET-DB-017", "log_error=/var/log/mysql/error.log\n", check.Pass}, {"NET-DB-017", "log-error=/var/log/mysqld.log\n", check.Pass}, {"NET-DB-017", "", check.Fail},
		{"NET-DB-018", "skip-name-resolve\n", check.Pass}, {"NET-DB-018", "skip_name_resolve=ON\n", check.Pass}, {"NET-DB-018", "skip-name-resolve=OFF\n", check.Fail}, {"NET-DB-018", "", check.Fail},
	} {
		if r := runDepth(t, tc.id, my(tc.body)); r.Status != tc.want {
			t.Errorf("%s with %q: want %s, got %s %v", tc.id, tc.body, tc.want, r.Status, r.Evidence)
		}
	}
	// A setting in [client] must not satisfy a [mysqld] requirement.
	f := &sys.Fake{Files: map[string]string{"/etc/my.cnf": "[client]\nlog_error=/tmp/x\n"}}
	if r := runDepth(t, "NET-DB-017", f); r.Status != check.Fail {
		t.Errorf("[client] log_error must not count, got %s", r.Status)
	}
}

func TestPostgreSQLDepthTable(t *testing.T) {
	pg := func(conf, hba string) *sys.Fake {
		return &sys.Fake{Files: map[string]string{"/var/lib/pgsql/data/postgresql.conf": conf, "/var/lib/pgsql/data/pg_hba.conf": hba}}
	}
	for _, tc := range []struct {
		id, conf, hba string
		want          check.Status
	}{
		{"NET-DB-019", "", "host all all 127.0.0.1/32 scram-sha-256\nlocal all all peer\n", check.Pass},
		{"NET-DB-019", "", "# host all all 0.0.0.0/0 md5\nhostssl all all 10.0.0.0/8 scram-sha-256 clientcert=verify-full\n", check.Pass},
		{"NET-DB-019", "", "host all all 10.0.0.0/8 md5\n", check.Fail},
		{"NET-DB-019", "", "hostssl all all 10.0.0.0/8 password\n", check.Fail},
		{"NET-DB-020", "ssl = on\n", "", check.Pass}, {"NET-DB-020", "ssl = off\n", "", check.Fail}, {"NET-DB-020", "listen_addresses = '*'\n", "", check.Fail}, {"NET-DB-020", "listen_addresses = ''\n", "", check.Pass},
		{"NET-DB-020", "ssl = off\nssl = on\n", "", check.Pass}, // last value wins
		{"NET-DB-021", "log_connections = on\n", "", check.Pass}, {"NET-DB-021", "log_connections = off\n", "", check.Fail}, {"NET-DB-021", "", "", check.Fail}, {"NET-DB-021", "log_connections = 'receipt,authentication'\n", "", check.Pass},
		{"NET-DB-022", "password_encryption = scram-sha-256\n", "", check.Pass}, {"NET-DB-022", "password_encryption = md5\n", "", check.Fail}, {"NET-DB-022", "password_encryption = on\n", "", check.Fail}, {"NET-DB-022", "", "", check.Pass},
	} {
		if r := runDepth(t, tc.id, pg(tc.conf, tc.hba)); r.Status != tc.want {
			t.Errorf("%s conf=%q hba=%q: want %s, got %s %v", tc.id, tc.conf, tc.hba, tc.want, r.Status, r.Evidence)
		}
	}
}

func TestRedisDangerousCommandsTable(t *testing.T) {
	rd := func(body string) *sys.Fake { return &sys.Fake{Files: map[string]string{"/etc/redis.conf": body}} }
	for _, tc := range []struct {
		body string
		want check.Status
	}{
		{"rename-command CONFIG \"\"\nrename-command FLUSHALL \"\"\nrename-command FLUSHDB \"\"\n", check.Pass},
		{"rename-command FLUSHALL \"\"\n", check.Fail}, // partial
		{"user app on >x ~app:* -@all +@read +@write\n", check.Pass},
		{"user app on >x ~* -@dangerous +@all\n", check.Pass},
		{"user app on >x ~* +@all\n", check.Fail},
		{"aclfile /etc/redis/users.acl\n", check.Pass},
		{"bind 127.0.0.1\n", check.Fail},
	} {
		if r := runDepth(t, "NET-DB-023", rd(tc.body)); r.Status != tc.want {
			t.Errorf("%q: want %s, got %s %v", tc.body, tc.want, r.Status, r.Evidence)
		}
	}
}

func TestMailAndDNSTable(t *testing.T) {
	pf := func(body string) *sys.Fake { return &sys.Fake{Files: map[string]string{"/etc/postfix/main.cf": body}} }
	for _, tc := range []struct {
		id, body string
		want     check.Status
	}{
		{"NET-MAIL-001", "smtpd_tls_security_level = may\nsmtpd_tls_cert_file = /etc/ssl/certs/mail.pem\n", check.Pass},
		{"NET-MAIL-001", "smtpd_tls_security_level = encrypt\nsmtpd_tls_chain_files = /k.pem, /c.pem\n", check.Pass},
		{"NET-MAIL-001", "smtpd_tls_security_level = may\n", check.Fail},
		{"NET-MAIL-001", "smtpd_tls_security_level = none\nsmtpd_tls_cert_file = /c.pem\n", check.Fail},
		{"NET-MAIL-001", "mynetworks = 127.0.0.0/8\n", check.Fail},
		{"NET-MAIL-001", "smtpd_use_tls = yes\nsmtpd_tls_cert_file = /c.pem\n", check.Pass},
		{"NET-MAIL-002", "smtpd_tls_security_level = may\nsmtpd_tls_protocols = >=TLSv1.2\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\n", check.Pass},
		{"NET-MAIL-002", "smtpd_tls_security_level = may\nsmtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\nsmtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n", check.Pass},
		{"NET-MAIL-002", "smtpd_tls_security_level = may\nsmtpd_tls_protocols = >=TLSv1.2\n", check.Fail}, // mandatory list unset
		{"NET-MAIL-002", "smtpd_tls_security_level = may\nsmtpd_tls_protocols = >=TLSv1\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\n", check.Fail},
		{"NET-MAIL-002", "smtpd_tls_security_level = none\n", check.Pass}, // handled by NET-MAIL-001
		{"NET-MAIL-003", "disable_vrfy_command = yes\n", check.Pass}, {"NET-MAIL-003", "disable_vrfy_command = no\n", check.Fail}, {"NET-MAIL-003", "", check.Fail},
	} {
		if r := runDepth(t, tc.id, pf(tc.body)); r.Status != tc.want {
			t.Errorf("%s with %q: want %s, got %s %v", tc.id, tc.body, tc.want, r.Status, r.Evidence)
		}
	}
	dc := func(body string) *sys.Fake {
		return &sys.Fake{Files: map[string]string{"/etc/dovecot/dovecot.conf": body}}
	}
	for _, tc := range []struct {
		body string
		want check.Status
	}{
		{"ssl = required\n", check.Pass}, {"ssl = yes\n", check.Fail}, {"ssl = no\n", check.Fail}, {"ssl = yes\nssl = required\n", check.Pass}, {"disable_plaintext_auth = yes\n", check.Fail},
	} {
		if r := runDepth(t, "NET-MAIL-004", dc(tc.body)); r.Status != tc.want {
			t.Errorf("dovecot %q: want %s, got %s", tc.body, tc.want, r.Status)
		}
	}
	bd := func(body string) *sys.Fake { return &sys.Fake{Files: map[string]string{"/etc/named.conf": body}} }
	for _, tc := range []struct {
		id, body string
		want     check.Status
	}{
		{"NET-DNS-001", "options {\n  version \"not disclosed\";\n};\n", check.Pass},
		{"NET-DNS-001", "options { version none; };\n", check.Pass},
		{"NET-DNS-001", "options {\n  recursion no;\n};\n", check.Fail},
		{"NET-DNS-002", "options {\n  dnssec-validation auto;\n};\n", check.Pass},
		{"NET-DNS-002", "options { dnssec-validation yes; };\n", check.Pass},
		{"NET-DNS-002", "options {\n  dnssec-validation no;\n};\n", check.Fail},
		{"NET-DNS-002", "options { recursion no; };\n", check.Pass}, // default auto
	} {
		if r := runDepth(t, tc.id, bd(tc.body)); r.Status != tc.want {
			t.Errorf("%s with %q: want %s, got %s %v", tc.id, tc.body, tc.want, r.Status, r.Evidence)
		}
	}
}

func TestPostfixWeakProtocolsTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		weak bool
	}{
		{">=TLSv1.2", false}, {">=TLSv1.3", false}, {">=TLSv1", true}, {"!SSLv2, !SSLv3", true}, {"!SSLv2, !SSLv3, !TLSv1, !TLSv1.1", false}, {"!TLSv1", true}, {"", true},
	} {
		if got := postfixWeakProtocols(tc.in); got != tc.weak {
			t.Errorf("%q: weak=%v, want %v", tc.in, got, tc.weak)
		}
	}
}
