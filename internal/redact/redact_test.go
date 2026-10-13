package redact

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	cases := []struct{ name, in, secret string }{
		{"env", "DB_PASSWORD=hunter2", "hunter2"},
		{"yaml", "api_key: abcdef123456", "abcdef123456"},
		{"url", "mysql://root:s3cret@127.0.0.1/db", "s3cret"},
		{"url at in password", "redis://user:p@ss@w0rd@127.0.0.1:6379/0", "w0rd"},
		{"url user", "redis://user:p@ss@w0rd@127.0.0.1:6379/0", "p@ss"},
		{"aws", "token AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"},
		{"shadow sha512", "root:$6$salt$hashhashhash:19000:0:::", "hashhashhash"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "abc"},
		{"pem no end", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0", "MIIEvQIBADANBgkqhkiG9w0"},
		{"php define", "define( 'DB_PASSWORD', 'hunter2' );", "hunter2"},
		{"php define double", `define("AUTH_KEY", "x9y8z7w6");`, "x9y8z7w6"},
		{"php define escaped", `define('DB_PASSWORD', 'a\'bcdefg');`, "bcdefg"},
		{"json", `{"password": "hunter2", "user": "bob"}`, "hunter2"},
		{"json escaped", `{"password":"hu\"nter2"}`, "nter2"},
		{"xml", "<password>hunter2</password>", "hunter2"},
		{"xml attr", `<db_password type="x">hunter2</db_password>`, "hunter2"},
		{"bearer header", "Authorization: Bearer abc.def.ghi123", "abc.def.ghi123"},
		{"basic header", "authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		{"bare bearer", "curl -H 'X: Bearer tok_1234567890'", "tok_1234567890"},
		{"argon2", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaGhhc2g", "aGFzaGhhc2g"},
		{"yescrypt", "alice:$y$j9T$saltsalt$hashhashhash:19000:0:99999:7:::", "hashhashhash"},
		{"bcrypt", "$2b$12$abcdefghijklmnopqrstuvwxyz012345678901234567890123", "abcdefghijklmnop"},
		{"ssha", "userPassword: {SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "W6ph5Mm5Pz8GgiULbPgzG37mj9g="},
		{"ldap sha lower", "{sha512}abcdEFGH1234", "abcdEFGH1234"},
		{"des crypt", "bob:abJnggxhB/yWI:19000:0:99999:7:::", "abJnggxhB/yWI"},
		{"slack bot", "SLACK=xoxb-123456789012-abcdefghij", "xoxb-123456789012-abcdefghij"},
		{"slack user", "xoxp-1234567890-abcdefghijkl", "xoxp-1234567890-abcdefghijkl"},
		{"google", "key AIzaSyA1234567890abcdefghijklmnopqrstuv", "AIzaSyA1234567890abcdefghijklmnopqrstuv"},
		{"anthropic", "x sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"},
		{"openai", "x sk-proj-abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuvwxyz0123"},
		{"ghp", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"github pat", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "dozjgNryP4J3jVmNHl0w5N"},
		{"redis", "requirepass s3cr3tvalue", "s3cr3tvalue"},
		{"prose is", "password is S3cr3t!", "S3cr3t!"},
		{"prose was the", "the root password was the hunter2 one", "hunter2"},
		{"prose colon is", "DB password: is Tr0ub4dor", "Tr0ub4dor"},
		{"pwd key", "PWD=hunter2xyz", "hunter2xyz"},
		{"db_pwd key", "db_pwd: hunter2xyz", "hunter2xyz"},
		{"passwd key", "passwd = hunter2xyz", "hunter2xyz"},
		{"mysql -p", "mysql -u root -pS3cretPw db", "S3cretPw"},
		{"mysqldump -p", "/usr/bin/mysqldump --single-transaction -uroot -pS3cretPw shop", "S3cretPw"},
		{"mysqladmin -p", "mysqladmin -u root -p'S3cretPw' status", "S3cretPw"},
		{"gitlab", "TOKEN glpat-abcdefghij0123456789", "glpat-abcdefghij0123456789"},
		{"gitlab bare", "clone with glpat-AbCdEfGhIj_KlMnOpQrSt", "glpat-AbCdEfGhIj_KlMnOpQrSt"},
		{"openssh", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----", "AAAABG5vbmU"},
		{"openssh no end", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU", "AAAABG5vbmU"},
		{"openssh body only", "line 2: b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "AAAABG5vbmU"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if out := String(c.in); strings.Contains(out, c.secret) || !strings.Contains(out, "REDACTED") {
				t.Errorf("secret %q leaked or not marked: %q", c.secret, out)
			}
		})
	}
}

func TestRedactKeepsOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"PermitRootLogin yes",
		"PasswordAuthentication no",
		"password is required for this account",
		"/etc/ssh/sshd_config",
		"/etc/passwd is world readable",
		"https://example.com/docs/page.html",
		"Listening on 127.0.0.1:443",
		"price is $5 today",
		"user@example.invalid wrote the report",
		"Server: nginx/1.18.0 (Ubuntu)",
		"sk-short",
		"password is required",
		"password is not required.",
		"Password must be changed",
		"auth required pam_unix.so",
		"PermitEmptyPasswords no",
		"password_hash enabled",
		"PasswordAuthentication yes",
		"mysql -u root -p",
		"mysql -u root -p shop",
	} {
		if out := String(s); out != s {
			t.Errorf("harmless line changed: %q -> %q", s, out)
		}
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("a", 299) + "é" + strings.Repeat("b", 10)
	out := String(s)
	if !strings.HasSuffix(out, " [truncated]") || strings.ContainsRune(out, '�') {
		t.Fatalf("bad truncation: %q", out)
	}
	if !strings.HasPrefix(out, strings.Repeat("a", 299)+" ") && !strings.HasPrefix(out, strings.Repeat("a", 299)+"é") {
		t.Fatalf("bad truncation boundary")
	}
}
