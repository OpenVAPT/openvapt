package redact

import (
	"strings"
	"testing"
)

// V-05: the redactor must not mask ordinary report prose or setting values
// that are themselves the finding, while real credentials stay masked.
func TestProseAndSettingValuesSurvive(t *testing.T) {
	keep := []string{
		"No superuser or password directive in 1 GRUB file(s)",
		"password_encryption = md5",
		"authorization = disabled",
		"authorization: enabled",
		"weak tokens rc4-sha, des-cbc3-sha",
		"server_tokens off",
		"Rails key or secrets file is exposed",
		"passwords are stored with md5",
		"md5 or password method in pg_hba.conf",
		"PasswordAuthentication no",
		"password_hash enabled",
		"secrets_file = /etc/app/secrets.yml",
		"token_url = https://example.test/oauth",
		"Every account has a password or is locked",
		"password or keyboard-interactive login enabled without a second factor",
		"PASS_MAX_DAYS 90 forces a password change every 90 days",
		"Password logins are accepted (PasswordAuthentication defaults to yes)",
		"Password quality checks are not enforced",
		"/etc/app/db.conf (mode 0666): credential assignment",
		"/etc/sudoers: deploy ALL=(ALL) NOPASSWD: ALL",
		"NOPASSWD: /usr/bin/systemctl restart nginx",
	}
	for _, s := range keep {
		if out := String(s); out != s {
			t.Errorf("over-redacted %q -> %q", s, out)
		}
	}
	mask := []struct{ in, secret string }{
		{"DB_PASSWORD=hunter2", "hunter2"},
		{"rootpassword hunter2", "hunter2"},
		{"requirepass s3cr3tvalue", "s3cr3tvalue"},
		{"secret_key_base = 0123456789abcdef", "0123456789abcdef"},
		{"SECRET_KEY = django-insecure-abc", "django-insecure-abc"},
		{"api-key: AB12CD34", "AB12CD34"},
		{"basic-auth: user1secret", "user1secret"},
		{"auth_token = abc123xyz", "abc123xyz"},
		{"Authorization: Bearer abc.def.ghi123", "abc.def.ghi123"},
		{"authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		{"Authorization: dXNlcjpwYXNz123=", "dXNlcjpwYXNz123="},
		{"userPassword: hunter2xyz", "hunter2xyz"},
		{"password is S3cr3t!", "S3cr3t!"},
		{"the root password was the hunter2 one", "hunter2"},
		{"password S3cr3t!", "S3cr3t!"},
		{"secret testing123", "testing123"},
		{"password 'mysecretword'", "mysecretword"},
		{"password: mysecretword", "mysecretword"},
		{"token = mysecretword", "mysecretword"},
	}
	for _, c := range mask {
		if out := String(c.in); strings.Contains(out, c.secret) || !strings.Contains(out, "REDACTED") {
			t.Errorf("secret %q leaked or not marked: %q", c.secret, out)
		}
	}
}
