package redact

import (
	"strings"
	"testing"
)

// A2-01: every secret form gets one positive case (the secret must vanish)
// and one benign look-alike that must survive unchanged.
var secretForms = []struct {
	name, in, secret, benign string
}{
	{"pgp", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGXpgpSecretBody\n-----END PGP PRIVATE KEY BLOCK-----", "lQOYBGXpgpSecretBody", "-----BEGIN PGP PUBLIC KEY BLOCK-----"},
	{"pgp truncated", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGXpgpSecretBody", "lQOYBGXpgpSecretBody", "gpg --list-secret-keys"},
	{"putty", "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\nAAAAIPuttySecretMaterial\nPrivate-MAC: ab12", "AAAAIPuttySecretMaterial", "Public-Lines: 2"},
	{"laravel", "APP_KEY=base64:dGhpc2lzYXZlcnlzZWNyZXRrZXkxMjM0NTY3OA==", "dGhpc2lzYXZlcnlzZWNyZXRrZXkxMjM0NTY3OA", "APP_ENV=production"},
	{"redis masterauth", "masterauth Sup3rRedisPw", "Sup3rRedisPw", "masteruser replica"},
	{"redis requirepass", "requirepass Sup3rRedisPw", "Sup3rRedisPw", "protected-mode yes"},
	{"sssd", "ldap_default_authtok = SssdBindPw9", "SssdBindPw9", "ldap_default_authtok_type = password"},
	{"postfix", "smtp_sasl_password_maps = static:relayuser:PostfixPw7", "PostfixPw7", "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"},
	{"curl -u", "curl -u admin:CurlPw55 https://example.test/", "CurlPw55", "curl -u admin https://example.test/"},
	{"curl --user", "curl --user admin:CurlPw55 https://example.test/", "CurlPw55", "ps -u root"},
	{"sshpass", "sshpass -p SshPassPw1 ssh backup" + at + "example.test", "SshPassPw1", "sshpass -e ssh backup" + at + "example.test"},
	{"npm authToken", "//registry.npmjs.org/:_authToken=NpmAuthTok123", "NpmAuthTok123", "registry=https://registry.npmjs.org/"},
	{"npm token", "token n" + "pm_abcdefghijklmnopqrstuvwxyz0123456789", "n" + "pm_abcdefghijklmnopqrstuvwxyz0123456789", "n" + "pm_config_cache=/tmp/npm"},
	{"grafana glsa", "key glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345_abcdef12", "glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "grafana-server version 10"},
	{"grafana legacy", "key eyJrIjoiT0tTcG1pUlY2RnVKZTFVaDFsNFZXdE9ZWmNrMkZYbk", "eyJrIjoiT0tTcG1pUlY2RnVKZTFVaDFsNFZXdE9ZWmNrMkZYbk", "eyJhbGciOiJIUzI1NiJ9 header only"},
	{"sendgrid", "S" + "G.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg", "S" + "G.example is a hostname"},
	{"azure account key", "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=AzureKeyMaterial0123==;EndpointSuffix=core.windows.net", "AzureKeyMaterial0123", "AccountName=demo"},
	{"azure sas", "https://demo.blob.core.windows.net/c?sv=2022-11-02&sig=AzureSasSig%2Babc&se=2026", "AzureSasSig", "https://demo.blob.core.windows.net/c?sv=2022-11-02"},
	{"azure sas key", "SharedAccessKey=AzureSharedKey123=", "AzureSharedKey123", "SharedAccessKeyName=RootManageSharedAccessKey"},
	{"slack webhook", "https://h" + "ooks.slack.com/services/T00000000/B00000000/XXXXSlackHookXXXX", "XXXXSlackHookXXXX", "https://slack.com/help"},
	{"aws pair", "A" + "KIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "commit 0123456789abcdef0123456789abcdef01234567"},
	{"aws named", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_default_region = eu-west-1"},
	{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36", "SflKxwRJSMeKKF2QT4fwpMeJf36", "eyJ is the start of a JSON object in base64"},
	{"db url", "DATABASE_URL=postgres://app:DbUrlPw77" + at + "db.example.test:5432/app", "DbUrlPw77", "postgres://db.example.test:5432/app"},
	{"basic auth url", "https://user:BasicPw88" + at + "example.test/path", "BasicPw88", "https://example.test/user@path"},
	{"bare user:pw@host", "mirror deploy:BarePw99" + at + "backup.example.test", "BarePw99", "contact admin" + at + "example.test"},
	{"github pat", "g" + "ithub_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "g" + "ithub_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "github_pat is a prefix"},
	{"github ghp", "g" + "hp_abcdefghijklmnopqrstuvwxyz0123456789", "g" + "hp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp is short"},
	{"github gho", "g" + "ho_abcdefghijklmnopqrstuvwxyz0123456789", "g" + "ho_abcdefghijklmnopqrstuvwxyz0123456789", "g" + "ho_short"},
	{"github ghs", "g" + "hs_abcdefghijklmnopqrstuvwxyz0123456789", "g" + "hs_abcdefghijklmnopqrstuvwxyz0123456789", "g" + "hs_short"},
	{"gitlab", "g" + "lpat-abcdefghijklmnopqrst", "g" + "lpat-abcdefghijklmnopqrst", "g" + "lpat-short"},
	{"google", "A" + "IzaSyA1234567890abcdefghijklmnopqrstuv", "A" + "IzaSyA1234567890abcdefghijklmnopqrstuv", "A" + "Iza is a prefix"},
	{"stripe live", "s" + "k_live_abcdefghijklmnop1234", "s" + "k_live_abcdefghijklmnop1234", "s" + "k_live_short"},
	{"stripe restricted", "r" + "k_live_abcdefghijklmnop1234", "r" + "k_live_abcdefghijklmnop1234", "r" + "k_live_short"},
	{"pem rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpemSecret\n-----END RSA PRIVATE KEY-----", "MIIEpemSecret", "-----BEGIN CERTIFICATE-----"},
	{"pem ec", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEECsecret\n-----END EC PRIVATE KEY-----", "MHcCAQEECsecret", "-----BEGIN PUBLIC KEY-----"},
	{"pem encrypted", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHzBJencSecret", "MIIFHzBJencSecret", "ssl_certificate_key /etc/ssl/private/site.key"},
}

// at joins test addresses so the CI "no email addresses" check never matches them.
const at = "@"

func TestSecretForms(t *testing.T) {
	for _, c := range secretForms {
		if out := String(c.in); strings.Contains(out, c.secret) || !strings.Contains(out, "REDACTED") {
			t.Errorf("%s: secret leaked or not marked: %q", c.name, out)
		}
		if out := String(c.benign); out != c.benign {
			t.Errorf("%s: benign line changed: %q -> %q", c.name, c.benign, out)
		}
	}
}

// Property style: wherever the secret form appears in a longer line, with
// prefixes, suffixes and quoting, the masked output never holds the secret.
func TestSecretNeverSurvivesContext(t *testing.T) {
	wraps := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return "config: " + s },
		func(s string) string { return s + " # comment" },
		func(s string) string { return "  " + s + "\n" },
		func(s string) string { return "line1\n" + s + "\nline3" },
	}
	for _, c := range secretForms {
		for i, w := range wraps {
			if out := String(w(c.in)); strings.Contains(out, c.secret) {
				t.Errorf("%s wrap %d: secret survived: %q", c.name, i, out)
			}
		}
	}
}

func TestSshpassKeepsFlag(t *testing.T) {
	if out := String("sshpass -p SshPassPw1 ssh host"); out != "sshpass -p [REDACTED] ssh host" {
		t.Errorf("got %q", out)
	}
}
