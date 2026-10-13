package redact

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"DB_PASSWORD=hunter2":                                                 "hunter2",
		"api_key: abcdef123456":                                               "abcdef123456",
		"mysql://root:s3cret@127.0.0.1/db":                                    "s3cret",
		"token AKIAABCDEFGHIJKLMNOP":                                          "AKIAABCDEFGHIJKLMNOP",
		"root:$6$salt$hashhashhash:19000:0:::":                                "hashhashhash",
		"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----": "abc",
	}
	for in, secret := range cases {
		if out := String(in); strings.Contains(out, secret) {
			t.Errorf("secret %q leaked: %q", secret, out)
		}
	}
	if out := String("PermitRootLogin yes"); out != "PermitRootLogin yes" {
		t.Errorf("harmless line changed: %q", out)
	}
}
