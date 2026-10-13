package redact

import "testing"

// C-10: configuration keywords that merely contain "auth" keep their values;
// real secret keys are still redacted.
func TestAuthKeywordsAreNotOverRedacted(t *testing.T) {
	keep := []string{
		"authenticationmethods publickey",
		"authorizedkeysfile .ssh/authorized_keys",
		"pam_faillock preauth and authfail, deny=3",
		"kbdinteractiveauthentication no",
		"auth required pam_unix.so",
	}
	for _, s := range keep {
		if got := String(s); got != s {
			t.Errorf("over-redacted %q -> %q", s, got)
		}
	}
	redacted := []string{"auth_token = abc123xyz", "basic-auth: user1secret", "DB_PASSWORD=hunter2", "rootpassword hunter2", "api_key: AB12", "auth.secret = x9"}
	for _, s := range redacted {
		if got := String(s); got == s {
			t.Errorf("not redacted: %q", s)
		}
	}
}
