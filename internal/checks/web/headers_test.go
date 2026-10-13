package web

import "testing"

func TestHSTSMaxAgeAdversarial(t *testing.T) {
	for _, tc := range []struct {
		h  string
		ok bool
	}{
		{"Max-Age=31536000", true}, {" max-age = 31536000 ; includeSubDomains", true},
		{"max-age=0", true}, {"max-age=invalid", false}, {"max-age=\"31536000\"", false},
		{"includeSubDomains", false}, {"max-age=1; MAX-AGE=2", false}, {"max-age=18446744073709551616", false},
	} {
		if _, ok := hstsMaxAge(tc.h); ok != tc.ok {
			t.Errorf("%q: got ok=%v", tc.h, ok)
		}
	}
}

func TestWeakCSPAdversarial(t *testing.T) {
	bad := []string{"default-src *; object-src 'none'", "script-src data:; object-src 'none'", "script-src http:; object-src 'none'", "script-src 'unsafe-eval'; object-src 'none'", "default-src 'self'"}
	for _, p := range bad {
		if weakCSP(p) == "" {
			t.Errorf("weak policy passed: %s", p)
		}
	}
	if got := weakCSP("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'"); got != "" {
		t.Errorf("safe policy failed: %s", got)
	}
}
