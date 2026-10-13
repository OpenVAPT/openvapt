// Package redact removes secrets from evidence before it is written into a
// report. Reports are meant to be shared with colleagues, so they must never
// carry passwords, keys or tokens even when a check quotes a config line.
package redact

import "regexp"

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// key = value / key: value pairs whose key names a secret
	{regexp.MustCompile(`(?i)\b([A-Z0-9_.-]*(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|auth|credential|salt)[A-Z0-9_.-]*)(\s*[:=]\s*|\s+)("[^"]*"|'[^']*'|\S+)`), `$1$4[REDACTED]`},
	// PEM private key blocks
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), `[REDACTED PRIVATE KEY]`},
	// URLs with embedded credentials: scheme://user:pass@host
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s]+):[^@/\s]+@`), `$1:[REDACTED]@`},
	// Well-known token shapes
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), `[REDACTED AWS KEY]`},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), `[REDACTED GITHUB TOKEN]`},
	{regexp.MustCompile(`\bsk_(live|test)_[A-Za-z0-9]{16,}\b`), `[REDACTED STRIPE KEY]`},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), `[REDACTED JWT]`},
	// Password hashes as found in /etc/shadow ($id$salt$hash)
	{regexp.MustCompile(`\$(1|2[abxy]?|5|6|y|gy|7)\$[^\s:]+`), `[REDACTED HASH]`},
}

// String returns s with every known secret pattern replaced.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	if len(s) > 300 {
		s = s[:300] + " [truncated]"
	}
	return s
}

// All redacts every string in a slice.
func All(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = String(s)
	}
	return out
}
