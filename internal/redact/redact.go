// Package redact removes secrets from evidence before it is written into a
// report. Reports are meant to be shared with colleagues, so they are
// designed never to carry passwords, keys or tokens even when a check quotes
// a config line.
package redact

import (
	"regexp"
	"strings"
)

// Quoted values honour backslash escapes, so `"pa\"ss"` is one value.
const (
	dq     = `"(?:[^"\\]|\\.)*"`
	sq     = `'(?:[^'\\]|\\.)*'`
	secret = `pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|salt`
)

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// PEM private key blocks, complete or truncated (no END line).
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), `[REDACTED PRIVATE KEY]`},
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*`), `[REDACTED PRIVATE KEY]`},
	// OpenSSH private key body without its BEGIN line ("openssh-key-v1" in base64).
	{regexp.MustCompile(`b3BlbnNzaC1rZXktdjE[A-Za-z0-9+/=]*`), `[REDACTED PRIVATE KEY]`},
	// mysql, mysqldump and mysqladmin with the password glued to -p (-pSecret).
	{regexp.MustCompile(`(\bmysql(?:dump|admin)?\b[^\n]*?\s-p)(?:'[^']*'|"[^"]*"|[^\s'"]+)`), `$1[REDACTED]`},
	// PHP define('DB_PASSWORD', 'value');
	{regexp.MustCompile(`(?i)(define\s*\(\s*['"][^'"]*(?:` + secret + `|key)[^'"]*['"]\s*,\s*)(` + dq + `|` + sq + `)`), `$1'[REDACTED]'`},
	// XML elements: <password>value</password>
	{regexp.MustCompile(`(?i)(<[A-Za-z0-9_:.-]*(?:` + secret + `)[A-Za-z0-9_:.-]*(?:\s[^>]*)?>)[^<]*`), `$1[REDACTED]`},
	// HTTP Authorization headers and bare bearer tokens.
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*["']?)(?:(?:bearer|basic|digest|token|negotiate)\s+)?[^\s"']+`), `$1[REDACTED]`},
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`), `Bearer [REDACTED]`},
	// URLs with embedded credentials: everything up to the last @ before the host.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s?#]*@`), `$1[REDACTED]@`},
	// Well-known token shapes.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), `[REDACTED AWS KEY]`},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), `[REDACTED GITHUB TOKEN]`},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`), `[REDACTED GITHUB TOKEN]`},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), `[REDACTED GITLAB TOKEN]`},
	{regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), `[REDACTED SLACK TOKEN]`},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), `[REDACTED GOOGLE KEY]`},
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{16,}`), `[REDACTED API KEY]`},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`), `[REDACTED API KEY]`},
	{regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}`), `[REDACTED STRIPE KEY]`},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), `[REDACTED JWT]`},
	// Password hashes: modular crypt ($id$...), LDAP style ({SSHA}...), and
	// traditional 13 character DES crypt in the second field of a shadow line.
	{regexp.MustCompile(`\$(?:1|2[abxy]?|5|6|y|gy|7|sha1|md5|apr1|argon2(?:id|i|d)|scrypt|pbkdf2[A-Za-z0-9_-]*)\$[^\s:'"]+`), `[REDACTED HASH]`},
	{regexp.MustCompile(`(?i)\{(?:SSHA|SHA|SMD5|MD5|CRYPT|SSHA256|SSHA384|SSHA512|SHA256|SHA384|SHA512|PBKDF2[A-Z0-9_-]*|ARGON2)\}[A-Za-z0-9+/=.$_-]+`), `[REDACTED HASH]`},
	{regexp.MustCompile(`(?m)^([a-z_][a-z0-9_.-]*\$?):[./0-9A-Za-z]{13}:`), `$1:[REDACTED HASH]:`},
}

// keyValue matches key = value, key: value, "key": "value" and
// "key value" pairs whose key names a secret.
var keyValue = regexp.MustCompile(`(?i)\b([A-Z0-9_.-]*(?:` + secret + `)[A-Z0-9_.-]*)(["']?)(\s*[:=]\s*|\s+)(` + dq + `|` + sq + `|[^\s,;}]+)`)

// harmless values are kept after a secret-looking key: they are setting
// values such as "PasswordAuthentication no", never credible secrets.
var harmless = map[string]bool{
	"yes": true, "no": true, "true": true, "false": true, "on": true, "off": true, "none": true, "null": true,
	"0": true, "1": true, "enabled": true, "disabled": true, "empty": true,
}

// connectors are prose words that may sit between a secret-looking key and
// its value ("password is S3cr3t!"). They are skipped, never trusted.
var connectors = map[string]bool{
	"is": true, "was": true, "are": true, "be": true, "been": true, "will": true, "must": true, "should": true,
	"can": true, "cannot": true, "may": true, "the": true, "a": true, "an": true, "to": true, "of": true,
	"and": true, "or": true, "not": true, "for": true, "has": true, "have": true, "now": true, "still": true,
}

// descriptors end a prose sentence without a secret ("password is required").
var descriptors = map[string]bool{
	"required": true, "optional": true, "missing": true, "unset": true, "expired": true, "incorrect": true,
	"invalid": true, "wrong": true, "needed": true, "changed": true, "locked": true, "set": true,
}

// proseTail decides what follows a connector word after a secret-looking
// key. It returns -1 when the rest of the line holds no secret (only
// connectors, descriptors or harmless values follow), otherwise the offset in
// s where redaction must start; redaction then runs to the end of the line.
func proseTail(s string, from int) int {
	i := from
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) || s[i] == '\n' || s[i] == '\r' {
			return -1
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' {
			j++
		}
		w := strings.ToLower(strings.TrimRight(s[i:j], ".,;:!?"))
		switch {
		case connectors[w]:
			i = j
		case descriptors[w] || harmless[w] || w == "":
			return -1
		default:
			return i
		}
	}
}

func lineEnd(s string, from int) int {
	if k := strings.IndexAny(s[from:], "\r\n"); k >= 0 {
		return from + k
	}
	return len(s)
}

func redactKeyValue(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range keyValue.FindAllStringSubmatchIndex(s, -1) {
		if m[0] < last {
			continue // inside a span already redacted
		}
		if m[2] > 0 && (s[m[2]-1] == '/' || s[m[2]-1] == '.') {
			continue // a file path such as /etc/passwd, not a key
		}
		val := s[m[8]:m[9]]
		quoted := strings.HasPrefix(val, `"`) || strings.HasPrefix(val, "'")
		if val == `""` || val == "''" || strings.HasPrefix(val, "[REDACTED") {
			continue
		}
		start, end := m[8], m[9]
		if !quoted {
			w := strings.ToLower(val)
			if harmless[w] || descriptors[w] {
				continue
			}
			if connectors[w] {
				at := proseTail(s, m[9])
				if at < 0 {
					continue
				}
				start, end = at, lineEnd(s, at)
			}
		}
		b.WriteString(s[last:start])
		b.WriteString("[REDACTED]")
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

// String returns s with every known secret pattern replaced.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	s = redactKeyValue(s)
	if len(s) > 300 {
		cut := 300
		for cut > 0 && cut < len(s) && s[cut]&0xC0 == 0x80 { // do not split a UTF-8 character
			cut--
		}
		s = s[:cut] + " [truncated]"
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
