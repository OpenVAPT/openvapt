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
	secret = `pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|salt` // #nosec G101 -- key-name pattern used to find and redact secrets, not a credential
)

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// PEM private key blocks, complete or truncated (no END line).
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), `[REDACTED PRIVATE KEY]`},
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*`), `[REDACTED PRIVATE KEY]`},
	// OpenPGP secret key blocks, complete or truncated.
	{regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?(?:-----END PGP PRIVATE KEY BLOCK-----|$)`), `[REDACTED PRIVATE KEY]`},
	// PuTTY .ppk files: everything from the private part onwards.
	{regexp.MustCompile(`Private-Lines:[\s\S]*`), `[REDACTED PRIVATE KEY]`},
	{regexp.MustCompile(`(PuTTY-User-Key-File-\d+:)[\s\S]*`), `$1 [REDACTED PRIVATE KEY]`},
	// OpenSSH private key body without its BEGIN line ("openssh-key-v1" in base64).
	{regexp.MustCompile(`b3BlbnNzaC1rZXktdjE[A-Za-z0-9+/=]*`), `[REDACTED PRIVATE KEY]`},
	// mysql, mysqldump and mysqladmin with the password glued to -p (-pSecret).
	{regexp.MustCompile(`(\bmysql(?:dump|admin)?\b[^\n]*?\s-p)(?:'[^']*'|"[^"]*"|[^\s'"]+)`), `$1[REDACTED]`},
	// sshpass -p <password>: mask the value, keep the flag.
	{regexp.MustCompile(`(\bsshpass\b[^\n]*?\s-p\s*)(?:'[^']*'|"[^"]*"|[^\s'"]+)`), `$1[REDACTED]`},
	// curl -u user:password and --user user:password.
	{regexp.MustCompile(`((?:^|\s)(?:-u|--user)(?:\s+|=)['"]?[^\s:'"]+:)[^\s'"]+`), `$1[REDACTED]`},
	// Postfix lookup tables with inline credentials: static:user:password.
	{regexp.MustCompile(`(?i)(_maps\s*=\s*static:)\S+`), `$1[REDACTED]`},
	// Laravel style keys: base64:<key material>.
	{regexp.MustCompile(`\bbase64:[A-Za-z0-9+/]{16,}={0,2}`), `base64:[REDACTED]`},
	// Azure storage connection strings and shared access signatures.
	{regexp.MustCompile(`(?i)\b((?:Shared)?Access(?:Key|Signature)\s*=\s*)[^;\s"']+`), `$1[REDACTED]`},
	{regexp.MustCompile(`(?i)\b(AccountKey\s*=\s*)[^;\s"']+`), `$1[REDACTED]`},
	{regexp.MustCompile(`([?&;\s]sig=)[^&;\s"']+`), `$1[REDACTED]`},
	// PHP define('DB_PASSWORD', 'value');
	{regexp.MustCompile(`(?i)(define\s*\(\s*['"][^'"]*(?:` + secret + `|key)[^'"]*['"]\s*,\s*)(` + dq + `|` + sq + `)`), `$1'[REDACTED]'`},
	// XML elements: <password>value</password>
	{regexp.MustCompile(`(?i)(<[A-Za-z0-9_:.-]*(?:` + secret + `)[A-Za-z0-9_:.-]*(?:\s[^>]*)?>)[^<]*`), `$1[REDACTED]`},
	// HTTP Authorization headers and bare bearer tokens. The value must look
	// like a credential: a scheme word followed by a token, a token holding a
	// digit or a base64 / token symbol, or sixteen or more bare letters.
	// "authorization = disabled" (MongoDB) is a setting and stays readable.
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*["']?)(?:(?:bearer|basic|digest|token|negotiate)\s+[^\s"']+|[A-Za-z]{16,}|[A-Za-z]*[0-9+/=._~-][^\s"']*)`), `$1[REDACTED]`},
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`), `Bearer [REDACTED]`},
	// URLs with embedded credentials: everything up to the last @ before the host.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s?#]*@`), `$1[REDACTED]@`},
	// user:password@host without a scheme.
	{regexp.MustCompile(`(^|[\s'"=(])([A-Za-z0-9._-]+):[^\s:@/'"]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|localhost)\b`), `$1$2:[REDACTED]@$3`},
	// Slack incoming webhook URLs: the path is the credential.
	// Anchored at a token boundary (start of text, whitespace, quote, = or
	// a URL scheme), so only the real Slack host matches, never a longer name.
	{regexp.MustCompile(`(^|[\s'"=(<]|https?://)hooks\.slack\.com/(services|workflows|triggers)/[A-Za-z0-9/_-]+`), `${1}hooks.slack.com/$2/[REDACTED]`},
	// Well-known token shapes.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), `[REDACTED AWS KEY]`},
	// A 40 character AWS secret access key next to its access key id.
	{regexp.MustCompile(`(\[REDACTED AWS KEY\][\s,:;=|"']+)[A-Za-z0-9/+=]{40}`), `$1[REDACTED AWS SECRET]`},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), `[REDACTED NPM TOKEN]`},
	{regexp.MustCompile(`\bglsa_[A-Za-z0-9_]{32,}`), `[REDACTED GRAFANA TOKEN]`},
	{regexp.MustCompile(`\bglc_[A-Za-z0-9+/=_-]{32,}`), `[REDACTED GRAFANA TOKEN]`},
	{regexp.MustCompile(`\beyJrIjoi[A-Za-z0-9+/=]{20,}`), `[REDACTED GRAFANA TOKEN]`},
	{regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`), `[REDACTED SENDGRID KEY]`},
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

// secretKey names a key that carries a secret. The secret word must END the
// key: DB_PASSWORD, rootpassword, requirepass, api-key, secret_key_base and
// auth_token are keys whose value is a credential, while password_encryption,
// server_tokens, secrets_file or passwords (plural) name a setting or a noun
// whose value (md5, off, a path, "are stored") is the finding itself and must
// stay readable. The short word "auth" must be its own token separated by
// _ . or - (basic_auth, basic-auth), so sshd and PAM settings such as
// authenticationmethods, authorizedkeysfile or preauth keep their values.
const secretKey = `[A-Z0-9_.-]*(?:pass(?:word|wd|phrase)?|pwd|secret(?:[_-]?key(?:[_-]?base)?)?|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|salt|app[_-]?key|account[_-]?key|authtok|masterauth)|(?:[A-Z0-9]+[_.-])*auth` // #nosec G101 -- key-name pattern used to find and redact secrets, not a credential

// keyValue matches key = value, key: value, "key": "value" and
// "key value" pairs whose key names a secret.
var keyValue = regexp.MustCompile(`(?i)\b(` + secretKey + `)(["']?)(\s*[:=]\s*|\s+)(` + dq + `|` + sq + `|[^\s,;}]+)`)

// harmless values are kept after a secret-looking key: they are setting
// values such as "PasswordAuthentication no", never credible secrets.
var harmless = map[string]bool{
	"yes": true, "no": true, "true": true, "false": true, "on": true, "off": true, "none": true, "null": true,
	"0": true, "1": true, "enabled": true, "disabled": true, "empty": true,
	// hash method names and report nouns that follow "password" in prose
	"md5": true, "scram-sha-256": true, "sha256": true, "sha512": true, "crypt": true, "plaintext": true, "hashed": true, "hashes": true,
	"directive": true, "file": true, "files": true, "method": true, "line": true, "stored": true, "setting": true, "field": true, "policy": true, "prompt": true,
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

// bareNouns are secret key words standing alone as an English noun
// ("password", "credential"). In the whitespace form ("password change",
// "credential assignment", "password or keyboard-interactive") they are
// usually prose, so the value must look like a credential (a digit, a symbol
// or quotes) before it is masked. Prefixed keys (DB_PASSWORD, requirepass)
// and the key = value and key: value forms are always masked.
var bareNouns = map[string]bool{
	"password": true, "passwd": true, "passphrase": true, "pwd": true, "secret": true, "token": true,
	"credential": true, "salt": true, "auth": true,
}

// notKeys are words that end in a secret key word but never carry one: the
// sudoers NOPASSWD tag is followed by the commands it applies to.
var notKeys = map[string]bool{"nopasswd": true, "sshpass": true}

// credentialShaped reports whether a bare value could be a credential: it
// holds a digit or a symbol other than the hyphen used in ordinary words.
func credentialShaped(v string) bool {
	for _, r := range v {
		if r >= '0' && r <= '9' {
			return true
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '.' || r == ',' || r == ';') {
			return true
		}
	}
	return false
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
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
		key := strings.ToLower(s[m[2]:m[3]])
		if notKeys[key] {
			continue
		}
		val := s[m[8]:m[9]]
		quoted := strings.HasPrefix(val, `"`) || strings.HasPrefix(val, "'")
		if val == `""` || val == "''" || strings.HasPrefix(val, "[REDACTED") {
			continue
		}
		prose := bareNouns[key] && !strings.ContainsAny(s[m[6]:m[7]], ":=")
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
				if prose && !credentialShaped(firstWord(s[at:end])) {
					continue
				}
			} else if prose && !credentialShaped(val) {
				continue
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
