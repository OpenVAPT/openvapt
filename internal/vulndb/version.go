package vulndb

import (
	"regexp"
	"strconv"
	"strings"
)

func sign(i int) int {
	if i < 0 {
		return -1
	}
	if i > 0 {
		return 1
	}
	return 0
}
func splitEpoch(s string) (int, string) {
	if p, q, ok := strings.Cut(s, ":"); ok {
		if n, e := strconv.Atoi(p); e == nil {
			return n, q
		}
	}
	return 0, s
}
func digit(c byte) bool  { return c >= '0' && c <= '9' }
func letter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func debPart(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !digit(a[0])) || (b != "" && !digit(b[0])) {
			var ac, bc byte
			if a != "" && !digit(a[0]) {
				ac = a[0]
				a = a[1:]
			}
			if b != "" && !digit(b[0]) {
				bc = b[0]
				b = b[1:]
			}
			order := func(c byte) int {
				if c == '~' {
					return -1
				}
				if c == 0 {
					return 0
				}
				if letter(c) {
					return int(c)
				}
				return int(c) + 256
			}
			if x := sign(order(ac) - order(bc)); x != 0 {
				return x
			}
		}
		for len(a) > 0 && a[0] == '0' {
			a = a[1:]
		}
		for len(b) > 0 && b[0] == '0' {
			b = b[1:]
		}
		i, j := 0, 0
		for i < len(a) && digit(a[i]) {
			i++
		}
		for j < len(b) && digit(b[j]) {
			j++
		}
		if i != j {
			return sign(i - j)
		}
		if x := strings.Compare(a[:i], b[:j]); x != 0 {
			return sign(x)
		}
		a = a[i:]
		b = b[j:]
	}
	return 0
}
func DebianCompare(a, b string) int {
	ae, a := splitEpoch(a)
	be, b := splitEpoch(b)
	if ae != be {
		return sign(ae - be)
	}
	au, ar := debRevision(a)
	bu, br := debRevision(b)
	if x := debPart(au, bu); x != 0 {
		return x
	}
	return debPart(ar, br)
}
func debRevision(s string) (string, string) {
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return s, "0"
	}
	return s[:i], s[i+1:]
}
func rpmSegment(s string) (seg, rest string, numeric bool) {
	i := 0
	numeric = digit(s[0])
	for i < len(s) && (digit(s[i]) == numeric) && (digit(s[i]) || letter(s[i])) {
		i++
	}
	return s[:i], s[i:], numeric
}
func rpmPart(a, b string) int {
	for {
		for len(a) > 0 && !digit(a[0]) && !letter(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for len(b) > 0 && !digit(b[0]) && !letter(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		if strings.HasPrefix(a, "~") || strings.HasPrefix(b, "~") {
			if !strings.HasPrefix(a, "~") {
				return 1
			}
			if !strings.HasPrefix(b, "~") {
				return -1
			}
			a = a[1:]
			b = b[1:]
			continue
		}
		if strings.HasPrefix(a, "^") || strings.HasPrefix(b, "^") {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if !strings.HasPrefix(a, "^") {
				return 1
			}
			if !strings.HasPrefix(b, "^") {
				return -1
			}
			a = a[1:]
			b = b[1:]
			continue
		}
		if a == "" || b == "" {
			return sign(len(a) - len(b))
		}
		as, ar, an := rpmSegment(a)
		bs, br, bn := rpmSegment(b)
		if an != bn {
			if an {
				return 1
			}
			return -1
		}
		if an {
			as = strings.TrimLeft(as, "0")
			bs = strings.TrimLeft(bs, "0")
			if len(as) != len(bs) {
				return sign(len(as) - len(bs))
			}
		}
		if x := strings.Compare(as, bs); x != 0 {
			return sign(x)
		}
		a, b = ar, br
	}
}
func RPMCompare(a, b string) int {
	ae, a := splitEpoch(a)
	be, b := splitEpoch(b)
	if ae != be {
		return sign(ae - be)
	}
	av, ar := rpmRelease(a)
	bv, br := rpmRelease(b)
	if x := rpmPart(av, bv); x != 0 {
		return x
	}
	return rpmPart(ar, br)
}
func rpmRelease(s string) (string, string) {
	i := strings.IndexByte(s, '-')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// numericParts compares dot-separated numeric version cores of any length;
// a missing part counts as 0, so 1.2 equals 1.2.0 and 1.2.0.1 is newer.
func numericParts(a, b string) int {
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ap) || i < len(bp); i++ {
		var x, y string
		if i < len(ap) {
			x = strings.TrimLeft(ap[i], "0")
		}
		if i < len(bp) {
			y = strings.TrimLeft(bp[i], "0")
		}
		if len(x) != len(y) {
			return sign(len(x) - len(y))
		}
		if c := strings.Compare(x, y); c != 0 {
			return sign(c)
		}
	}
	return 0
}

// SemverCompare orders npm style versions (Semantic Versioning 2.0.0), but
// accepts any number of numeric parts, treating a missing part as 0.
func SemverCompare(a, b string) int {
	parse := func(s string) (string, string) {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		s = strings.SplitN(s, "+", 2)[0]
		base, pre, _ := strings.Cut(s, "-")
		return base, pre
	}
	an, ap := parse(a)
	bn, bp := parse(b)
	if x := numericParts(an, bn); x != 0 {
		return x
	}
	if ap == "" && bp != "" {
		return 1
	}
	if bp == "" && ap != "" {
		return -1
	}
	aa, bb := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(aa) && i < len(bb); i++ {
		ai, ae := strconv.Atoi(aa[i])
		bi, be := strconv.Atoi(bb[i])
		if ae == nil && be == nil && ai != bi {
			return sign(ai - bi)
		}
		if ae == nil && be != nil {
			return -1
		}
		if ae != nil && be == nil {
			return 1
		}
		if x := strings.Compare(aa[i], bb[i]); x != 0 {
			return sign(x)
		}
	}
	return sign(len(aa) - len(bb))
}

// composerStability ranks Composer stability flags: dev < alpha < beta <
// RC < stable < patch (pl, p).
func composerStability(s string) (int, bool) {
	switch strings.ToLower(s) {
	case "dev":
		return 0, true
	case "alpha", "a":
		return 1, true
	case "beta", "b":
		return 2, true
	case "rc":
		return 3, true
	case "", "stable":
		return 4, true
	case "patch", "pl", "p":
		return 5, true
	}
	return 0, false
}

// splitComposer splits "v2.0.0-beta10" into "2.0.0", stability "beta" and
// number "10".
func splitComposer(s string) (core, flag, num string) {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "v"), "V")
	s = strings.SplitN(s, "+", 2)[0]
	i := 0
	for i < len(s) && (digit(s[i]) || s[i] == '.') {
		i++
	}
	core = strings.TrimRight(s[:i], ".")
	rest := strings.TrimLeft(s[i:], "-_.")
	j := 0
	for j < len(rest) && letter(rest[j]) {
		j++
	}
	flag = rest[:j]
	num = strings.TrimLeft(rest[j:], "-_.")
	k := 0
	for k < len(num) && (digit(num[k]) || num[k] == '.') {
		k++
	}
	return core, flag, num[:k]
}

// ComposerCompare orders Packagist versions the way Composer does: any
// number of numeric parts (missing = 0), then stability dev < alpha < beta <
// RC < stable < patch, then the stability number (beta10 > beta9).
func ComposerCompare(a, b string) int {
	ac, af, an := splitComposer(a)
	bc, bf, bn := splitComposer(b)
	if x := numericParts(ac, bc); x != 0 {
		return x
	}
	// An unknown flag ranks with dev, the lowest stability, so it can never
	// hide a vulnerable release; two unknown flags compare as text.
	as, aok := composerStability(af)
	bs, bok := composerStability(bf)
	if !aok && !bok {
		if x := strings.Compare(strings.ToLower(af), strings.ToLower(bf)); x != 0 {
			return sign(x)
		}
	}
	if as != bs {
		return sign(as - bs)
	}
	return numericParts(an, bn)
}

// WordPressCompare orders WordPress core, plugin and theme versions: dot
// separated numbers of any length (6.4 equals 6.4.0), followed by an
// optional pre-release tag (6.5-beta1 < 6.5-RC1 < 6.5), compared the way
// WordPress's own version_compare does for these shapes.
func WordPressCompare(a, b string) int {
	parse := func(s string) (string, string) {
		s = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(s)), "v")
		base, pre, _ := strings.Cut(s, "-")
		return base, pre
	}
	an, ap := parse(a)
	bn, bp := parse(b)
	if x := numericParts(an, bn); x != 0 {
		return x
	}
	if ap == "" && bp != "" {
		return 1
	}
	if bp == "" && ap != "" {
		return -1
	}
	rank := func(p string) (int, string) {
		for i, tag := range []string{"alpha", "beta", "rc"} {
			if strings.HasPrefix(p, tag) {
				return i, strings.TrimLeft(p[len(tag):], "-.")
			}
		}
		return -1, p
	}
	ar, anum := rank(ap)
	br, bnum := rank(bp)
	if ar != br {
		return sign(ar - br)
	}
	return numericParts(anum, bnum)
}

// pep440 is a parsed Python (PEP 440) version: epoch, release numbers, a
// pre-release phase and number, a post-release number and a dev number.
type pep440 struct {
	epoch     int
	release   []int
	phase     int // -1 dev-only, 0 alpha, 1 beta, 2 rc, 3 final
	pre, post int
	dev       int
}

var pep440Re = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)[-_.]?(?:(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?(?:(?:-(\d+))|(?:[-_.]?(?:post|rev|r)[-_.]?(\d*)))?(?:[-_.]?dev[-_.]?(\d*))?(?:\+.*)?$`)

func parsePEP440(s string) (pep440, bool) {
	m := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440{}, false
	}
	n := func(x string) int { v, _ := strconv.Atoi(x); return v }
	v := pep440{epoch: n(m[1]), phase: 3, post: -1, dev: 1 << 30}
	for _, p := range strings.Split(m[2], ".") {
		v.release = append(v.release, n(p))
	}
	switch m[3] {
	case "a", "alpha":
		v.phase = 0
	case "b", "beta":
		v.phase = 1
	case "c", "rc", "pre", "preview":
		v.phase = 2
	}
	v.pre = n(m[4])
	if m[5] != "" {
		v.post = n(m[5])
	} else if strings.Contains(m[0], "post") || strings.Contains(m[0], "rev") || (m[6] != "" && m[3] == "") {
		v.post = n(m[6])
	}
	if strings.Contains(m[0], "dev") {
		v.dev = n(m[7])
		if m[3] == "" && v.post < 0 {
			v.phase = -1
		}
	}
	return v, true
}

// PEP440Compare orders Python package versions (PyPI) by epoch, release,
// pre-release, post-release and development release, as PEP 440 defines.
// A version that does not parse falls back to plain numeric ordering.
func PEP440Compare(a, b string) int {
	x, okx := parsePEP440(a)
	y, oky := parsePEP440(b)
	if !okx || !oky {
		return numericParts(a, b)
	}
	if x.epoch != y.epoch {
		return sign(x.epoch - y.epoch)
	}
	for i := 0; i < len(x.release) || i < len(y.release); i++ {
		var p, q int
		if i < len(x.release) {
			p = x.release[i]
		}
		if i < len(y.release) {
			q = y.release[i]
		}
		if p != q {
			return sign(p - q)
		}
	}
	for _, d := range [][2]int{{x.phase, y.phase}, {x.pre, y.pre}, {x.post, y.post}, {x.dev, y.dev}} {
		if d[0] != d[1] {
			return sign(d[0] - d[1])
		}
	}
	return 0
}

var gemSegment = regexp.MustCompile(`[0-9]+|[a-z]+`)

// GemCompare orders RubyGems versions the way Gem::Version does: segments
// split at dots and at letter-digit changes, numbers compare as numbers, and
// a letter segment marks a pre-release, which sorts before a number.
func GemCompare(a, b string) int {
	x := gemSegment.FindAllString(strings.ToLower(a), -1)
	y := gemSegment.FindAllString(strings.ToLower(b), -1)
	for i := 0; i < len(x) || i < len(y); i++ {
		p, q := "0", "0"
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		pn, pe := strconv.Atoi(p)
		qn, qe := strconv.Atoi(q)
		switch {
		case pe == nil && qe == nil:
			if pn != qn {
				return sign(pn - qn)
			}
		case pe == nil:
			return 1
		case qe == nil:
			return -1
		default:
			if c := strings.Compare(p, q); c != 0 {
				return c
			}
		}
	}
	return 0
}

// PyPIName normalises a Python package name as PEP 503 does (lower case,
// runs of "-", "_" and "." become one "-"), so names from lockfiles and
// advisories compare equal.
func PyPIName(n string) string {
	return pypiSep.ReplaceAllString(strings.ToLower(strings.TrimSpace(n)), "-")
}

var pypiSep = regexp.MustCompile(`[-_.]+`)
