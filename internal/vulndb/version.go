package vulndb

import (
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
