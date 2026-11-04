package vulndb

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var apkVersion = regexp.MustCompile(`^(\d+(?:\.\d+)*)([a-z]?)((?:_[a-z]+\d*)*)(?:-r(\d+))?$`)
var apkSuffix = regexp.MustCompile(`_([a-z]+)(\d*)`)

// Suffix order from apk: pre-releases sort before the plain version, patch
// levels after it.
var apkSuffixRank = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

// AlpineCompare orders apk versions such as 1.2.3a_p1-r4. A version outside
// that form falls back to plain text order.
func AlpineCompare(a, b string) int {
	x, y := apkVersion.FindStringSubmatch(a), apkVersion.FindStringSubmatch(b)
	if x == nil || y == nil {
		return strings.Compare(a, b)
	}
	if c := slices.CompareFunc(strings.Split(x[1], "."), strings.Split(y[1], "."), func(p, q string) int {
		return cmp.Compare(apkNumber(p), apkNumber(q))
	}); c != 0 {
		return c
	}
	if c := strings.Compare(x[2], y[2]); c != 0 {
		return c
	}
	sx, sy := apkSuffix.FindAllStringSubmatch(x[3], -1), apkSuffix.FindAllStringSubmatch(y[3], -1)
	for i := 0; i < len(sx) || i < len(sy); i++ {
		rx, nx := apkSuffixAt(sx, i)
		ry, ny := apkSuffixAt(sy, i)
		if c := cmp.Compare(rx, ry); c != 0 {
			return c
		}
		if c := cmp.Compare(nx, ny); c != 0 {
			return c
		}
	}
	return cmp.Compare(apkNumber(x[4]), apkNumber(y[4]))
}

func apkSuffixAt(s [][]string, i int) (rank, number int) {
	if i >= len(s) {
		return 0, 0
	}
	return apkSuffixRank[s[i][1]], apkNumber(s[i][2])
}

func apkNumber(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
