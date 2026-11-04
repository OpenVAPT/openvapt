package vulndb

import "testing"

func TestVersionComparisons(t *testing.T) {
	cases := []struct {
		name string
		cmp  func(string, string) int
		a, b string
		want int
	}{
		{"deb tilde", DebianCompare, "1.0~rc1", "1.0", -1},
		{"deb epoch", DebianCompare, "1:1.0", "2.0", 1},
		{"deb revision", DebianCompare, "1.0-2", "1.0-10", -1},
		{"deb punctuation", DebianCompare, "1.0+a", "1.0.a", -1},
		{"deb zeros", DebianCompare, "1.02", "1.2", 0},
		{"rpm tilde", RPMCompare, "1.0~rc1", "1.0", -1},
		{"rpm caret", RPMCompare, "1.0^git1", "1.0", 1},
		{"rpm caret next", RPMCompare, "1.0^git1", "1.0.1", -1},
		{"rpm epoch", RPMCompare, "1:1.0-1", "2.0-1", 1},
		{"rpm release", RPMCompare, "1.0-2", "1.0-10", -1},
		{"rpm numeric", RPMCompare, "1.09", "1.9", 0},
		{"semver prerelease", SemverCompare, "1.0.0-rc.1", "1.0.0", -1},
		{"semver numeric prerelease", SemverCompare, "1.0.0-beta.2", "1.0.0-beta.10", -1},
		{"semver prefix", SemverCompare, "v1.2", "1.2.0", 0},
		{"semver build", SemverCompare, "1.2.3+abc", "1.2.3+def", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cmp(c.a, c.b); got != c.want {
				t.Fatalf("%s vs %s: got %d want %d", c.a, c.b, got, c.want)
			}
		})
	}
}
func TestMatch(t *testing.T) {
	s := Snapshot{Advisories: []Advisory{{ID: "A", Affected: []Affected{{Ecosystem: "npm", Package: "jquery", Ranges: []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "3.5.0"}}}}}}}}}
	if len(s.Match("npm", "jquery", "3.4.1")) != 1 || len(s.Match("npm", "jquery", "3.5.0")) != 0 || len(s.Match("npm", "other", "3.4.1")) != 0 {
		t.Fatal("range matching failed")
	}
}
