package vulndb

import "testing"

func TestOSVMultiIntervalRanges(t *testing.T) {
	mk := func(eco string, evs ...Event) Affected {
		return Affected{Ecosystem: eco, Ranges: []Range{{Type: "SEMVER", Events: evs}}}
	}
	// Events deliberately out of order: evaluation must sort them.
	two := mk("npm", Event{Introduced: "2.0.0"}, Event{Fixed: "2.3.0"}, Event{Introduced: "0"}, Event{Fixed: "1.5.0"})
	for v, want := range map[string]bool{
		"0.1.0": true, "1.4.9": true, "1.5.0": false, "1.9.9": false, "2.0.0": true, "2.2.9": true, "2.3.0": false, "3.0.0": false,
	} {
		if got := affected(two, v); got != want {
			t.Errorf("two intervals %s: got %v want %v", v, got, want)
		}
	}
	last := mk("npm", Event{Introduced: "1.0.0"}, Event{LastAffected: "1.2.0"})
	for v, want := range map[string]bool{"0.9.0": false, "1.0.0": true, "1.2.0": true, "1.2.1": false} {
		if got := affected(last, v); got != want {
			t.Errorf("last_affected %s: got %v want %v", v, got, want)
		}
	}
	lim := mk("npm", Event{Introduced: "0"}, Event{Limit: "3.0.0"})
	for v, want := range map[string]bool{"2.9.9": true, "3.0.0": false, "4.0.0": false} {
		if got := affected(lim, v); got != want {
			t.Errorf("limit %s: got %v want %v", v, got, want)
		}
	}
	comp := mk("Packagist", Event{Introduced: "0"}, Event{Fixed: "2.0.0-beta10"})
	if !affected(comp, "2.0.0-beta9") || affected(comp, "2.0.0-beta10") || affected(comp, "2.0.0") {
		t.Error("composer prerelease range wrong")
	}
	if affected(comp, "dev-main") {
		t.Error("branch name must not match a version range")
	}
}

func TestArbitraryPartsAndComposer(t *testing.T) {
	cases := []struct {
		cmp  func(string, string) int
		a, b string
		want int
	}{
		{SemverCompare, "1.2", "1.2.0.0", 0},
		{SemverCompare, "1.2.0.1", "1.2.0", 1},
		{SemverCompare, "1.10.0", "1.9.9", 1},
		{ComposerCompare, "2.0.0-beta10", "2.0.0-beta9", 1},
		{ComposerCompare, "2.0.0-dev", "2.0.0-alpha1", -1},
		{ComposerCompare, "2.0.0-alpha2", "2.0.0-beta1", -1},
		{ComposerCompare, "2.0.0-beta3", "2.0.0-RC1", -1},
		{ComposerCompare, "2.0.0-RC2", "2.0.0", -1},
		{ComposerCompare, "2.0.0", "2.0.0-patch1", -1},
		{ComposerCompare, "2.0.0-pl2", "2.0.0-p1", 1},
		{ComposerCompare, "v1.2.3.4", "1.2.3", 1},
		{ComposerCompare, "1.2", "1.2.0", 0},
		{ComposerCompare, "5.4.10", "5.4.9", 1},
		{ComposerCompare, "2.0.0RC1", "2.0.0-rc1", 0},
	}
	for _, c := range cases {
		if got := c.cmp(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s: got %d want %d", c.a, c.b, got, c.want)
		}
		if got := c.cmp(c.b, c.a); got != -c.want {
			t.Errorf("%s vs %s (reversed): got %d want %d", c.b, c.a, got, -c.want)
		}
	}
}
