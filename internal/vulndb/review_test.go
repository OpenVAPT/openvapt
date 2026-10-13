package vulndb

import "testing"

// Independent review cases added by Claude: well-known dpkg and rpm orderings.
func TestReviewVersionOrdering(t *testing.T) {
	deb := [][2]string{{"1.0~rc1", "1.0"}, {"1.0", "1.0-1"}, {"1:0.9", "2:0.1"}, {"2.30-0ubuntu1", "2.30-0ubuntu2"},
		{"1.8.21p2-3ubuntu1.4", "1.8.21p2-3ubuntu1.5"}, {"0.105-20ubuntu0.18.04.5", "0.105-20ubuntu0.18.04.6"},
		{"1.0a", "1.0b"}, {"1.0", "1.0.1"}, {"1.0~~", "1.0~"}, {"7.6p1-4ubuntu0.6", "1:7.6p1-4ubuntu0.1"}}
	for _, c := range deb {
		if DebianCompare(c[0], c[1]) >= 0 || DebianCompare(c[1], c[0]) <= 0 {
			t.Errorf("dpkg: expected %s < %s", c[0], c[1])
		}
	}
	if DebianCompare("1:1.0-1", "1:1.0-1") != 0 {
		t.Error("dpkg: equal versions must compare equal")
	}
	rpm := [][2]string{{"1.0~rc1", "1.0"}, {"1.0", "1.0^git1"}, {"0:1.2-3.el9", "1:1.0-1.el9"}, {"1.2-3.el9", "1.2-10.el9"}, {"9.0p1-1", "9.0p1-2"}}
	for _, c := range rpm {
		if RPMCompare(c[0], c[1]) >= 0 || RPMCompare(c[1], c[0]) <= 0 {
			t.Errorf("rpm: expected %s < %s", c[0], c[1])
		}
	}
}
