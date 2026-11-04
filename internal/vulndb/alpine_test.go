package vulndb

import "testing"

func TestAlpineCompare(t *testing.T) {
	for _, c := range [][2]string{
		{"1.2.3-r0", "1.2.3-r1"}, {"1.2-r9", "1.2.1-r0"}, {"1.2.9-r0", "1.2.10-r0"},
		{"1.2.3_rc1-r0", "1.2.3-r0"}, {"1.2.3-r5", "1.2.3_p1-r0"}, {"1.2_alpha1", "1.2_beta1"},
		{"1.2a-r0", "1.2b-r0"}, {"1.1.1w-r1", "3.0.0-r0"},
	} {
		if AlpineCompare(c[0], c[1]) >= 0 || AlpineCompare(c[1], c[0]) <= 0 {
			t.Errorf("%s must sort before %s", c[0], c[1])
		}
	}
	if AlpineCompare("1.2.3-r1", "1.2.3-r1") != 0 {
		t.Error("equal versions")
	}
}

func TestMatchStream(t *testing.T) {
	r := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "2"}}}}
	s := Snapshot{Advisories: []Advisory{{ID: "A", Streams: []string{"php:7.4"}, Affected: []Affected{{Ecosystem: "Rocky Linux:8", Package: "php", Ranges: r}}}}}
	if len(s.MatchStream("Rocky Linux:8", "php", "1", "php:7.2")) != 0 {
		t.Error("another stream must not match")
	}
	if len(s.MatchStream("Rocky Linux:8", "php", "1", "php:7.4")) != 1 || len(s.MatchStream("Rocky Linux:8", "php", "1", "")) != 1 {
		t.Error("same or unknown stream must match")
	}
}
