package vulndb

import (
	"strings"
	"testing"
	"time"
)

func TestWordPressCompare(t *testing.T) {
	less := [][2]string{{"5.2.1", "5.2.4"}, {"6.4", "6.4.1"}, {"6.5-beta1", "6.5-RC1"}, {"6.5-RC1", "6.5"}, {"6.5-alpha", "6.5-beta1"}, {"4.9.26", "5.0"}, {"6.5-beta1", "6.5-beta2"}}
	for _, c := range less {
		if WordPressCompare(c[0], c[1]) >= 0 || WordPressCompare(c[1], c[0]) <= 0 {
			t.Errorf("expected %s < %s", c[0], c[1])
		}
	}
	if WordPressCompare("6.4", "6.4.0") != 0 || WordPressCompare("v6.4.0", "6.4") != 0 {
		t.Error("6.4 must equal 6.4.0")
	}
	core := Affected{Ecosystem: "WordPress:Core", Package: "wordpress", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "5.2.4"}}}}}
	if !affected(core, "5.2.1") || affected(core, "5.2.4") || affected(core, "6.0") {
		t.Error("WordPress:Core range evaluation wrong")
	}
}

func TestIndexedMatchAndEcosystemCoverage(t *testing.T) {
	js := `{"Header":{"Schema":1,"Generated":"2026-01-01"},"Advisories":[
	 {"ID":"A","Severity":"high","Affected":[{"Ecosystem":"npm","Package":"jquery","Versions":["3.4.1"]}]},
	 {"ID":"B","Severity":"high","Affected":[{"Ecosystem":"npm","Package":"jquery","Ranges":[{"Type":"SEMVER","Events":[{"Introduced":"0"},{"Fixed":"3.5.0"}]}]}]},
	 {"ID":"C","Severity":"high","Affected":[{"Ecosystem":"WordPress:Core","Package":"wordpress","Ranges":[{"Type":"ECOSYSTEM","Events":[{"Introduced":"0"},{"Fixed":"5.2.4"}]}]}]}]}`
	s, err := DecodeJSON(strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if s.index == nil || len(s.index[indexKey("npm", "jquery")]) != 2 {
		t.Fatalf("index not built: %v", s.index)
	}
	ms := s.Match("npm", "jquery", "3.4.1")
	if len(ms) != 2 || ms[0].Matcher != MatcherExact || ms[1].Matcher != MatcherRange {
		t.Fatalf("got %+v", ms)
	}
	if len(s.Match("npm", "lodash", "1.0.0")) != 0 || len(s.Match("npm", "jquery", "3.7.1")) != 0 {
		t.Error("unexpected match")
	}
	if !s.HasEcosystem("WordPress") || s.HasEcosystem("Packagist") {
		t.Error("HasEcosystem wrong")
	}
	if s.AgeDays(mustDate("2026-04-01")) != 90 || (Snapshot{}).AgeDays(mustDate("2026-04-01")) != -1 {
		t.Error("AgeDays wrong")
	}
	// Embedded is decoded once and shared.
	a, e1 := Embedded()
	b, e2 := Embedded()
	if e1 != nil || e2 != nil || len(a.Advisories) != len(b.Advisories) || !a.Header.Fixture {
		t.Errorf("embedded fixture: %v %v", e1, e2)
	}
}

func mustDate(s string) time.Time {
	d, _ := time.Parse("2006-01-02", s)
	return d
}
