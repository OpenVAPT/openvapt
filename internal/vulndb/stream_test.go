package vulndb

import (
	"strings"
	"testing"
)

func TestOtherModuleStream(t *testing.T) {
	r := Range{Events: []Event{{Introduced: "0"}, {Fixed: "1:14.16.0-2.module+el8.3.0"}}}
	for v, want := range map[string]bool{
		"1:12.20.0-1.module+el8.3.0": true,  // another stream
		"14.15.0-1.el8":              true,  // not a module build
		"1:14.15.0-1.module+el8.3.0": false, // same stream
	} {
		if got := otherModuleStream(r, v); got != want {
			t.Errorf("%s: got %v", v, got)
		}
	}
	if otherModuleStream(Range{Events: []Event{{Fixed: "1.2-3.el9"}}}, "1.1-1.el9") {
		t.Error("a plain fix is never a stream mismatch")
	}
}

func TestEmbeddedHeader(t *testing.T) {
	if h, e := EmbeddedHeader(); e != nil || h.Schema != 1 {
		t.Fatalf("%+v %v", h, e)
	}
}

func TestTruncatedSnapshotRefused(t *testing.T) {
	head := `{"Header":{"Schema":1}`
	for _, in := range []string{
		head,
		head + `,"Advisories":[`,
		head + `,"Advisories":[{"ID":"A"}`,
		head + `,"Advisories":[{"ID":"A"},{"ID":"B"}`,
		head + `,"Advisories":[{"ID":"A"}]`,
	} {
		if _, e := DecodeJSON(strings.NewReader(in)); e == nil {
			t.Errorf("%s: want an error", in)
		}
	}
	if s, e := DecodeJSON(strings.NewReader(`{"Advisories":null,"Header":{"Schema":1}}`)); e != nil || len(s.Advisories) != 0 {
		t.Errorf("null advisories: %v", e)
	}
	if s, e := DecodeJSON(strings.NewReader(head + `,"Advisories":[{"ID":"A"}]}`)); e != nil || len(s.Advisories) != 1 {
		t.Errorf("whole file: %v", e)
	}
}
