package main

import (
	"testing"

	"github.com/openvapt/openvapt/internal/vulndb"
)

func TestOSVersionsKeptWithoutUsableRange(t *testing.T) {
	high := []struct{ Type, Score string }{{"CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	for _, c := range []struct {
		kind string
		want int
	}{{"GIT", 1}, {"ECOSYSTEM", 0}} {
		r := osvRecord{ID: "X", Severity: high}
		r.Affected = make([]struct {
			Package  struct{ Name, Ecosystem string }
			Ranges   []vulndb.Range
			Versions []string
		}, 1)
		r.Affected[0].Package.Name, r.Affected[0].Package.Ecosystem = "sudo", "Debian:12"
		r.Affected[0].Ranges = []vulndb.Range{{Type: c.kind}}
		r.Affected[0].Versions = []string{"1.0"}
		seen := map[string]*vulndb.Advisory{}
		add(r, "Debian:12", nil, nil, seen)
		if got := len(seen["X"].Affected[0].Versions); got != c.want {
			t.Errorf("%s: %d versions kept, want %d", c.kind, got, c.want)
		}
	}
}

func TestStreams(t *testing.T) {
	got := streams(osvRecord{ID: "RLSA-1", Summary: "Important: nodejs:14 and virt-devel:rhel security update"})
	if len(got) != 2 || got[0] != "nodejs:14" || got[1] != "virt-devel:rhel" {
		t.Errorf("%v", got)
	}
	for summary, want := range map[string]int{"Critical: 389-ds:1.4 security update": 1, "Moderate: idm:client and idm:DL1 update": 2, "Important: odd:(x) update": 0} {
		got := streams(osvRecord{ID: "ALSA-2", Summary: summary})
		if len(got) != want {
			t.Errorf("%s: %v", summary, got)
		}
	}
	if s := streams(osvRecord{ID: "ALSA-3", Summary: "Critical: 389-ds:1.4 update"}); len(s) != 1 || s[0] != "389-ds:1.4" {
		t.Errorf("%v", s)
	}
	if streams(osvRecord{ID: "ALSA-1", Summary: "Moderate: curl security update"}) != nil || streams(osvRecord{ID: "GHSA-1", Summary: "Bad: a:b"}) != nil {
		t.Error("no stream expected")
	}
}
