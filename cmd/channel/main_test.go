package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/channels"
)

const citationFixture = "cff-version: 1.2.0\ntitle: OpenVAPT\nversion: \"0.0.0\"\ndate-released: \"2000-01-01\"\n"

func TestUpdateCitationPrecedence(t *testing.T) {
	rel := func(v, d string) channels.Release { return channels.Release{Version: v, Date: d} }
	cases := []struct {
		name    string
		current map[channels.Channel]channels.Release
		version string
		date    string
	}{
		{"stable wins over all", map[channels.Channel]channels.Release{
			channels.Stable: rel("v1.0.0", "2026-04-01"), channels.RC: rel("v1.1.0-rc.1", "2026-04-02"),
			channels.Beta: rel("v1.1.0-beta.1", "2026-04-03"), channels.Alpha: rel("v1.1.0-alpha.1", "2026-04-04")}, "1.0.0", "2026-04-01"},
		{"rc wins over beta and alpha", map[channels.Channel]channels.Release{
			channels.RC: rel("v1.1.0-rc.1", "2026-04-02"), channels.Beta: rel("v1.1.0-beta.1", "2026-04-03"),
			channels.Alpha: rel("v1.1.0-alpha.1", "2026-04-04")}, "1.1.0-rc.1", "2026-04-02"},
		{"beta wins over alpha", map[channels.Channel]channels.Release{
			channels.Beta: rel("v1.1.0-beta.1", "2026-04-03"), channels.Alpha: rel("v1.1.0-alpha.1", "2026-04-04")}, "1.1.0-beta.1", "2026-04-03"},
		{"alpha only", map[channels.Channel]channels.Release{
			channels.Alpha: rel("v1.1.0-alpha.1", "2026-04-04")}, "1.1.0-alpha.1", "2026-04-04"},
		{"no channel leaves the file unchanged", map[channels.Channel]channels.Release{}, "0.0.0", "2000-01-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "CITATION.cff")
			if err := os.WriteFile(p, []byte(citationFixture), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := updateCitation(p, &channels.State{Current: tc.current}); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(p)
			if !strings.Contains(string(b), `version: "`+tc.version+`"`) || !strings.Contains(string(b), `date-released: "`+tc.date+`"`) {
				t.Errorf("got:\n%s", b)
			}
		})
	}
}

func TestUpdateCitationMissingLines(t *testing.T) {
	s := &channels.State{Current: map[channels.Channel]channels.Release{channels.Alpha: {Version: "v0.1.0-alpha.1", Date: "2026-04-04"}}}
	for name, body := range map[string]string{
		"no version": "title: OpenVAPT\ndate-released: \"2000-01-01\"\n",
		"no date":    "title: OpenVAPT\nversion: \"0.0.0\"\n",
	} {
		p := filepath.Join(t.TempDir(), "CITATION.cff")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := updateCitation(p, s); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
