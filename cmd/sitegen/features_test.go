package main

import (
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/channels"
)

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, min string
		want   bool
	}{
		{"v0.1.0-alpha.3", "v0.1.0-alpha.4", false},
		{"v0.1.0-alpha.4", "v0.1.0-alpha.4", true},
		{"v0.1.0-alpha.10", "v0.1.0-alpha.4", true},
		{"v0.1.0-beta.1", "v0.1.0-alpha.4", true},
		{"v0.1.0", "v0.1.0-rc.9", true},
		{"v0.0.9", "v0.1.0-alpha.4", false},
		{"v0.1.0-dev", "v0.1.0-alpha.4", false},
	} {
		if got := versionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("versionAtLeast(%s, %s) = %v", c.v, c.min, got)
		}
	}
}

// The website must not promise openvapt cite, --open or the default
// reports folder to users of a release that lacks them, and the notes must
// disappear by themselves once such a release is the default.
func TestFeatureNotesFollowTheReleaseRecord(t *testing.T) {
	old := siteFeatures
	t.Cleanup(func() { siteFeatures = old })
	for _, c := range []struct {
		version  string
		released bool
	}{{"v0.1.0-alpha.3", false}, {featuresSince, true}, {"v0.1.0", true}} {
		r := channels.Release{Channel: channels.Alpha, Version: c.version}
		f := featuresFor(siteChannels{Default: &r})
		if f.Released != c.released {
			t.Fatalf("%s: Released = %v, want %v", c.version, f.Released, c.released)
		}
		list := append([]FAQ(nil), faqs...)
		applyFeatures(f, list)
		var citeFAQ string
		for _, q := range list {
			if q.Q == "How Do I Cite OpenVAPT?" {
				citeFAQ = q.A
			}
		}
		siteFeatures = f
		llms := llmsCite()
		next := strings.Contains(citeFAQ, "arrive in the next release") && strings.Contains(llms, "arrives in the next release")
		if next == c.released {
			t.Errorf("%s: next-release notes shown = %v, want %v", c.version, next, !c.released)
		}
		if !c.released && (strings.Contains(llms, "`openvapt cite --format") || !strings.Contains(citeFAQ, "CITATION.cff")) {
			t.Errorf("%s: must point to cite.html and CITATION.cff instead of openvapt cite", c.version)
		}
	}
	if f := featuresFor(siteChannels{}); f.Released {
		t.Error("no release at all must not count as released")
	}
}
