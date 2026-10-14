package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestConfiguredEcosystemsExistInOSV checks every ecosystem the release
// workflow and the Makefile ask cmd/vulndbgen to download against OSV's own
// list of exports (testdata/osv-ecosystems.txt, fetched from
// https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt). A name
// OSV does not publish makes the release snapshot job fail with HTTP 404.
func TestConfiguredEcosystemsExistInOSV(t *testing.T) {
	raw, err := os.ReadFile("testdata/osv-ecosystems.txt")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			known[l] = true
		}
	}
	re := regexp.MustCompile(`(?m)(?:-ecosystems "|ECOSYSTEMS \?= )([^"\n]+)`)
	for _, f := range []string{"../../.github/workflows/release.yml", "../../Makefile"} {
		b, err := os.ReadFile(f) // #nosec G304 -- fixed repository paths in a test
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no ecosystem list found", f)
		}
		for _, e := range strings.Split(string(m[1]), ",") {
			e = strings.TrimSpace(e)
			// OSV export folders are the ecosystem name before the release
			// suffix ("Debian:12" is in the "Debian" export).
			base := e
			if i := strings.Index(e, ":"); i > 0 {
				base = e[:i]
			}
			if !known[base] {
				t.Errorf("%s: ecosystem %q (export %q) is not published by OSV", f, e, base)
			}
		}
	}
}
