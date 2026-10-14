package main

import (
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/channels"
)

func TestInstallBoxesFollowTheChannelRecord(t *testing.T) {
	none := installBoxes(siteChannels{})
	if _, ok := none["Manual"]; ok {
		t.Fatal("no manual download box may be shown before any release exists")
	}
	if !strings.HasSuffix(cmdDownloadOnly, "| sh") || !strings.HasSuffix(cmdDownloadScan, "| sh -s -- --run") {
		t.Fatal("installer commands changed; keep scripts/install.sh, the FAQ and the walkthrough in sync")
	}
	r := &channels.Release{Channel: channels.Beta, Version: "v9.8.7-beta.6"}
	m := installBoxes(siteChannels{Default: r, DefaultName: "Beta"})
	man := string(m["Manual"].(CiteBox).Text)
	if !strings.Contains(man, "/releases/download/v9.8.7-beta.6/openvapt_linux_amd64") || !strings.Contains(man, "sha256sum -c SHA256SUMS") || !strings.Contains(man, "cosign verify-blob") {
		t.Fatalf("manual box must link the default release and verify it:\n%s", man)
	}
	for _, a := range m["Assets"].([]map[string]string) {
		if !strings.Contains(a["URL"], "/v9.8.7-beta.6/") {
			t.Errorf("asset %s does not follow the channel record", a["URL"])
		}
	}
}

func TestFAQAnswersBothStartPaths(t *testing.T) {
	want := map[string]string{"Can I Download Without Scanning?": cmdDownloadOnly, "How Do I Scan Straight After Downloading?": cmdDownloadScan}
	for _, f := range faqs {
		if c, ok := want[f.Q]; ok {
			if !strings.Contains(f.A, c) {
				t.Errorf("%s does not show %q", f.Q, c)
			}
			if c == cmdDownloadScan && !strings.Contains(f.A, "I ACCEPT") {
				t.Errorf("%s must say the scan still needs I ACCEPT", f.Q)
			}
			delete(want, f.Q)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing FAQ entries: %v", want)
	}
}
