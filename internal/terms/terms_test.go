package terms

import (
	"os"
	"strings"
	"testing"
)

// The acknowledgements a user accepts must be identical everywhere they are
// published. This test fails if the EULA or README drift from terms.go.
func TestAcknowledgementsAreInSync(t *testing.T) {
	for _, file := range []string{"../../EULA.md", "../../README.md"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, a := range Acknowledgements {
			if !strings.Contains(string(b), a) {
				t.Errorf("%s is missing acknowledgement %d: %q", file, i+1, a)
			}
		}
	}
}

// The EULA states the acknowledgements version in words; it must be the same
// number terms.Version carries (without the date), or the EULA points users
// to a version string the tool never shows.
func TestEULAStatesTheCurrentAcknowledgementsVersion(t *testing.T) {
	b, err := os.ReadFile("../../EULA.md")
	if err != nil {
		t.Fatal(err)
	}
	num := strings.TrimSpace(strings.SplitN(Version, " ", 2)[0])
	for _, want := range []string{"Acknowledgements version " + num + ".", "These statements are version " + num + " of the acknowledgements"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("EULA.md must contain %q (terms.Version is %q)", want, Version)
		}
	}
}

func TestPositioningWording(t *testing.T) {
	for _, must := range []string{"Academic", "Non-commercial", "Built by AI Cybersecurity Engineers", "source-available", "Free", "own personal or business use", "100% at your own risk"} {
		if !strings.Contains(Tagline, must) {
			t.Errorf("tagline must contain %q", must)
		}
	}
}
