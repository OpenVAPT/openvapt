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

func TestPositioningWording(t *testing.T) {
	for _, must := range []string{"Academic", "Non-commercial", "Open-source code", "Free", "own use", "100% at your own risk"} {
		if !strings.Contains(Tagline, must) {
			t.Errorf("tagline must contain %q", must)
		}
	}
}
