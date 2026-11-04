package check

import (
	"regexp"
	"strings"
	"testing"
)

// TestASVSFillOnlyWeb: the ASVS fill table names only registered-style web
// ids in 4.0.3 chapter.section.item form.
func TestASVSFillOnlyWeb(t *testing.T) {
	for id, ids := range asvsFill {
		if !strings.HasPrefix(id, "WEB-") {
			t.Errorf("%s: ASVS fill is for web checks only", id)
		}
		for _, a := range ids {
			if !asvsID.MatchString(a) {
				t.Errorf("%s: %q is not an ASVS 4.0.3 id", id, a)
			}
		}
	}
}

var asvsID = regexp.MustCompile(`^\d{1,2}\.\d{1,2}\.\d{1,2}$`)
