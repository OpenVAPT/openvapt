package academy

import (
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
)

func TestCourseIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Modules {
		if seen[m.ID] {
			t.Errorf("duplicate module id %s", m.ID)
		}
		seen[m.ID] = true
		if m.Summary == "" || len(m.Objectives) == 0 || len(m.Sections) == 0 || len(m.Quiz) == 0 || len(m.Refs) == 0 || len(m.Lab) == 0 {
			t.Errorf("%s is missing content", m.ID)
		}
		for _, k := range m.KeyTerms {
			if _, ok := Glossary[k]; !ok {
				t.Errorf("%s uses key term %q with no glossary entry", m.ID, k)
			}
		}
		for _, q := range m.Quiz {
			if q.Answer < 0 || q.Answer >= len(q.Options) {
				t.Errorf("%s quiz %q has an invalid answer index", m.ID, q.Q)
			}
		}
	}
	if len(Modules) < 12 {
		t.Errorf("expected at least 12 modules, have %d", len(Modules))
	}
}

// Every related check must exist, so theory always links to real application.
func TestRelatedChecksExist(t *testing.T) {
	for _, m := range Modules {
		for _, r := range m.RelatedChecks {
			found := false
			for _, c := range check.All() {
				if c.ID == r || (strings.HasSuffix(r, "-") && strings.HasPrefix(c.ID, r)) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s references unknown check %q", m.ID, r)
			}
		}
	}
}

// Every check should be taught by at least one module.
func TestEveryCheckIsTaught(t *testing.T) {
	for _, c := range check.All() {
		if len(ForCheck(c.ID)) == 0 {
			t.Errorf("check %s is not covered by any module", c.ID)
		}
	}
}

func TestNoLongDashes(t *testing.T) {
	bad := []string{"—", "–"}
	for _, m := range Modules {
		all := m.Title + m.Summary
		for _, s := range m.Sections {
			all += strings.Join(s.Body, " ")
		}
		for _, b := range bad {
			if strings.Contains(all, b) {
				t.Errorf("%s contains a long dash", m.ID)
			}
		}
	}
}
