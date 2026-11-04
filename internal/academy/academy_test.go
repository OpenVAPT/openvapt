package academy

import (
	"fmt"
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

// Every prerequisite names a module that exists and comes earlier in the
// course, so a reader following the order never meets a module before its
// prerequisites. A module never lists itself.
func TestPrerequisitesExistAndPrecede(t *testing.T) {
	pos := map[string]int{}
	for i, m := range Modules {
		pos[m.ID] = i
	}
	for i, m := range Modules {
		for _, p := range m.Prereqs {
			j, ok := pos[p]
			if !ok {
				t.Errorf("%s lists unknown prerequisite %q", m.ID, p)
				continue
			}
			if j >= i {
				t.Errorf("%s lists prerequisite %s, which does not come before it", m.ID, p)
			}
		}
	}
}

// Every module closes its theory with an In Summary section, and every quiz
// has at least five questions with at least four options each.
func TestModuleShape(t *testing.T) {
	for _, m := range Modules {
		if n := len(m.Sections); n == 0 || m.Sections[n-1].Heading != "In Summary" {
			t.Errorf("%s does not end its sections with In Summary", m.ID)
		}
	}
	// Quiz depth applies to every module (TAP-12). Section depth applies to
	// the modules written after 2026-10-14.
	for _, m := range Modules {
		if len(m.Quiz) < 5 {
			t.Errorf("%s has %d quiz questions; want at least 5", m.ID, len(m.Quiz))
		}
		for _, q := range m.Quiz {
			if len(q.Options) < 4 {
				t.Errorf("%s quiz %q has %d options; want at least 4", m.ID, q.Q, len(q.Options))
			}
			if strings.TrimSpace(q.Explain) == "" {
				t.Errorf("%s quiz %q has no explanation", m.ID, q.Q)
			}
		}
	}
	for _, id := range []string{"P15", "P16"} {
		m := Get(id)
		if m == nil {
			t.Fatalf("module %s missing", id)
		}
		if n := len(m.Sections) - 1; n < 3 || n > 5 {
			t.Errorf("%s has %d sections before the summary; want 3 to 5", id, n)
		}
	}
}

// Every quiz has distinct options and an answer index that points at one of
// them, so exactly one option is marked correct.
func TestQuizOptionsDistinctAndAnswerInRange(t *testing.T) {
	for _, m := range Modules {
		for _, q := range m.Quiz {
			seen := map[string]bool{}
			for _, o := range q.Options {
				k := strings.ToLower(strings.TrimSpace(o))
				if seen[k] {
					t.Errorf("%s quiz %q repeats option %q", m.ID, q.Q, o)
				}
				seen[k] = true
			}
			if q.Answer < 0 || q.Answer >= len(q.Options) {
				t.Errorf("%s quiz %q answer index %d out of range", m.ID, q.Q, q.Answer)
			}
		}
	}
}

// sentenceAllow lists sentences that may run long because they quote the
// full title of a published standard. Keep it short.
var sentenceAllow = map[string]bool{}

// splitSentences breaks text at a full stop, question mark or exclamation
// mark followed by a space. Dots inside numbers and file names do not split.
func splitSentences(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text)-1; i++ {
		if (text[i] == '.' || text[i] == '?' || text[i] == '!') && text[i+1] == ' ' {
			out = append(out, strings.TrimSpace(text[start:i+1]))
			start = i + 1
		}
	}
	if rest := strings.TrimSpace(text[start:]); rest != "" {
		out = append(out, rest)
	}
	return out
}

// No sentence in a module summary or body runs over 30 words, so the course
// stays readable at around grade 8 to 9.
func TestModuleSentenceLength(t *testing.T) {
	const max = 30
	for _, m := range Modules {
		texts := []string{m.Summary}
		for _, s := range m.Sections {
			texts = append(texts, s.Body...)
		}
		for _, text := range texts {
			for _, s := range splitSentences(text) {
				if n := len(strings.Fields(s)); n > max && !sentenceAllow[s] {
					t.Errorf("%s has a %d-word sentence: %q", m.ID, n, s)
				}
			}
		}
	}
}

// Modules are in teaching order whatever file defined them: every Foundations
// module, then every Practitioner module, then every Applied module, each
// group by number.
func TestModulesInTeachingOrder(t *testing.T) {
	var got []string
	for _, m := range Modules {
		got = append(got, m.ID)
	}
	var want []string
	for i := 1; i <= 3; i++ {
		want = append(want, fmt.Sprintf("F%d", i))
	}
	for i := 1; i <= 25; i++ {
		want = append(want, fmt.Sprintf("P%d", i))
	}
	for i := 1; i <= 8; i++ {
		want = append(want, fmt.Sprintf("A%d", i))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("module order is\n%s\nwant\n%s", strings.Join(got, ","), strings.Join(want, ","))
	}
}

// Every Practitioner and Applied module names at least one module to read
// first; only the Foundations modules may start from nothing.
func TestPractitionerAndAppliedHavePrereqs(t *testing.T) {
	for _, m := range Modules {
		if m.Level != Foundation && len(m.Prereqs) == 0 {
			t.Errorf("%s has no prerequisites", m.ID)
		}
	}
}
