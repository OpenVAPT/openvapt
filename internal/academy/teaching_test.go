package academy

import (
	"context"
	"strings"
	"testing"
)

var _ = context.Background

// Course plans must reference real modules, cover the whole Academy in the
// semester plan, and the rubric must add up to 100 percent.
func TestTeachingMaterial(t *testing.T) {
	for _, c := range Courses {
		if c.Title == "" || len(c.Sessions) == 0 {
			t.Errorf("course %s is empty", c.ID)
		}
		for _, s := range c.Sessions {
			for _, id := range s.Modules {
				if Get(id) == nil {
					t.Errorf("course %s week %d references unknown module %s", c.ID, s.Week, id)
				}
			}
		}
	}
	covered := map[string]bool{}
	for _, s := range CourseByID("semester-14").Sessions {
		for _, id := range s.Modules {
			covered[id] = true
		}
	}
	for _, m := range Modules {
		if !covered[m.ID] {
			t.Errorf("the semester course does not teach module %s", m.ID)
		}
	}
	total := 0
	for _, r := range Rubric {
		total += r.Weight
	}
	if total != 100 {
		t.Errorf("rubric weights add up to %d", total)
	}
}

func TestWorksheetHidesAnswersFromStudents(t *testing.T) {
	m := Get("P2")
	student, key := Worksheet(m, false), Worksheet(m, true)
	if strings.Contains(student, "[x]") || strings.Contains(student, "Answer:") {
		t.Error("student worksheet reveals answers")
	}
	if strings.Count(key, "[x]") != len(m.Quiz) || !strings.Contains(key, "Teacher Answer Key") {
		t.Error("answer key must mark every correct option")
	}
	for _, s := range []string{student, key} {
		if strings.ContainsAny(s, "—–") {
			t.Error("worksheet contains a long dash")
		}
	}
}
