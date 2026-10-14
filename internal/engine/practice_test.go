package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
)

// The teacher's key must list exactly the failures in the student's report,
// the same seed must always give the same server, and different seeds must
// give different servers.
func TestPracticeLabAnswerKeyIsExact(t *testing.T) {
	ctx := context.Background()
	fails := func(seed string) []string {
		var ids []string
		for _, f := range Practice(ctx, seed, Options{}).Findings {
			if f.Status == string(check.Fail) {
				ids = append(ids, f.ID)
			}
		}
		return ids
	}
	var key []string
	for _, a := range Answers(ctx, "student-001", Options{}) {
		key = append(key, a.ID)
	}
	if got := fails("student-001"); !reflect.DeepEqual(got, key) {
		t.Fatalf("answer key differs from the report:\nreport %v\nkey    %v", got, key)
	}
	if !reflect.DeepEqual(fails("student-001"), fails("student-001")) {
		t.Error("the same seed must give the same server")
	}
	if reflect.DeepEqual(fails("student-001"), fails("student-002")) {
		t.Error("different seeds should give different servers")
	}
	if n := len(key); n < 20 || n > 200 {
		t.Errorf("practice server has %d weaknesses; expected a teachable middle ground", n)
	}
}
