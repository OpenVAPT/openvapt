package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func TestRunOneAbandonsHungCheck(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	c := &check.Check{ID: "T-HANG", Title: "Hang", Severity: check.High, Run: func(context.Context, sys.System) []check.Result {
		<-block // ignores its context, like a blocking read
		return nil
	}}
	start := time.Now()
	f := runOne(context.Background(), &sys.Fake{}, c, 50*time.Millisecond)
	if time.Since(start) > 2*time.Second {
		t.Fatal("hung check stalled runOne")
	}
	if f.Status != string(check.Error) || !strings.Contains(f.Results[0].Message, "timed out") {
		t.Fatalf("want timeout error, got %+v", f)
	}
}

func TestRunOneRecoversPanicAndRedactsTarget(t *testing.T) {
	p := &check.Check{ID: "T-PANIC", Title: "Panic", Run: func(context.Context, sys.System) []check.Result { panic("boom") }}
	if f := runOne(context.Background(), &sys.Fake{}, p, time.Second); f.Status != string(check.Error) {
		t.Fatalf("panic not recovered: %+v", f)
	}
	r := &check.Check{ID: "T-TGT", Title: "Target", Run: func(context.Context, sys.System) []check.Result {
		return []check.Result{{Status: check.Fail, Target: "mysql://root:s3cretpw@127.0.0.1/db", Message: "m"}}
	}}
	f := runOne(context.Background(), &sys.Fake{}, r, time.Second)
	if strings.Contains(f.Results[0].Target, "s3cretpw") {
		t.Fatalf("target not redacted: %q", f.Results[0].Target)
	}
}
