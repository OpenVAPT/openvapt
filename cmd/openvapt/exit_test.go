package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/report"
)

func rep(findings ...report.Finding) *report.Report {
	r := &report.Report{Schema: report.SchemaVersion, Findings: findings}
	r.Summarise()
	return r
}

func fnd(sev string, status check.Status) report.Finding {
	return report.Finding{ID: "X-" + sev, Severity: sev, Status: string(status)}
}

// B-02: the documented exit code contract, including --fail-on.
func TestExitCodeMapping(t *testing.T) {
	cases := []struct {
		name   string
		r      *report.Report
		failAt check.Severity
		want   int
	}{
		{"clean", rep(fnd("high", check.Pass)), check.High, 0},
		{"high fails by default", rep(fnd("high", check.Fail)), check.High, 3},
		{"critical fails by default", rep(fnd("critical", check.Fail)), check.High, 3},
		{"medium passes by default", rep(fnd("medium", check.Fail)), check.High, 0},
		{"medium fails with --fail-on medium", rep(fnd("medium", check.Fail)), check.Medium, 3},
		{"info fails with --fail-on info", rep(fnd("info", check.Fail)), check.Info, 3},
		{"high passes with --fail-on critical", rep(fnd("high", check.Fail)), check.Critical, 0},
		{"none never returns 3", rep(fnd("critical", check.Fail)), "", 0},
		{"incomplete beats findings", rep(fnd("critical", check.Fail), fnd("low", check.Incomplete)), check.High, 4},
		{"error beats incomplete", rep(fnd("low", check.Incomplete), fnd("low", check.Error)), check.High, 5},
		{"error even with --fail-on none", rep(fnd("low", check.Error)), "", 5},
		{"skip is not a gap", rep(fnd("low", check.Skip)), check.High, 0},
	}
	for _, c := range cases {
		if got, _ := exitCode(c.r, c.failAt); got != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, got)
		}
	}
	for in, want := range map[string]check.Severity{"": check.High, "HIGH": check.High, "medium": check.Medium, "none": ""} {
		if got, err := parseFailOn(in); err != nil || got != want {
			t.Errorf("parseFailOn(%q) = %q %v", in, got, err)
		}
	}
	var ee *exitError
	if _, err := parseFailOn("severe"); !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("bad --fail-on must be usage error 2, got %v", err)
	}
	f := scanFlags{formats: "json", parallel: 99}
	if err := f.prepare(); !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("--parallel over the cap must be usage error 2, got %v", err)
	}
	f = scanFlags{formats: "json", timeout: -time.Second}
	if err := f.prepare(); !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("negative --timeout must be usage error 2, got %v", err)
	}
}

// B-02: verify accepts the report path on either side of --key-id.
func TestVerifyArgumentOrder(t *testing.T) {
	for _, args := range [][]string{{"report.json", "--key-id", "abc"}, {"--key-id", "abc", "report.json"}, {"--key-id=abc", "report.json"}} {
		p, k, err := verifyArgs(args)
		if err != nil || p != "report.json" || k != "abc" {
			t.Errorf("%v: got %q %q %v", args, p, k, err)
		}
	}
	if p, k, err := verifyArgs([]string{"report.json"}); err != nil || p != "report.json" || k != "" {
		t.Errorf("path only: %q %q %v", p, k, err)
	}
	var ee *exitError
	for _, args := range [][]string{{}, {"--key-id", "abc"}, {"a.json", "b.json"}, {"--bogus", "a.json"}} {
		if _, _, err := verifyArgs(args); !errors.As(err, &ee) || ee.code != 2 {
			t.Errorf("%v: want usage error 2, got %v", args, err)
		}
	}
}

// B-02: only the exact phrase accepts the terms, and the terms are shown.
func TestConfirmTerms(t *testing.T) {
	for in, want := range map[string]bool{"I ACCEPT\n": true, "i accept\n": true, "  I ACCEPT  \n": true, "yes\n": false, "I ACCEPT THE TERMS\n": false, "": false, "\n": false} {
		var out bytes.Buffer
		if got := confirmTerms(strings.NewReader(in), &out); got != want {
			t.Errorf("confirmTerms(%q) = %v", in, got)
		}
		if !strings.Contains(out.String(), "Terms of Use") || !strings.Contains(out.String(), "I ACCEPT") {
			t.Errorf("terms text not shown for %q", in)
		}
	}
}

// A2-02: a selection that names unknown checks or selects nothing is a usage
// error (exit 2), and a report with zero checks never exits 0.
func TestEmptyOrUnknownSelectionIsUsageError(t *testing.T) {
	for _, c := range []struct{ only, skip, want string }{
		{"NOPE-999", "", "NOPE-999"},
		{"HOST-SHH-", "", "HOST-SHH-"},
		{"", "BOGUS-", "BOGUS-"},
		{"HOST-", "HOST-", "zero checks"},
	} {
		f := scanFlags{formats: "json", only: c.only, skip: c.skip}
		err := f.prepare()
		var ee *exitError
		if !errors.As(err, &ee) || ee.code != 2 || !strings.Contains(err.Error(), c.want) {
			t.Errorf("only=%q skip=%q: got %v", c.only, c.skip, err)
		}
	}
	if code, _ := exitCode(&report.Report{}, ""); code == 0 {
		t.Error("a scan that ran zero checks exited 0")
	}
}

func TestSafeCommandLineDropsPathsAndSeeds(t *testing.T) {
	got := safeCommandLine([]string{"/home/alice/bin/openvapt", "demo", "--lab", "practice", "--seed", "S1234567", "--out", "/home/alice/r", "--only=HOST-", "--suppress=/home/alice/s.json", "--no-sign", "--format", "json"})
	want := "openvapt demo --lab practice --seed <value> --out <value> --only=HOST- --suppress=<value> --no-sign --format json"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
