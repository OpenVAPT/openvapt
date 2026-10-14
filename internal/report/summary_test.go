package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
)

func a210Report() *Report {
	r := &Report{Schema: SchemaVersion, Disclaimer: Disclaimer,
		Scan: Scan{Host: "lab", Checks: 3, Started: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Finished: time.Date(2026, 1, 2, 3, 5, 5, 0, time.UTC)},
		Findings: []Finding{
			{ID: "T-1", Title: "Weak *thing*", Severity: "high", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/N:N", Status: "fail", Rationale: "First reason. Second.",
				Results: []check.Result{
					{Status: check.Fail, Target: "/etc/x_conf", Message: "see http://evil.example/x and [click](http://evil.example) # _em_ <b>",
						Evidence: []string{`<Server port="8005" shutdown="x">`, "a ``tick`` here", "`edge`"}},
					{Status: check.Incomplete, Target: "/etc/y", Message: "unreadable"},
				}},
			{ID: "T-2", Title: "Header", Severity: "medium", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", Status: "fail", Summary: "A heuristic check.",
				Results: []check.Result{{Status: check.Fail, Target: "jquery", Message: "old", Evidence: []string{"matcher: heuristic (version read from a file header)"}}}},
			{ID: "T-3", Title: "Exact", Severity: "critical", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Status: "fail",
				Results: []check.Result{{Status: check.Fail, Target: "openssl", Message: "old", Evidence: []string{"matcher: exact version"}}}},
		}}
	r.Findings[0].CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
	r.Summarise()
	return r
}

func TestConfidenceAndIncompleteTargets(t *testing.T) {
	r := a210Report()
	want := map[string]string{"T-1": ConfidenceLow, "T-2": ConfidenceMedium, "T-3": ConfidenceHigh}
	for _, f := range r.Findings {
		if f.Confidence != want[f.ID] {
			t.Errorf("%s confidence %q, want %q", f.ID, f.Confidence, want[f.ID])
		}
	}
	if r.Summary.IncompleteTargets != 1 {
		t.Errorf("incomplete targets %d, want 1 (the SARIF Incomplete result)", r.Summary.IncompleteTargets)
	}
	b, _ := r.SARIF()
	if n := strings.Count(string(b), `"Incomplete: `); n != r.Summary.IncompleteTargets {
		t.Errorf("SARIF has %d Incomplete results, summary says %d", n, r.Summary.IncompleteTargets)
	}
}

func TestMarkdownHostileEvidence(t *testing.T) {
	md := a210Report().Markdown()
	for _, bad := range []string{"&lt;", "&gt;", "[click](", "http://evil", " _em_", "<b>", "*thing*"} {
		if strings.Contains(md, bad) {
			t.Errorf("markdown contains %q", bad)
		}
	}
	for _, good := range []string{"`<Server port=\"8005\" shutdown=\"x\">`", "```a ``tick`` here```", "`` `edge` ``", "Confidence: low", "False Positive form", "\\*thing\\*"} {
		if !strings.Contains(md, good) {
			t.Errorf("markdown lacks %q", good)
		}
	}
}

func TestExecutiveSummaryFromData(t *testing.T) {
	r := a210Report()
	ex := r.Executive()
	text := strings.Join(ex.Paragraphs, " ")
	for _, s := range []string{"lab", "3 checks", "without root", "3 checks failed (1 Critical, 1 High, 1 Medium", "1 target", "not a penetration test", "snapshot"} {
		if !strings.Contains(text, s) {
			t.Errorf("summary lacks %q: %s", s, text)
		}
	}
	if len(ex.Top) != 3 || ex.Top[0].ID != "T-3" || ex.Top[1].ID != "T-1" || ex.Top[1].Why != "First reason." {
		t.Errorf("top risks %+v", ex.Top)
	}
	if len(ex.Gaps) != 1 {
		t.Errorf("gaps %v", ex.Gaps)
	}
	h, err := r.HTML()
	if err != nil || !strings.Contains(string(h), "Why It Matters") || !strings.Contains(string(h), "false-positive.yml") {
		t.Errorf("html summary missing: %v", err)
	}
}

func TestSARIFInvocationAndFingerprints(t *testing.T) {
	r := a210Report()
	r.Scan.Command = "openvapt demo --only T-"
	run := sarifRun(t, r)
	inv := run["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != true || inv["startTimeUtc"] != "2026-01-02T03:04:05.000Z" || inv["commandLine"] != "openvapt demo --only T-" {
		t.Errorf("invocation %v", inv)
	}
	res := run["results"].([]any)[0].(map[string]any)
	fp := res["partialFingerprints"].(map[string]any)["openvaptTarget/v1"]
	if fp != Fingerprint("T-3", "openssl") && fp != Fingerprint("T-1", "/etc/x_conf") {
		t.Errorf("fingerprint %v", fp)
	}
	if len(Fingerprint("a", "b")) != 32 || Fingerprint("a", "b") == Fingerprint("ab", "") {
		t.Error("fingerprint not stable or ambiguous")
	}
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"confidence"`) {
		t.Error("confidence property missing")
	}
}
