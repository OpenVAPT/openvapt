package report

import (
	"encoding/json"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
)

func sarifRun(t *testing.T, r *Report) map[string]any {
	t.Helper()
	b, err := r.SARIF()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []map[string]any `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || len(doc.Runs) != 1 {
		t.Fatalf("bad SARIF: %v", err)
	}
	return doc.Runs[0]
}

func TestSARIFEmptyArraysNotNull(t *testing.T) {
	run := sarifRun(t, &Report{Schema: SchemaVersion})
	if _, ok := run["results"].([]any); !ok {
		t.Fatalf("results must be an array, got %T", run["results"])
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"]
	if _, ok := rules.([]any); !ok {
		t.Fatalf("rules must be an array, got %T", rules)
	}
}

func TestSARIFLocationsOnlyForFiles(t *testing.T) {
	r := &Report{Schema: SchemaVersion, Findings: []Finding{{ID: "X", Severity: "high", Status: "fail", Results: []check.Result{
		{Status: check.Fail, Target: "/etc/ssh/sshd config#1", Message: "a"},
		{Status: check.Fail, Target: "127.0.0.1:443", Message: "b"},
		{Status: check.Fail, Target: "https://example.test/", Message: "c"},
		{Status: check.Fail, Target: "relative/path", Message: "d"},
	}}}}
	res := sarifRun(t, r)["results"].([]any)
	if len(res) != 4 {
		t.Fatalf("want 4 results, got %d", len(res))
	}
	first := res[0].(map[string]any)
	uri := first["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]
	if uri != "file:///etc/ssh/sshd%20config%231" {
		t.Fatalf("bad file URI %v", uri)
	}
	for _, x := range res[1:] {
		m := x.(map[string]any)
		if _, has := m["locations"]; has {
			t.Errorf("non-file target got a location: %v", m)
		}
		if m["properties"].(map[string]any)["target"] == "" {
			t.Errorf("target missing from properties: %v", m)
		}
	}
}
