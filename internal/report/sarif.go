package report

import (
	"encoding/json"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
)

// SARIF writes the report in the OASIS SARIF 2.1.0 format, so results can be
// loaded into code-scanning dashboards and CI tools.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
func (r *Report) SARIF() ([]byte, error) {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		FullDescription  msg            `json:"fullDescription"`
		Help             msg            `json:"help"`
		HelpURI          string         `json:"helpUri"`
		Properties       map[string]any `json:"properties"`
	}
	type location struct {
		PhysicalLocation map[string]any `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations"`
	}
	var rules []rule
	var results []result
	for _, f := range r.Findings {
		rules = append(rules, rule{
			ID: f.ID, Name: f.Title,
			ShortDescription: msg{f.Summary}, FullDescription: msg{f.Rationale},
			Help: msg{f.Fix}, HelpURI: "https://openvapt.com/checks/" + f.ID + ".html",
			Properties: map[string]any{"security-severity": sevScore(f.Severity), "category": f.Category, "effort": f.Effort, "tags": append(append([]string{"security"}, f.Standards.CWE...), f.Standards.OWASP...)},
		})
		for _, res := range f.Results {
			if res.Status != check.Fail && res.Status != check.Incomplete && res.Status != check.Error {
				continue
			}
			level := sevLevel(f.Severity)
			if res.Status != check.Fail {
				level = "warning"
			}
			results = append(results, result{
				RuleID: f.ID, Level: level, Message: msg{capitalise(string(res.Status)) + ": " + res.Message},
				Locations: []location{{PhysicalLocation: map[string]any{"artifactLocation": map[string]string{"uri": res.Target}}}},
			})
		}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "OpenVAPT", "version": r.Tool.Version, "informationUri": r.Tool.URL, "rules": rules}},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sevLevel(s string) string {
	switch check.Severity(s) {
	case check.Critical, check.High:
		return "error"
	case check.Medium:
		return "warning"
	default:
		return "note"
	}
}

// sevScore gives the representative numeric score GitHub code scanning uses
// to bucket "security-severity".
func sevScore(s string) string {
	switch check.Severity(s) {
	case check.Critical:
		return "9.5"
	case check.High:
		return "8.0"
	case check.Medium:
		return "5.5"
	case check.Low:
		return "2.5"
	default:
		return "0.0"
	}
}

// capitalise upper-cases the first letter of an ASCII status word such as
// "incomplete" (strings.Title is deprecated).
func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
