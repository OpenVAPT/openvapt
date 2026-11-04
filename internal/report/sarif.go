package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
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
	type suppression struct {
		Kind          string `json:"kind"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	}
	type result struct {
		RuleID       string         `json:"ruleId"`
		Suppressions []suppression  `json:"suppressions,omitempty"`
		Level        string         `json:"level"`
		Message      msg            `json:"message"`
		Locations    []location     `json:"locations,omitempty"`
		Properties   map[string]any `json:"properties,omitempty"`
		// PartialFingerprints lets dashboards match the same result across runs.
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	}
	// SARIF requires arrays, never null, even when nothing was found.
	rules := []rule{}
	results := []result{}
	for _, f := range r.Findings {
		rules = append(rules, rule{
			ID: f.ID, Name: f.Title,
			ShortDescription: msg{f.Summary}, FullDescription: msg{f.Rationale},
			Help: msg{f.Fix}, HelpURI: "https://openvapt.com/checks/" + f.ID + ".html",
			Properties: map[string]any{"security-severity": sevScore(f.Severity), "category": f.Category, "effort": f.Effort, "confidence": f.Confidence, "tags": append(append([]string{"security"}, f.Standards.CWE...), f.Standards.OWASP...)},
		})
		for _, res := range f.Results {
			if res.Status != check.Fail && res.Status != check.Incomplete && res.Status != check.Error {
				continue
			}
			level := sevLevel(f.Severity)
			if res.Status != check.Fail {
				level = "warning"
			}
			out := result{RuleID: f.ID, Level: level, Message: msg{capitalise(string(res.Status)) + ": " + res.Message},
				PartialFingerprints: map[string]string{"openvaptTarget/v1": Fingerprint(f.ID, res.Target)},
				Properties:          map[string]any{"confidence": f.Confidence}}
			if uri, ok := fileURI(res.Target); ok {
				out.Locations = []location{{PhysicalLocation: map[string]any{"artifactLocation": map[string]string{"uri": uri}}}}
			} else if res.Target != "" {
				// Ports, vhosts and URLs are not files: keep them out of
				// artifactLocation, where dashboards would treat them as paths.
				out.Message.Text += " (target: " + res.Target + ")"
				out.Properties["target"] = res.Target
			}
			if s := f.SuppressionFor(res); s != nil {
				just := s.Reason + " (expires " + s.Expires + ")"
				if s.AddedBy != "" {
					just += " added by " + s.AddedBy
				}
				out.Suppressions = []suppression{{Kind: "external", Status: "accepted", Justification: just}}
			}
			results = append(results, out)
		}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":        map[string]any{"driver": map[string]any{"name": "OpenVAPT", "version": r.Tool.Version, "informationUri": r.Tool.URL, "rules": rules}},
			"results":     results,
			"invocations": []any{r.invocation()},
			"properties":  map[string]any{"citation": r.HowToCite()},
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

// fileURI turns an absolute, clean file path into a percent-encoded file://
// URI. Anything else (relative paths, host:port, vhosts, URLs) is not a
// file location.
func fileURI(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\t\r\n\x00") || path.Clean(p) != p {
		return "", false
	}
	return (&url.URL{Scheme: "file", Path: p}).String(), true
}

// Fingerprint is a stable hash of a check id and a target, so the same
// result can be matched across scans without repeating the target.
func Fingerprint(id, target string) string {
	sum := sha256.Sum256([]byte(id + "\x00" + target))
	return hex.EncodeToString(sum[:16])
}

// invocation describes the run for SARIF: success, times and the command
// line (flag names and non-path values only; see Scan.Command).
func (r *Report) invocation() map[string]any {
	inv := map[string]any{"executionSuccessful": r.Summary.Errors == 0}
	const ts = "2006-01-02T15:04:05.000Z"
	if !r.Scan.Started.IsZero() {
		inv["startTimeUtc"] = r.Scan.Started.UTC().Format(ts)
	}
	if !r.Scan.Finished.IsZero() {
		inv["endTimeUtc"] = r.Scan.Finished.UTC().Format(ts)
	}
	if r.Scan.Command != "" {
		inv["commandLine"] = r.Scan.Command
	}
	return inv
}
