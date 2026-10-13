package check

import (
	"fmt"
	"math"
	"strings"
)

// CVSS v3.1 base score calculation, per FIRST, "CVSS v3.1 Specification",
// sections 7.1 to 7.4 and Appendix A (the Roundup function). A check's
// severity is derived from its vector with the qualitative rating scale in
// section 5, so the two can never disagree.

var cvssWeights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"N": 0, "L": 0.22, "H": 0.56},
	"I":  {"N": 0, "L": 0.22, "H": 0.56},
	"A":  {"N": 0, "L": 0.22, "H": 0.56},
}

// BaseScore returns the CVSS v3.0 or v3.1 base score of a vector such as
// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Every base metric must be
// present exactly once with a valid value.
func BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) != 9 || (parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0") {
		return 0, fmt.Errorf("not a CVSS v3 base vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if _, dup := m[k]; !ok || dup {
			return 0, fmt.Errorf("bad metric %q in %q", p, vector)
		}
		m[k] = v
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("bad scope in %q", vector)
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	w := map[string]float64{}
	for k, table := range cvssWeights {
		x, ok := table[m[k]]
		if !ok {
			return 0, fmt.Errorf("bad or missing %s in %q", k, vector)
		}
		w[k] = x
	}
	prw, ok := pr[m["PR"]]
	if !ok {
		return 0, fmt.Errorf("bad or missing PR in %q", vector)
	}
	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	impact := 6.42 * iss
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	exploit := 8.22 * w["AV"] * w["AC"] * prw * w["UI"]
	if scope == "U" {
		return roundup(math.Min(impact+exploit, 10)), nil
	}
	return roundup(math.Min(1.08*(impact+exploit), 10)), nil
}

// roundup is the specification's Roundup: the smallest number with one
// decimal place that is equal to or higher than its input, computed on
// integers to avoid floating point surprises.
func roundup(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// SeverityFor maps a base score to the CVSS v3.1 qualitative rating.
func SeverityFor(score float64) Severity {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return Info
	}
}
