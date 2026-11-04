package engine

import (
	"context"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/report"
)

// Practice labs for teaching. A practice server is the vulnerable lab with
// some weaknesses fixed: for each check, a seed (for example a student's
// name or number) decides whether the server still has that weakness. Every
// student gets a different server, the same seed always gives the same
// server, and the teacher's answer key comes from the same seed, so it is
// exact by construction. Nothing touches a real machine.

// practiceShare is the percentage of checks that keep their weakness.
const practiceShare = 45

// Vulnerable reports whether the practice server for seed keeps the weakness
// a check looks for. Informational checks always show their lab output.
func Vulnerable(seed, checkID string) bool {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(seed) + "|" + checkID))
	return h.Sum64()%100 < practiceShare
}

// Practice scans the practice server for seed.
func Practice(ctx context.Context, seed string, o Options) *report.Report {
	v := Run(ctx, lab.Vulnerable(), o)
	h := Run(ctx, lab.Hardened(), o)
	fixed := map[string]report.Finding{}
	for _, f := range h.Findings {
		fixed[f.ID] = f
	}
	r := v
	for i, f := range r.Findings {
		if f.Severity == string(check.Info) || Vulnerable(seed, f.ID) {
			continue
		}
		if hf, ok := fixed[f.ID]; ok {
			r.Findings[i] = hf
		}
	}
	if !Vulnerable(seed, "HOST-OS-001") {
		r.Scan.OS = h.Scan.OS
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Status != b.Status {
			return statusRank(a.Status) < statusRank(b.Status)
		}
		if a.Severity != b.Severity {
			return check.Severity(a.Severity).Rank() < check.Severity(b.Severity).Rank()
		}
		return a.ID < b.ID
	})
	r.Scan.Host = "lab-practice (simulated, seed " + seed + ")"
	r.Scan.AsRoot = false // a simulated server says nothing about the operator
	r.Scan.Sites = v.Scan.Sites
	r.Summarise()
	return r
}

// Answer is one weakness present on a practice server.
type Answer struct {
	ID, Title, Severity, Category string
}

// Answers is the teacher's key for a seed: every failed check on that
// practice server, most severe first.
func Answers(ctx context.Context, seed string, o Options) []Answer {
	var out []Answer
	for _, f := range Practice(ctx, seed, o).Findings {
		if f.Status == string(check.Fail) {
			out = append(out, Answer{f.ID, f.Title, f.Severity, string(f.Category)})
		}
	}
	return out
}
