package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
)

// Change is the difference for one check between two reports.
type Change struct {
	ID, Title, Severity, Before, After string
}

// Diff compares an older and a newer report: what was fixed, what is new,
// and what is still open. This supports the "verify the fix" step.
func Diff(old, cur *Report) (fixed, added, open []Change) {
	prev := map[string]Finding{}
	for _, f := range old.Findings {
		prev[f.ID] = f
	}
	for _, f := range cur.Findings {
		p, had := prev[f.ID]
		c := Change{ID: f.ID, Title: f.Title, Severity: f.Severity, After: f.Status}
		if had {
			c.Before = p.Status
		}
		switch {
		case f.Status == string(check.Fail) && (!had || p.Status != string(check.Fail)):
			added = append(added, c)
		case f.Status == string(check.Fail):
			open = append(open, c)
		case had && p.Status == string(check.Fail):
			fixed = append(fixed, c)
		}
	}
	return
}

// PrintDiff writes a human-readable diff.
func PrintDiff(w io.Writer, old, cur *Report) {
	fixed, added, open := Diff(old, cur)
	fmt.Fprintf(w, "Comparing %s -> %s\n\n", old.Scan.Started.Format("2006-01-02 15:04"), cur.Scan.Started.Format("2006-01-02 15:04"))
	section := func(title string, cs []Change) {
		fmt.Fprintf(w, "%s (%d)\n", title, len(cs))
		for _, c := range cs {
			fmt.Fprintf(w, "  %-9s %-13s %s\n", strings.ToUpper(c.Severity), c.ID, c.Title)
		}
		fmt.Fprintln(w)
	}
	section("Fixed", fixed)
	section("New", added)
	section("Still Open", open)
}
