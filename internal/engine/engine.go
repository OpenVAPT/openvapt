// Package engine runs checks and assembles the report.
//
// It follows the four phases of NIST SP 800-115 that apply to a
// non-intrusive self-assessment: planning (scope is fixed to this machine),
// discovery (collect), vulnerability analysis (checks), and reporting.
// The "attack" phase of 800-115 is deliberately absent: OpenVAPT never
// attempts exploitation.
package engine

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/redact"
	"github.com/openvapt/openvapt/internal/report"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/version"
)

// Options select which checks to run.
type Options struct {
	Only     []string // run only these ids (or id prefixes such as "WEB-")
	Skip     []string // skip these ids or prefixes
	Parallel int      // concurrent checks, default 4
	Timeout  time.Duration
}

func match(id string, list []string) bool {
	for _, p := range list {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" && (id == p || strings.HasPrefix(id, p)) {
			return true
		}
	}
	return false
}

// Select returns the checks chosen by Only/Skip.
func Select(o Options) []*check.Check {
	var out []*check.Check
	for _, c := range check.All() {
		if len(o.Only) > 0 && !match(c.ID, o.Only) {
			continue
		}
		if match(c.ID, o.Skip) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// Run executes the selected checks against s and returns a report.
func Run(ctx context.Context, s sys.System, o Options) *report.Report {
	if o.Parallel <= 0 {
		o.Parallel = 4
	}
	if o.Timeout <= 0 {
		o.Timeout = 90 * time.Second
	}
	checks := Select(o)
	started := time.Now().UTC()

	findings := make([]report.Finding, len(checks))
	sem := make(chan struct{}, o.Parallel)
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func(i int, c *check.Check) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			findings[i] = runOne(ctx, s, c, o.Timeout)
		}(i, c)
	}
	wg.Wait()

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Status != b.Status {
			return statusRank(a.Status) < statusRank(b.Status)
		}
		if a.Severity != b.Severity {
			return check.Severity(a.Severity).Rank() < check.Severity(b.Severity).Rank()
		}
		return a.ID < b.ID
	})

	host, _ := os.Hostname()
	osr := collect.OSRelease(s)
	r := &report.Report{
		Schema: report.SchemaVersion,
		Tool:   report.Tool{Name: "OpenVAPT", Version: version.Version, Commit: version.Commit, URL: "https://openvapt.com"},
		Scan: report.Scan{
			Started:  started,
			Finished: time.Now().UTC(),
			Host:     host,
			OS:       osr["PRETTY_NAME"],
			AsRoot:   os.Geteuid() == 0,
			Checks:   len(checks),
			Sites:    collect.VHosts(s),
		},
		Findings:    findings,
		Methodology: report.Methodology,
		Limitations: report.Limitations,
		Disclaimer:  report.Disclaimer,
	}
	r.Summarise()
	return r
}

func statusRank(s string) int {
	switch check.Status(s) {
	case check.Fail:
		return 0
	case check.Error:
		return 1
	case check.Incomplete:
		return 2
	case check.Pass:
		return 3
	default:
		return 3
	}
}

// runOne runs a single check with a timeout and turns a panic into an Error
// result, so one broken check can never stop the whole scan.
func runOne(parent context.Context, s sys.System, c *check.Check, timeout time.Duration) (f report.Finding) {
	f = report.FromCheck(c)
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			f.Results = []check.Result{{Status: check.Error, Target: c.ID, Message: fmt.Sprintf("internal error: %v", p)}}
			f.Status = string(check.Error)
			if os.Getenv("OPENVAPT_DEBUG") != "" {
				fmt.Fprintln(os.Stderr, string(debug.Stack()))
			}
		}
	}()
	res := c.Run(ctx, s)
	if ctx.Err() != nil {
		res = []check.Result{{Status: check.Error, Target: c.ID, Message: "timed out after " + timeout.String()}}
	}
	for i := range res {
		res[i].Message = redact.String(res[i].Message)
		res[i].Evidence = redact.All(res[i].Evidence)
	}
	f.Results = res
	f.Status = string(overall(res))
	return f
}

// overall never lets a Pass hide incomplete coverage.
func overall(rs []check.Result) check.Status {
	has := map[check.Status]bool{}
	for _, r := range rs {
		has[r.Status] = true
	}
	for _, s := range []check.Status{check.Fail, check.Error, check.Incomplete, check.Pass} {
		if has[s] {
			return s
		}
	}
	return check.Skip
}
