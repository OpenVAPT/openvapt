// Package check defines what a vulnerability check is, how checks register
// themselves, and the shape of the findings they produce.
//
// Every check in OpenVAPT is one small Go file that calls Register from its
// init function. The registry records the file each check lives in, so the
// website generator can cite the exact source code of every check.
package check

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/openvapt/openvapt/internal/sys"
)

// Domain groups checks by the part of the machine they look at.
type Domain string

const (
	DomainHost    Domain = "host"
	DomainNetwork Domain = "network"
	DomainWeb     Domain = "web"
)

// Severity follows the qualitative rating scale of CVSS v3.1
// (FIRST, "CVSS v3.1 Specification", section 5).
type Severity string

const (
	Critical Severity = "critical" // CVSS 9.0 - 10.0
	High     Severity = "high"     // CVSS 7.0 - 8.9
	Medium   Severity = "medium"   // CVSS 4.0 - 6.9
	Low      Severity = "low"      // CVSS 0.1 - 3.9
	Info     Severity = "info"     // CVSS 0.0, informational only
)

// Rank orders severities from most to least serious.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	default:
		return 4
	}
}

// Status is the outcome of running one check against one target.
type Status string

const (
	Pass  Status = "pass"  // the weakness was looked for and not found
	Fail  Status = "fail"  // the weakness was found
	Skip  Status = "skip"  // the check does not apply on this machine
	Error Status = "error" // the check could not complete
)

// Ref is a citation to a public source that explains the weakness or the fix.
type Ref struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Standards maps a check to the public frameworks VAPT reports are judged
// against. Empty fields mean "no direct mapping".
type Standards struct {
	CWE      []string `json:"cwe,omitempty"`       // e.g. "CWE-16"
	OWASP    []string `json:"owasp,omitempty"`     // OWASP Top 10 2021, e.g. "A05:2021"
	ASVS     []string `json:"asvs,omitempty"`      // OWASP ASVS 4.0.3 requirement ids
	NIST     []string `json:"nist,omitempty"`      // NIST SP 800-53 Rev. 5 controls
	CISTopic string   `json:"cis_topic,omitempty"` // CIS Benchmark topic, paraphrased, never copied
}

// Check is the definition of one vulnerability check.
type Check struct {
	ID        string    `json:"id"`        // stable id, e.g. "HOST-SSH-001"
	Title     string    `json:"title"`     // short name
	Domain    Domain    `json:"domain"`    // host, network or web
	Severity  Severity  `json:"severity"`  // severity when the check fails
	CVSS      string    `json:"cvss"`      // representative CVSS v3.1 base vector
	Summary   string    `json:"summary"`   // what the check looks for, one sentence
	Rationale string    `json:"rationale"` // why the weakness matters
	Detection string    `json:"detection"` // how the code detects it, in plain words
	Fix       string    `json:"fix"`       // how to remediate
	Verify    string    `json:"verify"`    // how to confirm the fix
	Refs      []Ref     `json:"refs"`
	Standards Standards `json:"standards"`

	// Run performs the check. It must be read-only and must only touch the
	// local machine through the sys.System it is given.
	Run func(ctx context.Context, s sys.System) []Result `json:"-"`

	// SourceFile is filled in by Register: the path of the Go file that
	// defines this check, relative to the repository root.
	SourceFile string `json:"source_file"`
}

// Result is one observation produced by a check.
type Result struct {
	Status   Status   `json:"status"`
	Target   string   `json:"target"`             // what was looked at (file, port, vhost)
	Message  string   `json:"message"`            // one-line outcome
	Evidence []string `json:"evidence,omitempty"` // redacted lines that support the outcome
}

var (
	mu       sync.Mutex
	registry = map[string]*Check{}
)

// Register adds a check to the global registry. It panics on duplicate ids
// or missing metadata, so a broken check fails the build's tests at once.
func Register(c *Check) {
	if c.ID == "" || c.Title == "" || c.Run == nil || c.Fix == "" || c.Rationale == "" {
		panic(fmt.Sprintf("check %q is missing required fields", c.ID))
	}
	if len(c.Refs) == 0 {
		panic(fmt.Sprintf("check %q must cite at least one reference", c.ID))
	}
	_, file, _, _ := runtime.Caller(1)
	if i := strings.Index(file, "/internal/checks/"); i >= 0 {
		c.SourceFile = file[i+1:]
	} else {
		c.SourceFile = file
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[c.ID]; dup {
		panic("duplicate check id " + c.ID)
	}
	registry[c.ID] = c
}

// All returns every registered check, sorted by domain then id.
func All() []*Check {
	mu.Lock()
	defer mu.Unlock()
	out := make([]*Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return domainOrder(out[i].Domain) < domainOrder(out[j].Domain)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one check by id, or nil.
func Get(id string) *Check {
	mu.Lock()
	defer mu.Unlock()
	return registry[strings.ToUpper(id)]
}

func domainOrder(d Domain) int {
	switch d {
	case DomainHost:
		return 0
	case DomainNetwork:
		return 1
	default:
		return 2
	}
}

// Helpers used by checks to build results without repeating boilerplate.

func PassR(target, msg string, ev ...string) Result {
	return Result{Status: Pass, Target: target, Message: msg, Evidence: ev}
}
func FailR(target, msg string, ev ...string) Result {
	return Result{Status: Fail, Target: target, Message: msg, Evidence: ev}
}
func SkipR(target, msg string) Result { return Result{Status: Skip, Target: target, Message: msg} }
func ErrR(target string, err error) Result {
	return Result{Status: Error, Target: target, Message: err.Error()}
}
