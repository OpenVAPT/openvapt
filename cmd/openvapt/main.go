// Command openvapt is an academic, read-only vulnerability self-assessment
// tool. It only ever examines the machine it runs on.
//
//	openvapt scan       assess this machine and write a local report
//	openvapt demo       scan the built-in simulated lab servers (safe anywhere)
//	openvapt checks     list every check
//	openvapt explain    show the full documentation of one check
//	openvapt learn      the OpenVAPT Academy course, offline
//	openvapt diff       compare two reports (what was fixed, what is new)
//	openvapt verify     confirm a signed report was not edited
//	openvapt terms      print the terms of use
//	openvapt version    print version information
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/engine"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/report"
	"github.com/openvapt/openvapt/internal/sign"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/terms"
	"github.com/openvapt/openvapt/internal/version"
	"github.com/openvapt/openvapt/internal/vulndb"
)

// termsText renders the positioning and acknowledgements from package terms,
// the same text the website shows before download.
func termsText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "OpenVAPT - Terms of Use and Acknowledgements, version %s\n", terms.Version)
	fmt.Fprintf(&b, "Full text: https://openvapt.com/legal/eula.html\n\n%s\n\n", terms.Tagline)
	for _, p := range terms.Pillars {
		fmt.Fprintf(&b, "  * %s: %s\n", p.Title, p.Text)
	}
	b.WriteString("\nBy continuing you confirm each statement below:\n\n")
	for i, a := range terms.Acknowledgements {
		fmt.Fprintf(&b, " %d. %s\n", i+1, a)
	}
	return b.String()
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stdout)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(ctx, os.Args[2:])
	case "demo":
		err = cmdDemo(ctx, os.Args[2:])
	case "checks", "list":
		err = cmdChecks(os.Args[2:])
	case "teach":
		err = cmdTeach(ctx, os.Args[2:])
	case "learn", "academy":
		err = cmdLearn(os.Args[2:])
	case "explain":
		err = cmdExplain(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "vulndb":
		db, e := vulndb.Embedded()
		if e != nil {
			err = e
		} else {
			fmt.Println(db.Notice())
			fmt.Printf("Fixture: %t\nAdvisories: %d\nAffected: %d\n", db.Header.Fixture, db.Header.Counts.Advisories, db.Header.Counts.Affected)
			for _, src := range db.Header.Sources {
				fmt.Printf("%s - %s - licence: %s\n", src.Name, src.URL, src.Licence)
			}
		}
	case "terms":
		fmt.Print(termsText())
	case "version", "--version", "-v":
		fmt.Printf("OpenVAPT %s (commit %s, %s/%s)\nChannel: %s\n%s\nhttps://openvapt.com\n",
			version.Version, version.Commit, runtime.GOOS, runtime.GOARCH, version.ChannelName(), terms.Tagline)
		if version.PreRelease() {
			fmt.Println("This is a pre-release build: it may be incomplete or wrong and is used 100% at your own risk.")
		}
		if db, e := vulndb.Embedded(); e == nil {
			fmt.Printf("Vulnerability data: snapshot %s (fixture: %t)\n", db.Header.Generated, db.Header.Fixture)
			for _, src := range db.Header.Sources {
				fmt.Printf("  %s - %s - licence: %s\n", src.Name, src.URL, src.Licence)
			}
		}
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "openvapt:", err)
		code := 5
		var ee *exitError
		if errors.As(err, &ee) {
			code = ee.code
		}
		os.Exit(code)
	}
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usage(w io.Writer) {
	fmt.Fprint(w, `OpenVAPT - academic, non-commercial, read-only vulnerability self-assessment for this machine only.
Free for your own personal or business use, 100% at your own risk. Not for sale. Not for providing services.

Usage:
  openvapt scan [flags]          Assess this machine and write a local report
  openvapt demo [flags]          Scan the built-in simulated lab (vulnerable|hardened|practice --seed S)
  openvapt checks [--json]       List every check
  openvapt explain <CHECK-ID>    Show what a check does, why, how to fix it
  openvapt learn [MODULE] [--quiz]  OpenVAPT Academy: learn VAPT from theory to application
  openvapt teach                 Teacher toolkit: course plans, worksheets, rubric, practice lab keys
  openvapt diff <old.json> <new.json>
  openvapt verify <report.json> [--key-id ID]
  openvapt vulndb             Show offline snapshot details
  openvapt terms | version

Run "openvapt scan -h" for scan flags (--timeout bounds the whole scan, --fail-on sets the
severity that returns exit code 3). Nothing is ever sent off this machine.

Exit Codes (checked in this order, so 0 means every selected check reached a verdict):
  0  completed: no finding at or above --fail-on (default high) and no coverage gap
  2  invalid arguments or usage
  3  findings at or above the --fail-on severity (default: critical or high)
  4  incomplete coverage: a check could not observe enough to decide
  5  internal error, a check ended with an error, or the scan was interrupted
  6  the report could not be written
`)
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

type scanFlags struct {
	out, formats, only, skip, baseline  string
	failOn                              string
	dryRun, accept, noSign, quiet, demo bool
	parallel                            int
	timeout                             time.Duration

	// Filled by prepare before any scanning starts.
	formatList []string
	old        *report.Report
	failAt     check.Severity // lowest severity that returns exit 3; "" never does
}

// parseFailOn validates --fail-on: a severity name, or none.
func parseFailOn(s string) (check.Severity, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "":
		return check.High, nil // the default: Critical or High returns 3
	case "critical", "high", "medium", "low", "info":
		return check.Severity(v), nil
	case "none":
		return "", nil
	}
	return "", usageErr("--fail-on must be critical, high, medium, low, info or none (got %q)", s)
}

// exitCode maps a finished report to the documented exit code. Errors win
// over coverage gaps, which win over findings, so 0 is only ever returned
// when every selected check reached a verdict and nothing at or above
// failAt failed.
func exitCode(r *report.Report, failAt check.Severity) (int, string) {
	if r.Summary.Errors > 0 {
		return 5, "one or more checks ended with an internal error"
	}
	if r.Summary.Incomplete > 0 {
		return 4, "scan coverage was incomplete"
	}
	if failAt == "" {
		return 0, ""
	}
	n := 0
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) && check.Severity(f.Severity).Rank() <= failAt.Rank() {
			n++
		}
	}
	if n > 0 {
		return 3, fmt.Sprintf("%d finding(s) at or above %s severity", n, failAt)
	}
	return 0, ""
}

// engineOptions turns the flags into engine options.
func (f *scanFlags) engineOptions() engine.Options {
	return engine.Options{Only: splitList(f.only), Skip: splitList(f.skip), Parallel: f.parallel, Deadline: f.timeout}
}

var knownFormats = map[string]bool{"html": true, "json": true, "sarif": true, "md": true}

// parseFormats validates --format: trims, lower-cases and de-duplicates the
// list, and rejects unknown or empty values as a usage error (exit 2).
func parseFormats(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if !knownFormats[f] {
			return nil, usageErr("unknown report format %q (use html, json, sarif, md)", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, usageErr("--format needs at least one of html, json, sarif, md")
	}
	return out, nil
}

// prepare validates flags and loads the baseline before scanning, so a typo
// fails in a second instead of after a full scan.
func (f *scanFlags) prepare() error {
	list, err := parseFormats(f.formats)
	if err != nil {
		return err
	}
	f.formatList = list
	failAt, err := parseFailOn(f.failOn)
	if err != nil {
		return err
	}
	f.failAt = failAt
	if f.parallel == 0 {
		f.parallel = 4
	}
	if f.parallel < 1 || f.parallel > engine.MaxParallel {
		return usageErr("--parallel must be between 1 and %d", engine.MaxParallel)
	}
	if f.timeout < 0 {
		return usageErr("--timeout must be a positive duration such as 30m")
	}
	if f.baseline != "" {
		old, err := report.Load(f.baseline)
		if err != nil {
			return usageErr("cannot use --baseline: %v", err)
		}
		f.old = old
	}
	return nil
}

// defaultOutDir creates a fresh private report folder named after the time.
func defaultOutDir(prefix string) (string, error) {
	dir, err := os.MkdirTemp(".", prefix+time.Now().Format("20060102-150405")+"-")
	if err != nil {
		return "", err
	}
	// A private directory needs the execute bit; 0700 is owner-only.
	err = os.Chmod(dir, 0o700) // #nosec G302 -- directory, not a file
	if err != nil {
		return "", err
	}
	return dir, nil
}

func addScanFlags(fs *flag.FlagSet, f *scanFlags, defOut string) {
	fs.StringVar(&f.out, "out", defOut, "directory to write the report into")
	fs.StringVar(&f.formats, "format", "html,json,sarif,md", "comma-separated report formats: html,json,sarif,md")
	fs.StringVar(&f.only, "only", "", "run only these check ids or prefixes (e.g. WEB-,HOST-SSH-001)")
	fs.StringVar(&f.skip, "skip", "", "skip these check ids or prefixes")
	fs.StringVar(&f.baseline, "baseline", "", "previous report.json to compare against")
	fs.BoolVar(&f.noSign, "no-sign", false, "do not sign the report")
	fs.BoolVar(&f.quiet, "quiet", false, "print less")
	fs.IntVar(&f.parallel, "parallel", 4, fmt.Sprintf("number of checks to run at once (1 to %d)", engine.MaxParallel))
	fs.DurationVar(&f.timeout, "timeout", 0, "bound the whole scan, for example 30m; checks still waiting when it passes are reported as errors (0 = no bound; each check always has its own 90s limit)")
	fs.StringVar(&f.failOn, "fail-on", "high", "lowest failed severity that returns exit code 3: critical, high, medium, low, info or none")
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var f scanFlags
	addScanFlags(fs, &f, "")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print every file, command and request the scan would use, then exit")
	fs.BoolVar(&f.accept, "accept-terms", false, "confirm you have read and accept every acknowledgement in 'openvapt terms' (for automation)")
	_ = fs.Parse(args)
	if err := f.prepare(); err != nil {
		return err
	}

	opts := f.engineOptions()
	if f.dryRun {
		fmt.Println("Dry run: nothing will be read or executed. Operations a real scan would perform:")
		rec := &sys.Recorder{W: os.Stdout}
		engine.Run(ctx, rec, opts)
		fmt.Println("\nEvery operation above is read-only and limited to this machine (127.0.0.1).")
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("scan supports Linux only in this version; try 'openvapt demo' or 'openvapt scan --dry-run'")
	}
	if !f.accept && !confirmTerms(os.Stdin, os.Stdout) {
		return errors.New("terms not accepted; nothing was scanned")
	}
	if os.Geteuid() != 0 && !f.quiet {
		fmt.Println("Note: not running as root. Checks that need protected files will be skipped.")
	}
	fmt.Printf("Scanning this machine with %d checks (read-only, local only)...\n", len(engine.Select(opts)))
	r := engine.Run(ctx, sys.NewLive(), opts)
	return finish(r, f)
}

func cmdDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	var f scanFlags
	var which string
	fs.StringVar(&which, "lab", "vulnerable", "which simulated server to scan: vulnerable, hardened or practice")
	seed := fs.String("seed", "", "practice lab seed, for example a student number (with --lab practice)")
	addScanFlags(fs, &f, "")
	// The help text invites  demo hardened ; accept one positional lab name
	// (before or after the flags) as a synonym for --lab and refuse anything
	// else, so a typo never scans the vulnerable lab in silence.
	var pos []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = append(pos, args[0]), args[1:]
	}
	_ = fs.Parse(args)
	pos = append(pos, fs.Args()...)
	labFlag := false
	fs.Visit(func(fl *flag.Flag) { labFlag = labFlag || fl.Name == "lab" })
	switch len(pos) {
	case 0:
	case 1:
		if labFlag && which != pos[0] {
			return usageErr("lab given twice: --lab %s and %q", which, pos[0])
		}
		which = pos[0]
	default:
		return usageErr("demo takes at most one lab name (vulnerable, hardened or practice), got %q", strings.Join(pos, " "))
	}
	if err := f.prepare(); err != nil {
		return err
	}
	f.demo = true
	if which == "practice" {
		if strings.TrimSpace(*seed) == "" {
			return usageErr("--lab practice needs --seed, for example your student number")
		}
		fmt.Printf("Demo: scanning your practice lab server, seed %q (simulated in memory, your machine is not touched).\n", *seed)
		r := engine.Practice(ctx, *seed, f.engineOptions())
		return finish(r, f)
	}
	var s sys.System
	switch which {
	case "vulnerable":
		s = lab.Vulnerable()
	case "hardened":
		s = lab.Hardened()
	default:
		return usageErr("unknown lab %q (vulnerable, hardened or practice)", which)
	}
	fmt.Printf("Demo: scanning the simulated %q lab server (in memory, your machine is not touched).\n", which)
	r := engine.Run(ctx, s, f.engineOptions())
	r.Scan.Host = "lab-" + which + " (simulated)"
	r.Scan.AsRoot = false // a simulated server says nothing about the operator
	return finish(r, f)
}

func finish(r *report.Report, f scanFlags) error {
	if f.formatList == nil {
		if err := f.prepare(); err != nil {
			return err
		}
	}
	if !f.noSign {
		if path, err := sign.KeyPath(); err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		} else if key, err := sign.LoadOrCreateKey(path); err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		} else if err := sign.Sign(r, key); err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		}
	}
	if f.out == "" {
		prefix := "openvapt-report-"
		if f.demo {
			prefix = "openvapt-demo-report-"
		}
		dir, err := defaultOutDir(prefix)
		if err != nil {
			return &exitError{code: 6, err: err}
		}
		f.out = dir
	}
	files, err := r.WriteAll(f.out, f.formatList)
	if err != nil {
		return &exitError{code: 6, err: err}
	}
	r.PrintSummary(os.Stdout)
	if f.old != nil {
		report.PrintDiff(os.Stdout, f.old, r)
	}
	fmt.Println("Report written (only on this machine):")
	for _, p := range files {
		abs, _ := filepath.Abs(p)
		fmt.Println("  " + abs)
	}
	if r.Integrity != nil && !f.quiet {
		fmt.Printf("Signed with your local key %s. Anyone can check it with: openvapt verify report.json --key-id %s\n", r.Integrity.KeyID, r.Integrity.KeyID)
	}
	if code, why := exitCode(r, f.failAt); code != 0 {
		return &exitError{code: code, err: errors.New(why)}
	}
	return nil
}

// confirmTerms asks the user to read and accept every acknowledgement by
// typing the exact phrase. Nothing about the answer is stored.
func confirmTerms(in io.Reader, out io.Writer) bool {
	fmt.Fprint(out, termsText())
	fmt.Fprintf(out, "\nIf you have read, studied, understood, acknowledged, agreed to and accepted all of the above,\ntype %s to continue (anything else cancels; nothing is stored): ", terms.AcceptPhrase)
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), terms.AcceptPhrase)
}

func cmdChecks(args []string) error {
	fs := flag.NewFlagSet("checks", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the full catalogue as JSON")
	_ = fs.Parse(args)
	all := check.All()
	if *asJSON {
		b, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	for _, c := range all {
		fmt.Printf("%-13s %-8s %-8s %s\n", c.ID, c.Domain, c.Severity, c.Title)
	}
	fmt.Printf("\n%d checks. Run 'openvapt explain <ID>' for details.\n", len(all))
	return nil
}

func cmdExplain(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: openvapt explain <CHECK-ID>")
	}
	c := check.Get(args[0])
	if c == nil {
		return fmt.Errorf("no check with id %q (see 'openvapt checks')", args[0])
	}
	fmt.Printf("%s  %s\nDomain: %s   Severity: %s   CVSS: %s\n\n", c.ID, c.Title, c.Domain, c.Severity, c.CVSS)
	fmt.Printf("What it checks:\n  %s\n\nWhy it matters:\n  %s\n\nHow it detects:\n  %s\n\nHow to fix:\n  %s\n\nHow to verify:\n  %s\n\n",
		c.Summary, c.Rationale, c.Detection, c.Fix, c.Verify)
	fmt.Println("References:")
	for _, r := range c.Refs {
		fmt.Printf("  - %s\n    %s\n", r.Title, r.URL)
	}
	if mods := academy.ForCheck(c.ID); len(mods) > 0 {
		fmt.Println("\nLearn more in the OpenVAPT Academy:")
		for _, m := range mods {
			fmt.Printf("  - %s: %s (%s, about %d minutes)\n    offline: openvapt learn %s\n    online:  https://openvapt.com/academy/%s.html\n", m.ID, m.Title, m.Level, m.Minutes, m.ID, strings.ToLower(m.ID))
		}
	}
	fmt.Printf("\nSource code: %s\nOnline: https://openvapt.com/checks/%s.html\n", c.SourceFile, c.ID)
	return nil
}

func cmdDiff(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: openvapt diff <old.json> <new.json>")
	}
	old, err := report.Load(args[0])
	if err != nil {
		return err
	}
	cur, err := report.Load(args[1])
	if err != nil {
		return err
	}
	report.PrintDiff(os.Stdout, old, cur)
	return nil
}

// verifyArgs accepts the report path before or after --key-id:
// "verify report.json --key-id X" and "verify --key-id X report.json".
func verifyArgs(args []string) (path, keyID string, err error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	k := fs.String("key-id", "", "expected signing key id (ask the report owner for it)")
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path, args = args[0], args[1:]
	}
	if e := fs.Parse(args); e != nil {
		return "", "", usageErr("verify: %v", e)
	}
	if path == "" {
		path = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return "", "", usageErr("verify takes one report file, got %q and %q", path, fs.Arg(0))
	}
	if path == "" {
		return "", "", usageErr("usage: openvapt verify <report.json> [--key-id ID]")
	}
	return path, *k, nil
}

func cmdVerify(args []string) error {
	path, keyID, err := verifyArgs(args)
	if err != nil {
		return err
	}
	r, err := sign.VerifyFile(path, keyID)
	if err != nil {
		return fmt.Errorf("NOT VERIFIED: %w", err)
	}
	fmt.Printf("Verified: unchanged since it was signed by key %s on %s.\n", r.Integrity.KeyID, r.Scan.Finished.Format("2006-01-02 15:04 UTC"))
	if keyID == "" {
		fmt.Println("Tip: pass --key-id to also confirm WHO signed it (the owner can tell you their key id).")
	}
	fmt.Println("A valid signature proves integrity only. It does not prove the machine is secure.")
	return nil
}
