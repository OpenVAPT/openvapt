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
	"runtime"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/engine"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/redact"
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

	c := lookup(os.Args[1])
	if c == nil {
		usage(os.Stderr)
		os.Exit(2)
	}
	if err := c.Run(ctx, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "openvapt:", err)
		code := 5
		var ee *exitError
		if errors.As(err, &ee) {
			code = ee.code
		}
		os.Exit(code)
	}
}

func cmdVulndb() error {
	db, err := vulndb.Embedded()
	if err != nil {
		return err
	}
	fmt.Println(db.Notice())
	fmt.Printf("Fixture: %t\nAdvisories: %d\nAffected: %d\n", db.Header.Fixture, db.Header.Counts.Advisories, db.Header.Counts.Affected)
	for _, src := range db.Header.Sources {
		fmt.Printf("%s - %s - licence: %s\n", src.Name, src.URL, src.Licence)
	}
	return nil
}

func cmdVersion() {
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
`)
	for _, c := range commands {
		if c.Hidden {
			continue
		}
		syn := "openvapt " + strings.TrimSpace(c.Name+" "+c.Args)
		if len(syn) > 34 {
			fmt.Fprintf(w, "  %s\n  %-34s %s\n", syn, "", c.Summary)
			continue
		}
		fmt.Fprintf(w, "  %-34s %s\n", syn, c.Summary)
	}
	fmt.Fprint(w, `
Run "openvapt scan -h" for scan flags (--timeout bounds the whole scan, --fail-on sets the
severity that returns exit code 3, --suppress names a suppression file with a reason and an
expiry for each accepted finding). Nothing is ever sent off this machine.
"openvapt man" prints the manual page; "openvapt completion bash|zsh|fish" prints shell completion.

Exit Codes (checked in this order, so 0 means every selected check reached a verdict):
`)
	for _, e := range exitCodes {
		fmt.Fprintf(w, "  %d  %s\n", e.Code, e.Meaning)
	}
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

type scanFlags struct {
	out, formats, only, skip, baseline  string
	suppress                            string
	failOn                              string
	dryRun, accept, noSign, quiet, demo bool
	open                                bool
	parallel                            int
	timeout                             time.Duration

	// Filled by prepare before any scanning starts.
	formatList []string
	old        *report.Report
	failAt     check.Severity // lowest severity that returns exit 3; "" never does
	sup        *report.Suppressions
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
	if r.Scan.Checks == 0 && len(r.Findings) == 0 {
		return 2, "no checks were run"
	}
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
		if f.Status == string(check.Fail) && !f.FullySuppressed() && check.Severity(f.Severity).Rank() <= failAt.Rank() {
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
	opts := f.engineOptions()
	if bad := engine.Unmatched(opts.Only); len(bad) > 0 {
		return usageErr("--only names no known check id or prefix: %s", strings.Join(bad, ", "))
	}
	if bad := engine.Unmatched(opts.Skip); len(bad) > 0 {
		return usageErr("--skip names no known check id or prefix: %s", strings.Join(bad, ", "))
	}
	if len(engine.Select(opts)) == 0 {
		return usageErr("--only and --skip together select zero checks; nothing would be assessed")
	}
	if f.baseline != "" {
		old, err := report.Load(f.baseline)
		if err != nil {
			return usageErr("cannot use --baseline: %v", err)
		}
		f.old = old
	}
	if f.suppress != "" {
		sup, err := report.LoadSuppressions(f.suppress, time.Now().UTC())
		if err != nil {
			return usageErr("cannot use --suppress: %v", err)
		}
		f.sup = sup
		for _, e := range sup.Expired {
			fmt.Fprintf(os.Stderr, "warning: suppression for %s expired on %s and is ignored\n", e.ID, e.Expires)
		}
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
	fs.StringVar(&f.out, "out", defOut, "directory to write the report into (scan default: a new folder ~/openvapt-reports/<UTC time>, given back to the sudo user when sudo keeps HOME; demo default: a new folder in the current directory)")
	fs.BoolVar(&f.open, "open", false, "after writing, open report.html with /usr/bin/xdg-open, only in a desktop session (DISPLAY or WAYLAND_DISPLAY set) and never as root")
	fs.StringVar(&f.formats, "format", "html,json,sarif,md", "comma-separated report formats: html,json,sarif,md")
	fs.StringVar(&f.only, "only", "", "run only these check ids or prefixes (e.g. WEB-,HOST-SSH-001)")
	fs.StringVar(&f.skip, "skip", "", "skip these check ids or prefixes")
	fs.StringVar(&f.baseline, "baseline", "", "previous report.json to compare against")
	fs.BoolVar(&f.noSign, "no-sign", false, "do not sign the report")
	fs.BoolVar(&f.quiet, "quiet", false, "print less")
	fs.IntVar(&f.parallel, "parallel", 4, fmt.Sprintf("number of checks to run at once (1 to %d)", engine.MaxParallel))
	fs.DurationVar(&f.timeout, "timeout", 0, "bound the whole scan, for example 30m; checks still waiting when it passes are reported as errors (0 = no bound; each check always has its own 90s limit)")
	fs.StringVar(&f.failOn, "fail-on", "high", "lowest failed severity that returns exit code 3: critical, high, medium, low, info or none")
	fs.StringVar(&f.suppress, "suppress", "", "suppression file (JSON list with id, optional target, reason, expires); suppressed findings stay in the report and do not count toward --fail-on")
}

// scanFlagSet is the single definition of the scan flags, used by the
// command, the man page and shell completion.
func scanFlagSet(f *scanFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	addScanFlags(fs, f, "")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print every file, command and request the scan would use, then exit")
	fs.BoolVar(&f.accept, "accept-terms", false, "confirm you have read and accept every acknowledgement in 'openvapt terms' (for automation)")
	return fs
}

// demoFlagSet is the single definition of the demo flags.
func demoFlagSet(f *scanFlags, which, seed *string) *flag.FlagSet {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	fs.StringVar(which, "lab", "vulnerable", "which simulated server to scan: vulnerable, hardened or practice")
	fs.StringVar(seed, "seed", "", "practice lab seed, for example a student number (with --lab practice)")
	addScanFlags(fs, f, "")
	return fs
}

func cmdScan(ctx context.Context, args []string) error {
	var f scanFlags
	fs := scanFlagSet(&f)
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
	var f scanFlags
	var which, seedV string
	seed := &seedV
	fs := demoFlagSet(&f, &which, seed)
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
	r.ApplySuppressions(f.sup)
	r.Scan.Command = safeCommandLine(os.Args)
	if !f.noSign {
		if path, err := sign.KeyPath(); err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		} else if key, err := sign.LoadOrCreateKey(path); err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		} else if err := sign.Sign(r, key); err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		}
	}
	var rd *reportsDir
	if f.out == "" {
		var dir string
		var err error
		if f.demo {
			dir, err = defaultOutDir("openvapt-demo-report-")
		} else {
			home, _ := os.UserHomeDir()
			rd, err = scanReportsDir(home, time.Now(), sudoOwner(os.Geteuid(), os.Getenv, home))
			if rd != nil {
				dir = rd.Path
			}
		}
		if err != nil {
			return &exitError{code: 6, err: err}
		}
		f.out = dir
	}
	files, err := r.WriteAll(f.out, f.formatList)
	if rd != nil {
		if herr := rd.finish(files); err == nil && herr != nil {
			err = fmt.Errorf("could not give the report folder back to the sudo user: %w", herr)
		}
	}
	if err != nil {
		return &exitError{code: 6, err: err}
	}
	r.PrintSummary(os.Stdout)
	if f.old != nil {
		report.PrintDiff(os.Stdout, f.old, r)
	}
	printReports(os.Stdout, files)
	if r.Integrity != nil && !f.quiet {
		fmt.Printf("Signed with your local key %s. Anyone can check it with: openvapt verify report.json --key-id %s\n", r.Integrity.KeyID, r.Integrity.KeyID)
	}
	if f.open {
		openReport(os.Stdout, files, os.Getenv, os.Geteuid())
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
	var asJSONV bool
	asJSON := &asJSONV
	fs := checksFlagSet(asJSON)
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

func checksFlagSet(asJSON *bool) *flag.FlagSet {
	fs := flag.NewFlagSet("checks", flag.ExitOnError)
	fs.BoolVar(asJSON, "json", false, "print the full catalogue as JSON")
	return fs
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
	var kV string
	k := &kV
	fs := verifyFlagSet(k)
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

func verifyFlagSet(k *string) *flag.FlagSet {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(k, "key-id", "", "expected signing key id (ask the report owner for it)")
	return fs
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

// keptValues are flags whose values are check ids, formats or numbers and
// are copied into the report's command line; every other value (paths,
// seeds) is replaced with a placeholder.
var keptValues = map[string]bool{"only": true, "skip": true, "format": true, "fail-on": true, "lab": true, "parallel": true, "timeout": true}

// safeCommandLine rebuilds the command line for the report without file
// paths, seeds or any free text.
func safeCommandLine(args []string) string {
	out := []string{"openvapt"}
	expectValue := ""
	for i, a := range args {
		if i == 0 {
			continue
		}
		if expectValue != "" {
			if keptValues[expectValue] {
				out = append(out, redact.String(a))
			} else {
				out = append(out, "<value>")
			}
			expectValue = ""
			continue
		}
		if !strings.HasPrefix(a, "-") {
			if i == 1 || a == "vulnerable" || a == "hardened" || a == "practice" {
				out = append(out, a)
			} else {
				out = append(out, "<value>")
			}
			continue
		}
		name := strings.TrimLeft(a, "-")
		if k, v, ok := strings.Cut(name, "="); ok {
			if keptValues[k] {
				out = append(out, "--"+k+"="+redact.String(v))
			} else {
				out = append(out, "--"+k+"=<value>")
			}
			continue
		}
		out = append(out, "--"+name)
		if fl := scanFlagSet(&scanFlags{}).Lookup(name); fl != nil {
			if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
				expectValue = name
			}
		} else if name == "lab" || name == "seed" {
			expectValue = name
		}
	}
	return strings.Join(out, " ")
}
