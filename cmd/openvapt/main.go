// Command openvapt is an academic, read-only vulnerability self-assessment
// tool. It only ever examines the machine it runs on.
//
//	openvapt scan       assess this machine and write a local report
//	openvapt demo       scan the built-in simulated lab servers (safe anywhere)
//	openvapt checks     list every check
//	openvapt explain    show the full documentation of one check
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

	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/engine"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/report"
	"github.com/openvapt/openvapt/internal/sign"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/version"
)

const terms = `OpenVAPT - Terms of Use (summary; full text: https://openvapt.com/legal/eula.html)

 1. OpenVAPT is an academic project made for learning. It is free of charge.
 2. Anyone (individuals and companies) may run it on computers and servers
    they own or control, for their own use.
 3. You may NOT use it to provide services to others, sell it, or do
    business with it.
 4. It only examines the machine it runs on and never sends data anywhere.
 5. It is provided "AS IS", without warranty of any kind. You use it
    entirely at your own risk. The developers accept no responsibility or
    liability for anything that happens from downloading or using it.
 6. You are solely responsible for having the right to run it on this
    machine and for complying with all applicable laws.
`

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
	case "explain":
		err = cmdExplain(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "terms":
		fmt.Print(terms)
	case "version", "--version", "-v":
		fmt.Printf("OpenVAPT %s (commit %s, %s/%s)\nAcademic project. Own use only, at your own risk. https://openvapt.com\n",
			version.Version, version.Commit, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "openvapt:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `OpenVAPT - academic, read-only vulnerability self-assessment for this machine only.

Usage:
  openvapt scan [flags]          Assess this machine and write a local report
  openvapt demo [flags]          Scan the built-in simulated lab (vulnerable|hardened)
  openvapt checks [--json]       List every check
  openvapt explain <CHECK-ID>    Show what a check does, why, how to fix it
  openvapt diff <old.json> <new.json>
  openvapt verify <report.json> [--key-id ID]
  openvapt terms | version

Run "openvapt scan -h" for scan flags. Nothing is ever sent off this machine.
`)
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

type scanFlags struct {
	out, formats, only, skip, baseline string
	dryRun, accept, noSign, quiet      bool
	parallel                           int
}

func addScanFlags(fs *flag.FlagSet, f *scanFlags, defOut string) {
	fs.StringVar(&f.out, "out", defOut, "directory to write the report into")
	fs.StringVar(&f.formats, "format", "html,json,sarif,md", "comma-separated report formats: html,json,sarif,md")
	fs.StringVar(&f.only, "only", "", "run only these check ids or prefixes (e.g. WEB-,HOST-SSH-001)")
	fs.StringVar(&f.skip, "skip", "", "skip these check ids or prefixes")
	fs.StringVar(&f.baseline, "baseline", "", "previous report.json to compare against")
	fs.BoolVar(&f.noSign, "no-sign", false, "do not sign the report")
	fs.BoolVar(&f.quiet, "quiet", false, "print less")
	fs.IntVar(&f.parallel, "parallel", 4, "number of checks to run at once")
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var f scanFlags
	addScanFlags(fs, &f, "openvapt-report-"+time.Now().Format("20060102-150405"))
	fs.BoolVar(&f.dryRun, "dry-run", false, "print every file, command and request the scan would use, then exit")
	fs.BoolVar(&f.accept, "accept-terms", false, "accept the terms of use without the interactive prompt")
	_ = fs.Parse(args)

	opts := engine.Options{Only: splitList(f.only), Skip: splitList(f.skip), Parallel: f.parallel}
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
	if !f.accept && !confirmTerms() {
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
	fs.StringVar(&which, "lab", "vulnerable", "which simulated server to scan: vulnerable or hardened")
	addScanFlags(fs, &f, "openvapt-demo-report")
	_ = fs.Parse(args)
	var s sys.System
	switch which {
	case "vulnerable":
		s = lab.Vulnerable()
	case "hardened":
		s = lab.Hardened()
	default:
		return fmt.Errorf("unknown lab %q (vulnerable or hardened)", which)
	}
	fmt.Printf("Demo: scanning the simulated %q lab server (in memory, your machine is not touched).\n", which)
	r := engine.Run(ctx, s, engine.Options{Only: splitList(f.only), Skip: splitList(f.skip), Parallel: f.parallel})
	r.Scan.Host = "lab-" + which + " (simulated)"
	return finish(r, f)
}

func finish(r *report.Report, f scanFlags) error {
	if !f.noSign {
		key, err := sign.LoadOrCreateKey(sign.KeyPath())
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		} else if err := sign.Sign(r, key); err != nil {
			fmt.Fprintln(os.Stderr, "warning: report not signed:", err)
		}
	}
	files, err := r.WriteAll(f.out, splitList(f.formats))
	if err != nil {
		return err
	}
	r.PrintSummary(os.Stdout)
	if f.baseline != "" {
		old, err := report.Load(f.baseline)
		if err != nil {
			return err
		}
		report.PrintDiff(os.Stdout, old, r)
	}
	fmt.Println("Report written (only on this machine):")
	for _, p := range files {
		abs, _ := filepath.Abs(p)
		fmt.Println("  " + abs)
	}
	if r.Integrity != nil && !f.quiet {
		fmt.Printf("Signed with your local key %s. Anyone can check it with: openvapt verify report.json --key-id %s\n", r.Integrity.KeyID, r.Integrity.KeyID)
	}
	if r.Summary.Critical+r.Summary.High > 0 {
		os.Exit(3) // non-zero for CI pipelines when serious findings exist
	}
	return nil
}

func confirmTerms() bool {
	fmt.Print(terms)
	fmt.Print("\nType 'yes' to accept and continue (nothing is stored): ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line)) == "yes"
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

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keyID := fs.String("key-id", "", "expected signing key id (ask the report owner for it)")
	var path string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if path == "" {
		path = fs.Arg(0)
	}
	if path == "" {
		return errors.New("usage: openvapt verify <report.json> [--key-id ID]")
	}
	r, err := report.Load(path)
	if err != nil {
		return err
	}
	if err := sign.Verify(r, *keyID); err != nil {
		return fmt.Errorf("NOT VERIFIED: %w", err)
	}
	fmt.Printf("Verified: unchanged since it was signed by key %s on %s.\n", r.Integrity.KeyID, r.Scan.Finished.Format("2006-01-02 15:04 UTC"))
	if *keyID == "" {
		fmt.Println("Tip: pass --key-id to also confirm WHO signed it (the owner can tell you their key id).")
	}
	fmt.Println("A valid signature proves integrity only. It does not prove the machine is secure.")
	return nil
}
