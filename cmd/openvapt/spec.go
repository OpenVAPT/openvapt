package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

// command is one entry of the command table. The table drives dispatch,
// "openvapt help", the man page and shell completion, so they never drift.
type command struct {
	Name    string
	Aliases []string
	Args    string // argument synopsis after the name
	Summary string
	Hidden  bool                 // not listed in help (man, completion, internal aliases)
	Flags   func() *flag.FlagSet // the real flag set the command parses; nil if none
	Subs    []command            // subcommands (teach), names and flags only
	Values  []string             // fixed positional values offered by completion
	Run     func(context.Context, []string) error
}

// exitStatus is one documented process exit status.
type exitStatus struct {
	Code    int
	Meaning string
}

var exitCodes = []exitStatus{
	{0, "completed: no unsuppressed finding at or above --fail-on (default high) and no coverage gap"},
	{2, "invalid arguments or usage, including a rejected --suppress or --baseline file"},
	{3, "unsuppressed findings at or above the --fail-on severity (default: critical or high)"},
	{4, "incomplete coverage: a check could not observe enough to decide"},
	{5, "internal error, a check ended with an error, or the scan was interrupted"},
	{6, "the report could not be written"},
}

func noArgs(name string, fn func()) func(context.Context, []string) error {
	return func(_ context.Context, args []string) error {
		if len(args) > 0 {
			return usageErr("%s takes no arguments", name)
		}
		fn()
		return nil
	}
}

var commands []command

func init() {
	commands = []command{
		{Name: "scan", Args: "[flags]", Summary: "Assess this machine and write a local report",
			Flags: func() *flag.FlagSet { return scanFlagSet(&scanFlags{}) }, Run: cmdScan},
		{Name: "demo", Args: "[vulnerable|hardened|practice] [flags]", Summary: "Scan the built-in simulated lab (practice needs --seed S)",
			Flags:  func() *flag.FlagSet { var a, b string; return demoFlagSet(&scanFlags{}, &a, &b) },
			Values: []string{"vulnerable", "hardened", "practice"}, Run: cmdDemo},
		{Name: "checks", Aliases: []string{"list"}, Args: "[--json]", Summary: "List every check",
			Flags: func() *flag.FlagSet { var b bool; return checksFlagSet(&b) },
			Run:   func(_ context.Context, a []string) error { return cmdChecks(a) }},
		{Name: "explain", Args: "<CHECK-ID>", Summary: "Show what a check does, why, how to fix it",
			Run: func(_ context.Context, a []string) error { return cmdExplain(a) }},
		{Name: "learn", Aliases: []string{"academy"}, Args: "[MODULE] [--quiz]", Summary: "OpenVAPT Academy: learn VAPT from theory to application",
			Flags: func() *flag.FlagSet { var b bool; var s string; return learnFlagSet(&b, &s) },
			Run:   func(_ context.Context, a []string) error { return cmdLearn(a) }},
		{Name: "teach", Args: "<SUBCOMMAND>", Summary: "Teacher toolkit: course plans, worksheets, rubric, practice lab keys",
			Subs: []command{
				{Name: "courses", Summary: "List ready-made course plans"},
				{Name: "course", Args: "<ID>", Summary: "Print a course plan (Markdown)"},
				{Name: "worksheet", Args: "<MODULE> [--answers] [--out FILE]", Summary: "Printable worksheet, or the teacher answer key",
					Flags: func() *flag.FlagSet { var b bool; var s string; return worksheetFlagSet(&b, &s) }},
				{Name: "rubric", Summary: "Marking rubric for an assessment report"},
				{Name: "answers", Args: "--seed <SEED> [--only ..] [--skip ..]", Summary: "Answer key for a student's practice lab",
					Flags: func() *flag.FlagSet { var a, b, c string; return answersFlagSet(&a, &b, &c) }},
			},
			Run: cmdTeach},
		{Name: "diff", Args: "<old.json> <new.json>", Summary: "Compare two reports (what was fixed, what is new)",
			Run: func(_ context.Context, a []string) error { return cmdDiff(a) }},
		{Name: "verify", Args: "<report.json> [--key-id ID]", Summary: "Confirm a signed report was not edited",
			Flags: func() *flag.FlagSet { var s string; return verifyFlagSet(&s) },
			Run:   func(_ context.Context, a []string) error { return cmdVerify(a) }},
		{Name: "vulndb", Summary: "Show offline snapshot details", Run: func(_ context.Context, a []string) error {
			if len(a) > 0 {
				return usageErr("vulndb takes no arguments")
			}
			return cmdVulndb()
		}},
		{Name: "cite", Args: "[--format F] [--check ID] [--module ID]", Summary: "Print how to cite this exact version (APA, BibTeX and more)", Flags: func() *flag.FlagSet { var a, b, c string; return citeFlagSet(&a, &b, &c) }, Run: cmdCite},
		{Name: "terms", Summary: "Print the terms of use and acknowledgements", Run: noArgs("terms", func() { fmt.Print(termsText()) })},
		{Name: "version", Aliases: []string{"--version", "-v"}, Summary: "Print version information", Run: noArgs("version", cmdVersion)},
		{Name: "man", Summary: "Print the manual page (roff), for example openvapt man > openvapt.1", Run: noArgs("man", func() { fmt.Print(manPage()) })},
		{Name: "completion", Args: "bash|zsh|fish", Summary: "Print a shell completion script", Values: []string{"bash", "zsh", "fish"}, Run: cmdCompletion},
		{Name: "help", Aliases: []string{"-h", "--help"}, Summary: "Show this help", Run: func(context.Context, []string) error { usage(os.Stdout); return nil }},
	}
}

// lookup finds a command by name or alias.
func lookup(name string) *command {
	for i := range commands {
		if commands[i].Name == name {
			return &commands[i]
		}
		for _, a := range commands[i].Aliases {
			if a == name {
				return &commands[i]
			}
		}
	}
	return nil
}
