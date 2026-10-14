package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/report"
)

// every command, alias, subcommand and flag of the command table.
func everyWord() (cmds, flags []string) {
	for _, c := range commands {
		cmds = append(cmds, c.Name)
		for _, a := range c.Aliases {
			if !strings.HasPrefix(a, "-") {
				cmds = append(cmds, a)
			}
		}
		fss := []func() *flag.FlagSet{c.Flags}
		for _, s := range c.Subs {
			cmds = append(cmds, s.Name)
			fss = append(fss, s.Flags)
		}
		for _, fs := range fss {
			if fs != nil {
				fs().VisitAll(func(f *flag.Flag) { flags = append(flags, f.Name) })
			}
		}
	}
	return
}

func TestCompletionCoversEverything(t *testing.T) {
	cmds, flags := everyWord()
	for _, sh := range []string{"bash", "zsh", "fish"} {
		s, err := completionScript(sh)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cmds {
			if !strings.Contains(s, c) {
				t.Errorf("%s completion lacks command %q", sh, c)
			}
		}
		for _, f := range flags {
			want := "--" + f
			if sh == "fish" {
				want = "-l " + f
			}
			if !strings.Contains(s, want) {
				t.Errorf("%s completion lacks flag %q", sh, f)
			}
		}
	}
	if _, err := completionScript("tcsh"); err == nil {
		t.Error("unknown shell accepted")
	}
}

func TestManPageCoversEverything(t *testing.T) {
	m := manPage()
	cmds, flags := everyWord()
	for _, c := range cmds {
		if !strings.Contains(m, roff(c)) {
			t.Errorf("man page lacks command %q", c)
		}
	}
	for _, f := range flags {
		if !strings.Contains(m, roff("--"+f)) {
			t.Errorf("man page lacks flag %q", f)
		}
	}
	for _, sec := range []string{".SH EXIT STATUS", ".SH FILES", ".SH SEE ALSO", ".SH ACKNOWLEDGEMENT", ".SH SUPPRESSIONS"} {
		if !strings.Contains(m, sec) {
			t.Errorf("man page lacks %s", sec)
		}
	}
	for _, e := range exitCodes {
		if !strings.Contains(m, fmt.Sprintf(".B %d\n", e.Code)) {
			t.Errorf("man page lacks exit code %d", e.Code)
		}
	}
}

func TestHelpListsEveryCommandAndExitCode(t *testing.T) {
	var b bytes.Buffer
	usage(&b)
	for _, c := range commands {
		if !strings.Contains(b.String(), "openvapt "+c.Name) {
			t.Errorf("help lacks %q", c.Name)
		}
	}
	for _, e := range exitCodes {
		if !strings.Contains(b.String(), fmt.Sprintf("  %d  %s", e.Code, e.Meaning)) {
			t.Errorf("help lacks exit code %d", e.Code)
		}
	}
}

// The README exit code table must list exactly the codes the CLI documents.
func TestReadmeExitCodesMatch(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, line := range strings.Split(string(b), "\n") {
		if len(line) > 4 && line[0] == '|' && line[2] >= '0' && line[2] <= '9' && line[3] == ' ' {
			got = append(got, line[2:3])
		}
	}
	var want []string
	for _, e := range exitCodes {
		want = append(want, fmt.Sprint(e.Code))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("README exit codes %v, CLI %v", got, want)
	}
	for _, f := range []string{"--suppress", "openvapt man", "openvapt completion"} {
		if !strings.Contains(string(b), f) {
			t.Errorf("README lacks %s", f)
		}
	}
}

func TestEveryCommandDispatches(t *testing.T) {
	for _, c := range commands {
		if c.Run == nil || lookup(c.Name) == nil {
			t.Errorf("command %q has no handler", c.Name)
		}
	}
	if lookup("nope") != nil {
		t.Error("unknown command found")
	}
}

// A fully suppressed finding never returns exit 3; a partly suppressed one does.
func TestExitCodeIgnoresSuppressed(t *testing.T) {
	f := report.Finding{ID: "HOST-SSH-005", Severity: "critical", Status: string(check.Fail),
		Results: []check.Result{{Status: check.Fail, Target: "a"}, {Status: check.Fail, Target: "b"}}}
	full := f
	full.Suppressed = []report.Suppressed{{Target: "a"}, {Target: "b"}}
	if c, _ := exitCode(rep(full), check.High); c != 0 {
		t.Errorf("fully suppressed: exit %d", c)
	}
	part := f
	part.Suppressed = []report.Suppressed{{Target: "a"}}
	if c, _ := exitCode(rep(part), check.High); c != 3 {
		t.Errorf("partly suppressed: exit %d", c)
	}
	inc := full
	if c, _ := exitCode(rep(inc, fnd("low", check.Incomplete)), check.High); c != 4 {
		t.Errorf("suppression hid a coverage gap: exit %d", c)
	}
}

func TestSuppressFlagRejectsBadFile(t *testing.T) {
	p := t.TempDir() + "/s.json"
	if err := os.WriteFile(p, []byte(`[{"id":"HOST-SSH-005","expires":"2027-01-01"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := scanFlags{formats: "json", suppress: p}
	err := f.prepare()
	var ee *exitError
	if err == nil || !errors.As(err, &ee) || ee.code != 2 {
		t.Fatalf("missing reason: %v", err)
	}
}
