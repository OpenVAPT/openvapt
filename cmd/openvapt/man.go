package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/terms"
	"github.com/openvapt/openvapt/internal/version"
)

// roff escapes text for a man page: backslashes, and a leading dot or
// apostrophe that roff would read as a request.
func roff(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	s = strings.ReplaceAll(s, "-", `\-`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// flagLine is the synopsis of one flag: --name VALUE, or --name for a switch.
func flagLine(f *flag.Flag) string {
	if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
		return "--" + f.Name
	}
	name, _ := flag.UnquoteUsage(f)
	if name == "" {
		name = "value"
	}
	return "--" + f.Name + " " + strings.ToUpper(name)
}

func manFlags(b *strings.Builder, fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		fmt.Fprintf(b, ".TP\n.B %s\n%s", roff(flagLine(f)), roff(f.Usage))
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" {
			fmt.Fprintf(b, " (default: %s)", roff(f.DefValue))
		}
		b.WriteString("\n")
	})
}

// manPage renders openvapt(1) from the command table, the real flag sets
// and the exit code table, so it cannot drift from the code.
func manPage() string {
	var b strings.Builder
	fmt.Fprintf(&b, ".TH OPENVAPT 1 \"\" \"OpenVAPT %s\" \"User Commands\"\n", roff(version.Version))
	b.WriteString(".SH NAME\nopenvapt \\- academic, read\\-only vulnerability self\\-assessment of this machine only\n")
	b.WriteString(".SH SYNOPSIS\n")
	for _, c := range commands {
		if c.Hidden || strings.HasPrefix(c.Name, "-") {
			continue
		}
		fmt.Fprintf(&b, ".B openvapt %s\n", roff(c.Name))
		if c.Args != "" {
			fmt.Fprintf(&b, "%s\n", roff(c.Args))
		}
		b.WriteString(".br\n")
	}
	b.WriteString(".SH DESCRIPTION\nOpenVAPT runs automated, read\\-only checks against the machine it runs on and writes a local report in HTML, JSON, SARIF and Markdown. Every network connection is restricted in code to loopback addresses. No exploitation is attempted and no data is sent anywhere. It is not a penetration test, an audit or a certification, and absence of findings is not proof of security.\n")
	b.WriteString(".SH COMMANDS\n")
	for _, c := range commands {
		if c.Hidden {
			continue
		}
		head := c.Name
		if len(c.Aliases) > 0 {
			head += " (also " + strings.Join(c.Aliases, ", ") + ")"
		}
		fmt.Fprintf(&b, ".SS %s\n%s.\n", roff(head), roff(c.Summary))
		if c.Args != "" {
			fmt.Fprintf(&b, ".PP\nUsage: \\fBopenvapt %s\\fR %s\n", roff(c.Name), roff(c.Args))
		}
		if c.Flags != nil {
			manFlags(&b, c.Flags())
		}
		for _, s := range c.Subs {
			fmt.Fprintf(&b, ".TP\n.B %s %s\n%s.\n", roff(s.Name), roff(s.Args), roff(s.Summary))
			if s.Flags != nil {
				b.WriteString(".RS\n")
				manFlags(&b, s.Flags())
				b.WriteString(".RE\n")
			}
		}
	}
	b.WriteString(".SH SUPPRESSIONS\n")
	b.WriteString(roff("--suppress FILE reads a JSON list of entries, each with id (a check id), optional target (exact or a glob), reason (required), expires (required, YYYY-MM-DD, at most 365 days ahead) and optional added_by. A malformed file, an unknown check id or a missing reason or expiry is a usage error. Expired entries are ignored with a warning. Suppressed findings keep their status in every report format, are listed under Suppressed Findings, are marked in SARIF with an external suppression, and do not count toward --fail-on. The report header states how many results were suppressed and the file's sha256. No suppression file is ever loaded unless named.") + "\n")
	b.WriteString(".SH EXIT STATUS\nChecked in order 5, 4, 3, so 0 means every selected check reached a verdict.\n")
	for _, e := range exitCodes {
		fmt.Fprintf(&b, ".TP\n.B %d\n%s\n", e.Code, roff(e.Meaning))
	}
	b.WriteString(".SH FILES\n")
	b.WriteString(".TP\n.I ~/openvapt\\-reports/YYYYMMDDTHHMMSSZ/\nDefault report folder of openvapt scan without \\-\\-out: a new folder named after the UTC time under the home folder named by HOME (under sudo usually root's; when sudo keeps the invoking user's HOME and it is that user's home folder in the user database, the folder and reports are given to that user), mode 0700, never reused; report.html, report.json, report.sarif and report.md inside it are mode 0600.\n")
	b.WriteString(".TP\n.I openvapt\\-demo\\-report\\-YYYYMMDD\\-HHMMSS\\-*/\nDefault report folder of openvapt demo without \\-\\-out, in the current directory (mode 0700).\n")
	b.WriteString(".TP\n.I /usr/bin/xdg\\-open\nStarted only with \\-\\-open, only in a desktop session (DISPLAY or WAYLAND_DISPLAY set), never as root, and only with the report.html the same run wrote. It is the one program OpenVAPT may start outside its read\\-only command allow\\-list.\n")
	b.WriteString(".TP\n.I ~/.config/openvapt/report\\-key\nLocal Ed25519 report signing key (under the user configuration folder), created on first signed report (see openvapt verify).\n")
	b.WriteString(".TP\n.I suppress.json\nOptional suppression file named with \\-\\-suppress; never loaded automatically. A sample is docs/suppress.sample.json in the source.\n")
	b.WriteString(".SH ACKNOWLEDGEMENT\n")
	b.WriteString(roff(terms.Tagline) + "\n.PP\nA scan asks you to read and accept every acknowledgement in \\fBopenvapt terms\\fR (or \\-\\-accept\\-terms for automation). By using OpenVAPT you confirm each of them:\n")
	for i, a := range terms.Acknowledgements {
		fmt.Fprintf(&b, ".TP\n%d.\n%s\n", i+1, roff(a))
	}
	b.WriteString(".SH SEE ALSO\n")
	b.WriteString("Full terms: https://openvapt.com/legal/eula.html\n.br\nChecks: https://openvapt.com/checks/\n.br\nCiting: https://openvapt.com/cite.html\n.br\nNIST SP 800\\-115, Technical Guide to Information Security Testing and Assessment.\n")
	return b.String()
}
