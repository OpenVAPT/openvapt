// Command channel runs OpenVAPT's release channel gates. It is used by the
// promote workflow (.github/workflows/promote.yml) and can be run locally to
// see where every channel stands:
//
//	go run ./cmd/channel status
//	go run ./cmd/channel head
//	go run ./cmd/channel plan    --head <sha> [--signed v0.1.0-beta.1,...]
//	go run ./cmd/channel notes
//	go run ./cmd/channel promote <channel> --commit <sha> --ci-green --lab-pass [--installer-e2e] [--signed ...]
//
// head prints the newest commit that changed a build file: a commit that only
// records a promotion (release/, CITATION.cff, CHANGELOG.md) is never a new
// build. plan picks the most mature channel whose time, legal and history
// gates pass, assuming the candidate build will pass verification. The
// workflow then verifies that exact commit and calls promote with the real
// evidence; promote evaluates every gate again and refuses if any fails.
// notes prints the CHANGELOG.md [Unreleased] section as release notes.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/channels"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	state := fs.String("state", "release/channels.json", "channel state file")
	legal := fs.String("legal", "release/legal-review.json", "AI legal review record")
	text := fs.String("text", "release/channels.txt", "plain channel list for the installer")
	citation := fs.String("citation", "CITATION.cff", "citation file whose version follows the most advanced release")
	changelog := fs.String("changelog", "CHANGELOG.md", "changelog whose [Unreleased] section becomes the released version's section")
	head := fs.String("head", "", "commit at the tip of main (plan)")
	commit := fs.String("commit", "", "commit that was verified (promote)")
	ci := fs.Bool("ci-green", false, "CI passed on the commit")
	lab := fs.Bool("lab-pass", false, "lab tests passed on the commit")
	inst := fs.Bool("installer-e2e", false, "installer end-to-end test passed")
	signed := fs.String("signed", "", "comma-separated release versions verified to carry signatures, provenance and SBOM")
	today := fs.String("today", "", "override today's date (YYYY-MM-DD), for tests")
	expect := fs.String("version", "", "the version the plan published; promote refuses if it would record another")

	var target string
	if cmd == "promote" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	s, err := channels.Load(*state)
	must(err)
	now := time.Now().UTC()
	if *today != "" {
		now, err = time.Parse("2006-01-02", *today)
		must(err)
	}
	lr, lerr := channels.LoadLegal(*legal)
	signedSet := map[string]bool{}
	for _, v := range strings.Split(*signed, ",") {
		if v = strings.TrimSpace(v); channels.Of(v) != channels.Dev {
			signedSet[v] = true
		}
	}
	evidence := func(c channels.Channel, commit string, ci, lab, inst bool) channels.Evidence {
		e := channels.Evidence{Commit: commit, CIGreen: ci, LabPass: lab, InstallerE2E: inst, Legal: lr, LegalErr: lerr, Now: now}
		if p := channels.Previous(c); p != "" {
			e.Signed = signedSet[s.Current[p].Version]
		}
		return e
	}

	switch cmd {
	case "head":
		h, err := gitHead(".")
		must(err)
		output("head", h)
		return
	case "notes":
		b, err := os.ReadFile(*changelog) // #nosec G304 -- fixed repository file chosen by the operator
		must(err)
		fmt.Println(releaseNotes(string(b)))
		return
	case "status":
		fmt.Printf("Next stable: %s\n", s.Next)
		for _, c := range channels.Order {
			info := channels.InfoFor(c)
			if r, ok := s.Current[c]; ok {
				fmt.Printf("%-18s %-16s %s  %s\n", info.Name, r.Version, r.Date, r.Commit[:min(12, len(r.Commit))])
			} else {
				fmt.Printf("%-18s %s\n", info.Name, "not released yet")
			}
		}
	case "plan":
		// Most mature first, so a build moves up as soon as it may.
		for i := len(channels.Order) - 1; i >= 0; i-- {
			c := channels.Order[i]
			cand := *head
			if p := channels.Previous(c); p != "" {
				cand = s.Current[p].Commit
			}
			ok, checks := channels.Gate(s, c, evidence(c, cand, true, true, true))
			fmt.Fprintf(os.Stderr, "%s: %v\n", c, summary(checks))
			if ok && cand != "" {
				output("target", string(c))
				output("commit", cand)
				output("version", s.NextVersion(c))
				output("prerelease", fmt.Sprint(c != channels.Stable))
				return
			}
		}
		output("target", "")
		fmt.Fprintln(os.Stderr, "No channel is ready for promotion.")
	case "promote":
		c := channels.Channel(target)
		if channels.InfoFor(c).SoakDays == 0 && c != channels.Alpha {
			die("unknown channel %q", target)
		}
		if !commitRe.MatchString(*commit) {
			die("--commit must be the full 40-character commit that was verified")
		}
		if *expect != "" && s.NextVersion(c) != *expect {
			die("the record would be %s but the plan published %s; nothing was promoted", s.NextVersion(c), *expect)
		}
		ok, checks := channels.Gate(s, c, evidence(c, *commit, *ci, *lab, *inst))
		for _, x := range checks {
			mark := "PASS"
			if !x.Passed {
				mark = "FAIL"
			}
			fmt.Printf("%s  %s: %s\n", mark, x.Name, x.Detail)
		}
		if !ok {
			die("gate for %s failed; nothing was promoted", c)
		}
		r := s.Promote(c, evidence(c, *commit, *ci, *lab, *inst), checks)
		must(s.Save(*state))
		must(os.WriteFile(*text, []byte(s.Text()), 0o644)) // #nosec G306 -- public release list
		must(updateCitation(*citation, s))
		note := "No changelog entry was written for this build (commit " + r.Commit[:min(12, len(r.Commit))] + ")."
		if p := channels.Previous(c); p != "" {
			note = "Same build as " + s.Current[p].Version + " (commit " + r.Commit[:min(12, len(r.Commit))] + "), promoted to " + channels.InfoFor(c).Name + "."
		}
		must(updateChangelog(*changelog, r.Version, r.Date, note))
		fmt.Printf("Promoted %s to %s (%s)\n", r.Commit, channels.InfoFor(c).Name, r.Version)
	default:
		usage()
	}
}

// updateCitation points CITATION.cff at the most advanced current release
// (stable, then rc, beta, alpha), so academic citations name a real version.
// internal/sources tests enforce the same rule.
func updateCitation(path string, s *channels.State) error {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed repository file chosen by the operator
	if err != nil {
		return err
	}
	for _, c := range []channels.Channel{channels.Stable, channels.RC, channels.Beta, channels.Alpha} {
		r, ok := s.Current[c]
		if !ok {
			continue
		}
		if !citationVersion.Match(b) {
			return fmt.Errorf("%s has no version: line to update", path)
		}
		if !citationDate.Match(b) {
			return fmt.Errorf("%s has no date-released: line to update", path)
		}
		out := citationVersion.ReplaceAllString(string(b), `version: "`+strings.TrimPrefix(r.Version, "v")+`"`)
		out = citationDate.ReplaceAllString(out, `date-released: "`+r.Date+`"`)
		return os.WriteFile(path, []byte(out), 0o644) // #nosec G306 -- public citation file
	}
	return nil
}

var (
	citationVersion = regexp.MustCompile(`(?m)^version: "[^"]*"`)
	citationDate    = regexp.MustCompile(`(?m)^date-released: "[^"]*"`)
)

func summary(cs []channels.Check) string {
	var failed []string
	for _, c := range cs {
		if !c.Passed {
			failed = append(failed, c.Name+" ("+c.Detail+")")
		}
	}
	if len(failed) == 0 {
		return "ready"
	}
	return "blocked by " + strings.Join(failed, "; ")
}

var (
	commitRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	safeValue = regexp.MustCompile(`^[A-Za-z0-9.\-]*$`)
)

// output prints key=value and appends it to $GITHUB_OUTPUT when set. Values
// are restricted to versions, channel names and commit hashes, so nothing
// read from the repository can inject extra workflow outputs.
func output(k, v string) {
	if !safeValue.MatchString(v) {
		die("refusing unsafe output %s=%q", k, v)
	}
	fmt.Printf("%s=%s\n", k, v)
	if p := os.Getenv("GITHUB_OUTPUT"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- path provided by GitHub Actions
		must(err)
		defer f.Close()
		_, err = fmt.Fprintf(f, "%s=%s\n", k, v)
		must(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: channel status | head | notes | plan --head <sha> | promote <alpha|beta|rc|stable> --commit <sha> [evidence flags]")
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		die("%v", err)
	}
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "channel: "+f+"\n", a...)
	os.Exit(1)
}
