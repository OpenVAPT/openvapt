package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/engine"
)

// cmdTeach is the teacher's toolkit: course plans, printable worksheets and
// answer keys, the marking rubric, and seeded practice labs with answer
// keys. Everything runs offline; practice labs are simulated in memory.
// What teachers may do is set by TEACHING.md.
func cmdTeach(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Print(`openvapt teach: tools for teachers (see TEACHING.md for what teaching allows)

  openvapt teach courses                      list ready-made course plans
  openvapt teach course <ID>                  print a course plan (Markdown)
  openvapt teach worksheet <MODULE> [--answers] [--out FILE]
                                              printable worksheet, or the teacher answer key
  openvapt teach rubric                       marking rubric for an assessment report
  openvapt teach answers --seed <SEED> [--only ..] [--skip ..]
                                              answer key for a student's practice lab

Students scan their own practice lab with:
  openvapt demo --lab practice --seed <SEED>
Each seed (for example a student number) gives a different simulated server.
Any student can print the answer key for any seed, so practice labs are
learning exercises, not secure exams. Free teaching use under TEACHING.md;
pre-release, used 100% at your own risk.

Citing: credit OpenVAPT in anything you copy or adapt (licence section 5.4),
and please cite it in handouts, slides and course pages. Copy a citation from
https://openvapt.com/cite.html, or read CITING.md.
`)
		return nil
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "courses":
		for _, c := range academy.Courses {
			fmt.Printf("%-12s %s (%s)\n             %s\n", c.ID, c.Title, c.Hours, c.Audience)
		}
	case "course":
		if len(rest) == 0 || academy.CourseByID(rest[0]) == nil {
			return usageErr("usage: openvapt teach course <ID>; see openvapt teach courses")
		}
		fmt.Print(courseMarkdown(academy.CourseByID(rest[0])))
	case "worksheet":
		if len(rest) == 0 || academy.Get(rest[0]) == nil {
			return usageErr("usage: openvapt teach worksheet <MODULE> [--answers] [--out FILE]; modules: openvapt learn")
		}
		var answersV bool
		var outV string
		answers, out := &answersV, &outV
		fs := worksheetFlagSet(answers, out)
		_ = fs.Parse(rest[1:])
		text := academy.Worksheet(academy.Get(rest[0]), *answers)
		if *out == "" {
			fmt.Print(text)
			return nil
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path chosen by the user; never overwrites
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(text)
		if err == nil {
			fmt.Println("Wrote", *out)
		}
		return err
	case "rubric":
		fmt.Print(rubricMarkdown())
	case "answers":
		var seedV, onlyV, skipV string
		seed, only, skip := &seedV, &onlyV, &skipV
		fs := answersFlagSet(seed, only, skip)
		_ = fs.Parse(rest)
		if strings.TrimSpace(*seed) == "" {
			return usageErr("usage: openvapt teach answers --seed <SEED>")
		}
		as := engine.Answers(ctx, *seed, engine.Options{Only: splitList(*only), Skip: splitList(*skip)})
		fmt.Printf("# Answer Key: Practice Lab, Seed %q\n\n%d weaknesses are planted in this simulated lab. A complete student report finds each one, rates it and gives a verified fix. Any student can print this key for any seed, so use it for learning exercises, not secure exams.\n\n| ID | Severity | Category | Weakness |\n|---|---|---|---|\n", *seed, len(as))
		for _, a := range as {
			fmt.Printf("| %s | %s | %s | %s |\n", a.ID, a.Severity, a.Category, a.Title)
		}
	default:
		return usageErr("unknown teach command %q; run openvapt teach", sub)
	}
	return nil
}

func courseMarkdown(c *academy.Course) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\n- Audience: %s\n- Time: %s\n\n| Week | Topic | Academy Modules | Activity |\n|---|---|---|---|\n", c.Title, c.Summary, c.Audience, c.Hours)
	for _, s := range c.Sessions {
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", s.Week, s.Topic, strings.Join(s.Modules, ", "), s.Activity)
	}
	b.WriteString("\nWorksheets: openvapt teach worksheet <MODULE>. Practice labs: openvapt demo --lab practice --seed <SEED>. Free teaching use under TEACHING.md. OpenVAPT is not affiliated with, and is not endorsed by, this institution or any third party named in this material. Pre-release versions may be wrong or unstable. Use at your own risk.\n")
	return b.String()
}

func rubricMarkdown() string {
	var b strings.Builder
	b.WriteString("# Assessment Report Rubric\n\nStructured after the reporting guidance of NIST SP 800-115. NIST does not endorse OpenVAPT or this rubric. Free teaching use under TEACHING.md; pre-release, used 100% at your own risk.\n\n| Criterion | Weight |")
	for _, l := range academy.RubricLevels {
		b.WriteString(" " + l + " |")
	}
	b.WriteString("\n|---|---|---|---|---|---|\n")
	for _, r := range academy.Rubric {
		fmt.Fprintf(&b, "| %s | %d%% | %s |\n", r.Name, r.Weight, strings.Join(r.Levels[:], " | "))
	}
	return b.String()
}

// usageErr reports invalid arguments with exit code 2.
func worksheetFlagSet(answers *bool, out *string) *flag.FlagSet {
	fs := flag.NewFlagSet("worksheet", flag.ExitOnError)
	fs.BoolVar(answers, "answers", false, "print the teacher answer key")
	fs.StringVar(out, "out", "", "write to this file instead of the terminal")
	return fs
}

func answersFlagSet(seed, only, skip *string) *flag.FlagSet {
	fs := flag.NewFlagSet("answers", flag.ExitOnError)
	fs.StringVar(seed, "seed", "", "the seed the student used (for example their student number)")
	fs.StringVar(only, "only", "", "the same --only the student used, if any")
	fs.StringVar(skip, "skip", "", "the same --skip the student used, if any")
	return fs
}

func usageErr(f string, a ...any) error {
	return &exitError{code: 2, err: fmt.Errorf(f, a...)}
}
