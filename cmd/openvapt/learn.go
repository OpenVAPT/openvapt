package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
)

// cmdLearn is the offline OpenVAPT Academy: it lists the course, prints a
// module, runs a module's self-check quiz, or looks up a glossary term.
// Quiz answers are checked in memory and never stored.
func cmdLearn(args []string) error {
	fs := flag.NewFlagSet("learn", flag.ExitOnError)
	quiz := fs.Bool("quiz", false, "run the module's self-check quiz")
	term := fs.String("term", "", "look up a glossary term")
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if id == "" {
		id = fs.Arg(0)
	}

	if *term != "" {
		for _, t := range academy.Terms() {
			if strings.EqualFold(t, *term) {
				fmt.Printf("%s\n  %s\n", t, academy.Glossary[t])
				return nil
			}
		}
		return fmt.Errorf("no glossary entry for %q (try 'openvapt learn glossary')", *term)
	}
	switch strings.ToLower(id) {
	case "":
		printCourse()
		return nil
	case "glossary":
		for _, t := range academy.Terms() {
			fmt.Printf("%-26s %s\n", t, academy.Glossary[t])
		}
		return nil
	}
	m := academy.Get(id)
	if m == nil {
		return fmt.Errorf("no module %q (run 'openvapt learn' for the course)", id)
	}
	if *quiz {
		return runQuiz(m)
	}
	printModule(m)
	return nil
}

func printCourse() {
	fmt.Println("OpenVAPT Academy: learn vulnerability assessment from theory to application.")
	fmt.Println("Free, offline, nothing stored. Also online at https://openvapt.com/academy/")
	for _, l := range academy.Levels() {
		fmt.Printf("\n%s\n", l)
		for _, m := range academy.ByLevel(l) {
			fmt.Printf("  %-3s %-45s %d min\n", m.ID, m.Title, m.Minutes)
		}
	}
	fmt.Println("\nRead a module:  openvapt learn F1")
	fmt.Println("Take its quiz:  openvapt learn F1 --quiz")
	fmt.Println("Glossary:       openvapt learn glossary   or   openvapt learn --term CVSS")
}

func printModule(m *academy.Module) {
	fmt.Printf("%s  %s  (%s, about %d minutes)\n\n%s\n", m.ID, m.Title, m.Level, m.Minutes, m.Summary)
	fmt.Println("\nYou will be able to:")
	for _, o := range m.Objectives {
		fmt.Println("  - " + o)
	}
	for _, s := range m.Sections {
		fmt.Printf("\n%s\n", strings.ToUpper(s.Heading))
		for _, p := range s.Body {
			fmt.Println(wrap(p, 78, "  "))
		}
	}
	if len(m.KeyTerms) > 0 {
		fmt.Printf("\nKEY TERMS\n  %s\n", strings.Join(m.KeyTerms, ", "))
	}
	if len(m.RelatedChecks) > 0 {
		fmt.Println("\nAPPLY IT: OPENVAPT CHECKS FOR THIS MODULE")
		for _, c := range check.All() {
			for _, r := range m.RelatedChecks {
				if c.ID == r || (strings.HasSuffix(r, "-") && strings.HasPrefix(c.ID, r)) {
					fmt.Printf("  %-13s %s\n", c.ID, c.Title)
					break
				}
			}
		}
	}
	fmt.Println("\nLAB")
	for i, s := range m.Lab {
		fmt.Printf("  %d. %s\n", i+1, s)
	}
	fmt.Println("\nREFERENCES")
	for _, r := range m.Refs {
		fmt.Printf("  - %s\n    %s\n", r.Title, r.URL)
	}
	fmt.Printf("\nTest yourself: openvapt learn %s --quiz\n", m.ID)
}

func runQuiz(m *academy.Module) error {
	in := bufio.NewReader(os.Stdin)
	score := 0
	fmt.Printf("%s quiz: %d questions. Answers are checked here and never stored.\n", m.Title, len(m.Quiz))
	for i, q := range m.Quiz {
		fmt.Printf("\n%d. %s\n", i+1, q.Q)
		for j, o := range q.Options {
			fmt.Printf("   %d) %s\n", j+1, o)
		}
		fmt.Print("Your answer: ")
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return errors.New("quiz cancelled")
		}
		n, _ := strconv.Atoi(strings.TrimSpace(line))
		if n-1 == q.Answer {
			score++
			fmt.Println("Correct. " + q.Explain)
		} else {
			fmt.Printf("Not quite. The answer is %d) %s. %s\n", q.Answer+1, q.Options[q.Answer], q.Explain)
		}
	}
	fmt.Printf("\nScore: %d of %d. Re-read the module with: openvapt learn %s\n", score, len(m.Quiz), m.ID)
	return nil
}

// wrap word-wraps a paragraph to width with an indent.
func wrap(s string, width int, indent string) string {
	var b strings.Builder
	line := indent
	for _, w := range strings.Fields(s) {
		if len(line)+len(w)+1 > width && strings.TrimSpace(line) != "" {
			b.WriteString(line + "\n")
			line = indent
		}
		if strings.TrimSpace(line) != "" {
			line += " "
		}
		line += w
	}
	b.WriteString(line)
	return b.String()
}
