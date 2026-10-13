// Package academy is the OpenVAPT learning path: a bottom-up course that
// starts with security theory and ends with running, fixing, reporting and
// building checks. The command line tool ("openvapt learn") and the website
// both read from here, so the course is identical online and offline.
//
// Each module links theory to application through RelatedChecks: the real
// OpenVAPT checks that put the module's ideas into practice.
package academy

import "strings"

// Level groups modules from first principles to hands-on practice.
type Level string

const (
	Foundation   Level = "Foundations"
	Practitioner Level = "Practitioner"
	Applied      Level = "Applied"
)

// Section is one titled block of theory.
type Section struct {
	Heading string
	Body    []string // paragraphs
}

// Question is a self-check quiz question. Answers are checked in the reader's
// browser or terminal and never stored or sent anywhere.
type Question struct {
	Q       string
	Options []string
	Answer  int // index into Options
	Explain string
}

// Ref is a public source for further reading.
type Ref struct {
	Title, URL string
}

// Module is one lesson.
type Module struct {
	ID            string
	Title         string
	Level         Level
	Minutes       int
	Summary       string
	Objectives    []string
	Sections      []Section
	KeyTerms      []string // glossary term names
	RelatedChecks []string // check ids or prefixes (e.g. "HOST-SSH-")
	Lab           []string // steps using the simulated lab or a dry run
	Quiz          []Question
	Refs          []Ref
}

// Get returns a module by id (case-insensitive), or nil.
func Get(id string) *Module {
	for i := range Modules {
		if strings.EqualFold(Modules[i].ID, id) {
			return &Modules[i]
		}
	}
	return nil
}

// ForCheck returns the modules whose RelatedChecks cover a check id.
func ForCheck(checkID string) []*Module {
	var out []*Module
	for i := range Modules {
		for _, r := range Modules[i].RelatedChecks {
			if checkID == r || (strings.HasSuffix(r, "-") && strings.HasPrefix(checkID, r)) {
				out = append(out, &Modules[i])
				break
			}
		}
	}
	return out
}

// Levels returns the levels in teaching order.
func Levels() []Level { return []Level{Foundation, Practitioner, Applied} }

// ByLevel returns the modules of one level in order.
func ByLevel(l Level) []*Module {
	var out []*Module
	for i := range Modules {
		if Modules[i].Level == l {
			out = append(out, &Modules[i])
		}
	}
	return out
}
