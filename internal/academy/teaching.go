package academy

import (
	"fmt"
	"strings"
)

// Teaching material: course plans, an assessment rubric and printable
// worksheets with teacher answer keys. The website and "openvapt teach"
// both read from here. What teachers may do is set by TEACHING.md.

// Session is one class session in a course plan.
type Session struct {
	Week     int
	Topic    string
	Modules  []string // Academy module ids
	Activity string   // what students do in class or as homework
}

// Course is a ready-made plan a teacher can adopt or adapt.
type Course struct {
	ID       string
	Title    string
	Audience string
	Hours    string
	Summary  string
	Sessions []Session
}

// Courses lists the ready-made plans, shortest first.
var Courses = []Course{
	{
		ID: "intro-4", Title: "Four-Week Introduction to Vulnerability Assessment", Audience: "Diploma, first-year degree or upper secondary students with basic Linux (students under 18 need a parent's or guardian's acceptance before downloading)", Hours: "4 Sessions of 2 Hours",
		Summary: "From what VAPT is, and the law around it, to running and reading a first assessment on the simulated lab.",
		Sessions: []Session{
			{1, "Security Basics, Ethics and the Law", []string{"F1", "F2"}, "Discuss the Computer Crimes Act 1997 and authorisation; students accept the acknowledgements personally and run openvapt demo."},
			{2, "Vulnerabilities and Ratings", []string{"F3", "P10"}, "Read three findings in the demo report and explain their CVE, CWE and CVSS."},
			{3, "Server and Network Exposure", []string{"P1", "P3"}, "Practice lab: each student scans their own seeded practice server and lists the five most serious findings."},
			{4, "Reporting", []string{"A1", "A3"}, "Write a one-page assessment report of the practice server, marked with the rubric."},
		},
	},
	{
		ID: "course-8", Title: "Eight-Week Vulnerability Assessment Course", Audience: "Degree or professional certificate students", Hours: "8 Sessions of 3 Hours",
		Summary: "A full assessment cycle: plan, discover, analyse, report, remediate and verify, across servers, networks, TLS and web applications.",
		Sessions: []Session{
			{1, "Foundations, Ethics and Scope", []string{"F1", "F2"}, "Rules of engagement exercise: write the scope and authorisation for an assessment of a school lab machine."},
			{2, "Vulnerabilities, CVE, CWE and CVSS", []string{"F3", "P10"}, "Score three findings with the CVSS v3.1 calculator and compare with OpenVAPT's vectors."},
			{3, "Linux Hardening, SSH, Access Control and Logging", []string{"P1", "P2", "P7", "P15", "P16"}, "Worksheets P1 and P15; practice lab triage of host findings, then ask what the logs would show."},
			{4, "Network Exposure, Firewalls and Data Services", []string{"P3", "P12", "P8"}, "Map listening services against firewall rules for the practice server (NET-FW-006)."},
			{5, "TLS and Web Security", []string{"P4", "P5", "P6"}, "Explain each failed web check on the practice server and its fix."},
			{6, "Services, Application Stacks and CMS", []string{"P11", "P13", "P14", "P9"}, "Write the corrected systemd unit and Tomcat settings for the vulnerable lab."},
			{7, "Remediation and Verification", []string{"A2"}, "Compare vulnerable and hardened lab reports with openvapt diff; plan remediation by effort."},
			{8, "Reporting and Presentation", []string{"A3", "A4"}, "Submit a full assessment report of the practice server, marked with the rubric; optional: design a new check."},
		},
	},
	{
		ID: "semester-14", Title: "Fourteen-Week Semester Course", Audience: "Undergraduate cyber security or IT programmes", Hours: "14 Weeks, 1 Lecture and 1 Lab Session per Week",
		Summary: "Every Academy module in depth, with weekly practice labs, a mid-semester test and a final assessment project on an institution lab machine.",
		Sessions: []Session{
			{1, "Security Basics", []string{"F1"}, "Glossary quiz; set up the institution's isolated lab virtual machines."},
			{2, "VAPT, Ethics and the Law", []string{"F2"}, "Case study discussion on unauthorised access; students accept the acknowledgements personally."},
			{3, "Vulnerabilities and Scoring", []string{"F3"}, "CVSS scoring exercise."},
			{4, "Linux Server Hardening, Logging and Time", []string{"P1", "P16"}, "Practice lab with a personal seed; list the findings an investigator would miss without logs."},
			{5, "SSH, Identity, Privilege and Access Control", []string{"P2", "P7", "P15"}, "Harden SSH on an isolated institution lab virtual machine the teacher has authorised, and verify with a targeted re-scan."},
			{6, "Network Exposure and Firewall Policy", []string{"P3", "P12"}, "Firewall rule review against listening sockets."},
			{7, "Mid-Semester Test", []string{"F1", "F2", "F3", "P1", "P2", "P3", "P7", "P12"}, "Printed worksheet questions; teacher answer keys."},
			{8, "TLS and Certificates", []string{"P4"}, "Inspect the lab's TLS findings and explain each fix."},
			{9, "Web Headers, Cookies and Exposure", []string{"P5", "P6"}, "Practice lab web findings."},
			{10, "Data Services and Containers", []string{"P8", "P9"}, "Data service configuration review."},
			{11, "Services, Application Stacks and CMS", []string{"P11", "P13", "P14"}, "Fix the vulnerable lab's systemd, Tomcat, Node.js, Django and WordPress settings on paper."},
			{12, "Vulnerability Management", []string{"P10"}, "Prioritise known exploited vulnerabilities."},
			{13, "Running, Fixing and Verifying an Assessment", []string{"A1", "A2"}, "Final project: assess an institution lab virtual machine with the teacher's authorisation."},
			{14, "Reporting and Building Checks", []string{"A3", "A4"}, "Submit the final report, marked with the rubric; present findings."},
		},
	},
}

// Criterion is one row of the assessment rubric.
type Criterion struct {
	Name   string
	Weight int       // percent
	Levels [4]string // Excellent, Good, Satisfactory, Needs Work
}

// RubricLevels names the four columns of the rubric.
var RubricLevels = [4]string{"Excellent", "Good", "Satisfactory", "Needs Work"}

// Rubric marks a student's vulnerability assessment report. Its structure
// follows the reporting guidance of NIST SP 800-115 (scope and method,
// findings with evidence and impact, remediation, limitations).
var Rubric = []Criterion{
	{"Scope, Authorisation and Method", 15, [4]string{"States the exact target, written authorisation, rules of engagement, tools, date and method.", "States target, authorisation and method with minor gaps.", "Mentions target and tool but not authorisation or method.", "No scope or authorisation."}},
	{"Findings and Evidence", 25, [4]string{"Every significant finding is described with its evidence, affected item and check id; false positives are identified and justified.", "Most findings have evidence; few errors.", "Findings listed with little evidence.", "Findings copied without evidence or understanding."}},
	{"Risk Rating and Prioritisation", 20, [4]string{"Severity and CVSS are explained and adjusted for context; findings are ordered by risk and effort.", "Severity used correctly with some context.", "Severity copied without explanation.", "No prioritisation."}},
	{"Remediation and Verification", 20, [4]string{"Each fix is specific, safe (with rollback) and paired with a verification step; quick wins identified.", "Fixes are correct but verification is partial.", "Generic fixes with no verification.", "Missing or unsafe fixes."}},
	{"Limitations and Honesty", 10, [4]string{"Clearly states what was not tested and why a clean result is not proof of security.", "States main limitations.", "Limitations mentioned briefly.", "Claims the system is secure."}},
	{"Communication", 10, [4]string{"Executive summary a manager can act on; clear structure, correct terms, cited sources.", "Clear with minor issues.", "Hard to follow in places.", "Unstructured."}},
}

// Worksheet renders a printable Markdown worksheet for a module. With
// answers, it becomes the teacher's key: correct options and explanations.
func Worksheet(m *Module, answers bool) string {
	var b strings.Builder
	kind := "Student Worksheet"
	if answers {
		kind = "Teacher Answer Key"
	}
	fmt.Fprintf(&b, "# OpenVAPT Academy %s: %s\n\n**%s** (about %d minutes, %s level)\n\nName: ______________________  Class: __________  Date: __________\n\n", m.ID, m.Title, kind, m.Minutes, m.Level)
	if len(m.Prereqs) > 0 {
		fmt.Fprintf(&b, "Read first: %s\n\n", strings.Join(m.Prereqs, ", "))
	}
	b.WriteString("## Learning Objectives\n\n")
	for _, o := range m.Objectives {
		b.WriteString("- [ ] " + o + "\n")
	}
	b.WriteString("\n## Key Terms\n\nWrite each definition in your own words.\n\n")
	for _, k := range m.KeyTerms {
		if answers {
			fmt.Fprintf(&b, "- **%s**: %s\n", k, Glossary[k])
		} else {
			fmt.Fprintf(&b, "- **%s**: ______________________________________________\n", k)
		}
	}
	b.WriteString("\n## Lab Tasks\n\nUse only the simulated lab or a machine your teacher has authorised.\n\n")
	for i, l := range m.Lab {
		fmt.Fprintf(&b, "%d. %s\n", i+1, l)
		if !answers {
			b.WriteString("   Notes: ________________________________________________\n")
		}
	}
	b.WriteString("\n## Self-Check Questions\n\n")
	for i, q := range m.Quiz {
		fmt.Fprintf(&b, "%d. %s\n", i+1, q.Q)
		for j, o := range q.Options {
			mark := "[ ]"
			if answers && j == q.Answer {
				mark = "[x]"
			}
			fmt.Fprintf(&b, "   - %s %c) %s\n", mark, 'a'+j, o)
		}
		if answers {
			fmt.Fprintf(&b, "   - Answer: %c. %s\n", 'a'+q.Answer, q.Explain)
		}
	}
	b.WriteString("\n## Reflection\n\nWhich finding from this module would matter most on a server you are responsible for, and why?\n\n________________________________________________________________\n\n")
	b.WriteString("## Sources\n\n")
	for _, r := range m.Refs {
		fmt.Fprintf(&b, "- %s: %s\n", r.Title, r.URL)
	}
	b.WriteString("\nAdapted from the OpenVAPT Academy (openvapt.com), built by AI Cybersecurity Engineers, used under the OpenVAPT Source-Available Licence 1.2. Free teaching use under TEACHING.md. Please cite OpenVAPT: see CITING.md or openvapt.com/cite.html. OpenVAPT is not affiliated with, and is not endorsed by, this institution or any third party named in this material. Pre-release versions may be wrong or unstable. Use at your own risk. If you adapt this material, say where you changed it.\n")
	return b.String()
}

// CourseByID returns a course plan, or nil.
func CourseByID(id string) *Course {
	for i := range Courses {
		if strings.EqualFold(Courses[i].ID, id) {
			return &Courses[i]
		}
	}
	return nil
}
