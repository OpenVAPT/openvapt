package academy

var applied = []Module{
	{
		ID: "A1", Title: "Running an Assessment", Level: Applied, Minutes: 20,
		Summary: "Putting theory into practice: plan, preview, scan and triage an assessment of a machine you own.",
		Prereqs: []string{"F2", "F3"},
		Objectives: []string{
			"Plan a safe assessment of your own machine.",
			"Preview every action before scanning.",
			"Triage findings by severity and context.",
		},
		Sections: []Section{
			{"Plan", []string{
				"Confirm you own or control the machine, choose a quiet time, take a backup, and decide what you will do with the results. Prefer a test copy of a production server.",
			}},
			{"Preview and Scan", []string{
				"openvapt scan --dry-run lists every file, command and request a real scan would use, without doing any of it. Then run sudo openvapt scan --out <folder>, read the acknowledgements, and type I ACCEPT.",
			}},
			{"Triage", []string{
				"Start with Critical and High findings. For each one, ask three questions. Is it real (check the evidence)? Is it reachable in my environment? What would an attacker gain? Record false positives honestly instead of hiding them.",
			}},
			{"In Summary", []string{
				"Plan, preview with a dry run, then scan. Triage by severity and by what an attacker could actually reach.",
			}},
		},
		KeyTerms:      []string{"Triage", "Dry Run", "Evidence"},
		RelatedChecks: []string{"NET-LSN-001"},
		Lab: []string{
			"Run: openvapt scan --dry-run | less",
			"Run: openvapt demo --out a1 and triage the top five findings in a short table: finding, real or not, reachable or not, impact.",
		},
		Quiz: []Question{
			{"What does openvapt scan --dry-run do?", []string{"Scans faster", "Lists every operation without performing any", "Scans other servers", "Fixes findings automatically"}, 1, "It is a preview: it lists every file, command and request a real scan would use, without doing any of it."},
			{"Which findings should you look at first?", []string{"Low", "Critical and High", "Passed checks", "Informational"}, 1, "Prioritise by severity first, then by context."},
			{"During triage, how do you decide whether a finding is real?", []string{"Check the evidence", "Trust the severity alone", "Re-run the scan without reading it", "Assume every finding is real"}, 0, "The evidence shows what the check actually saw. It is how you spot false positives."},
			{"What should you do before scanning a production server?", []string{"Nothing, because the scan is read-only", "Confirm you own or control it, take a backup and prefer a test copy", "Turn off the firewall", "Turn off logging"}, 1, "Planning comes first: authority over the machine, a backup and, ideally, a test copy."},
			{"You find a false positive. What should you do?", []string{"Delete it from the report", "Record it honestly as a false positive", "Mark it as fixed", "Raise its severity"}, 1, "Honest records keep the report trustworthy and help improve the check."},
		},
		Refs: []Ref{refNIST115},
	},
	{
		ID: "A2", Title: "Remediation and Verification", Level: Applied, Minutes: 20,
		Summary: "Fixing findings safely, proving the fix worked, and tracking progress over time.",
		Prereqs: []string{"A1"},
		Objectives: []string{
			"Apply a fix with change control and a rollback plan.",
			"Verify a fix with a targeted re-scan.",
			"Track progress with report diffs.",
		},
		Sections: []Section{
			{"Fix Safely", []string{
				"Every check gives exact fix steps and cited sources. Apply one change at a time, test it, and keep a way back. Configuration changes to SSH or firewalls can lock you out of a remote server; keep a second session open.",
			}},
			{"Verify", []string{
				"Each check has a verification command. Then re-run just that check: openvapt scan --only HOST-SSH-001. A fix is not done until it is verified.",
			}},
			{"Track", []string{
				"Keep each report.json and compare with openvapt diff old.json new.json, or scan with --baseline old.json. The diff lists what was fixed, what is new and what is still open.",
			}},
			{"In Summary", []string{
				"Fix the highest risk and the easiest wins first. Change one thing at a time, with a way back. Verify with a targeted re-scan and a diff.",
			}},
		},
		KeyTerms:      []string{"Remediation", "Verification", "Change Management", "Baseline"},
		RelatedChecks: []string{"HOST-SSH-001"},
		Lab: []string{
			"Run: openvapt demo --lab vulnerable --out before && openvapt demo --lab hardened --out after",
			"Run: openvapt diff before/report.json after/report.json",
		},
		Quiz: []Question{
			{"When is a fix complete?", []string{"When the configuration file is saved", "When it has been verified, for example by a targeted re-scan", "When the ticket is closed", "When the service restarts"}, 1, "Verification proves the fix. A saved file or a restart does not."},
			{"What does openvapt diff show?", []string{"Fixed, new and still open findings between two reports", "Source code changes", "Network traffic", "Changes in every file on the disk"}, 0, "It compares two JSON reports."},
			{"Why keep a second SSH session open while changing SSH or firewall settings?", []string{"To save time", "So you can undo a change that locks you out", "To make the scan faster", "To log more detail"}, 1, "A bad SSH or firewall change can lock you out of a remote server. The open session is your way back."},
			{"Which command re-runs only one check?", []string{"openvapt scan --only HOST-SSH-001", "openvapt diff old.json new.json", "openvapt verify report.json", "openvapt scan --dry-run"}, 0, "--only limits the scan to the checks you name."},
			{"How many changes should you apply at once?", []string{"All of them together", "One at a time, tested, with a way back", "As many as fit in the maintenance window", "Only the Low findings first"}, 1, "One change at a time shows which change caused a problem and makes rollback simple."},
		},
		Refs: []Ref{{"NIST SP 800-40 Rev. 4, Enterprise Patch Management", "https://csrc.nist.gov/pubs/sp/800/40/r4/final"}},
	},
	{
		ID: "A3", Title: "Reporting and Communication", Level: Applied, Minutes: 15,
		Summary: "What a good assessment report contains, how to read OpenVAPT's report, and how to share results safely.",
		Prereqs: []string{"A2"},
		Objectives: []string{
			"Describe the structure of an assessment report.",
			"Explain why limitations belong in every report.",
			"Share reports without leaking sensitive information.",
		},
		Sections: []Section{
			{"Structure", []string{
				"NIST SP 800-115 recommends scope and methodology first, then findings with severity, evidence and remediation, then limitations. OpenVAPT reports follow that order and come in HTML, JSON, SARIF 2.1.0 and Markdown.",
			}},
			{"Honesty in Reports", []string{
				"An honest report says what was not tested. Limitations protect readers from false confidence and protect the author from overclaiming. OpenVAPT never issues a seal, score or certificate.",
			}},
			{"Sharing Safely", []string{
				"A report describes weaknesses of a real machine. Share it only with people who need it, and review it for remaining secrets first. Sign it (the default) so recipients can use openvapt verify to confirm it was not edited.",
			}},
			{"In Summary", []string{
				"A report serves its reader. Lead with what matters, give evidence and say what was not tested. SARIF and signing make it machine readable and tamper evident.",
			}},
		},
		KeyTerms:      []string{"SARIF", "Limitations", "Report Signing"},
		RelatedChecks: []string{},
		Lab: []string{
			"Open a sample report on openvapt.com and identify scope, methodology, findings and limitations.",
			"Run: openvapt verify a1/report.json, then edit one character in the file and verify again.",
		},
		Quiz: []Question{
			{"Why should a report list its limitations?", []string{"To make it longer", "So readers do not mistake absence of findings for proof of security", "To hide findings", "So the report can claim compliance"}, 1, "Honest limits prevent false confidence and stop the author overclaiming."},
			{"What does a valid report signature prove?", []string{"The machine is secure", "The report was not edited after signing", "The project endorses the report", "Every finding is real"}, 1, "A signature proves integrity only, never security."},
			{"Which order does NIST SP 800-115 recommend for a report?", []string{"Scope and methodology, then findings, then limitations", "Findings first, then scope", "Limitations only", "An overall score, then a seal"}, 0, "Readers first learn what was tested and how, then what was found, then what was not covered."},
			{"Before sharing a report, what should you do?", []string{"Post it publicly for transparency", "Review it for remaining secrets and share it only with people who need it", "Remove the signature", "Delete the limitations"}, 1, "A report describes weaknesses of a real machine, so share it carefully."},
			{"Does OpenVAPT issue a security seal, score or certificate?", []string{"Yes, after a clean scan", "No, never", "Only when there are no Critical findings", "Only for signed reports"}, 1, "OpenVAPT never issues a seal, score or certificate, because no scan proves security."},
		},
		Refs: []Ref{refNIST115, {"OASIS SARIF 2.1.0", "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html"}},
	},
	{
		ID: "A4", Title: "Building Your Own Check", Level: Applied, Minutes: 30,
		Summary: "The engineering view: how a detection is designed, kept read-only, tested against false results and documented.",
		Prereqs: []string{"A1"},
		Objectives: []string{
			"Describe the parts of an OpenVAPT check.",
			"Write a read-only detection through the System interface.",
			"Prove a check with vulnerable and hardened test cases.",
		},
		Sections: []Section{
			{"Anatomy", []string{
				"A check is one Go file that registers metadata (id, severity, CVSS vector, rationale, detection, fix, verify, references, standards) and a Run function. Registration refuses checks without documentation or citations.",
			}},
			{"Read-Only by Construction", []string{
				"Run receives a sys.System with only read operations, an allow-list of read-only commands, and loopback-only HTTP. There is nothing to call that could change the machine or reach another one.",
			}},
			{"Proving It", []string{
				"Add lab fixtures in internal/lab so the simulated vulnerable server triggers your check and the hardened server passes it. The engine tests fail until both behave. That is how false positives and false negatives are caught before release.",
			}},
			{"In Summary", []string{
				"A check is a small Go file with full documentation and tests. It must fail on the vulnerable lab and pass on the hardened lab.",
			}},
		},
		KeyTerms:      []string{"Detection Logic", "Test Fixture", "False Positive"},
		RelatedChecks: []string{"HOST-LOG-001"},
		Lab: []string{
			"Read internal/checks/host/logging_time.go and internal/check/check.go.",
			"Follow the steps on the Learn page to add a small check, then run go test ./...",
		},
		Quiz: []Question{
			{"How does OpenVAPT show a check does not raise false positives?", []string{"It runs the check against a hardened simulated server, which must pass", "It asks users", "It cannot", "It compares results with another scanner"}, 0, "The hardened lab must stay silent for every check."},
			{"Why can a check not modify the system?", []string{"Developers promise not to", "The System interface offers no write or restart operations", "Go forbids it", "Checks run inside a container"}, 1, "Read-only is enforced by the interface design."},
			{"What happens when a check is registered without documentation or citations?", []string{"It is accepted with a warning", "Registration refuses it", "It is marked Low severity", "It is hidden from reports"}, 1, "Every check must carry its rationale, fix and references, or it is refused."},
			{"What network access does a check get?", []string{"Any host on the internet", "Loopback-only HTTP", "Any host on the local network", "None except DNS"}, 1, "The System interface allows HTTP to loopback only, so a check cannot reach another machine."},
			{"How are false negatives caught before release?", []string{"The vulnerable lab must trigger the check, or the engine tests fail", "Users report them", "They cannot be caught", "By running the check on production servers"}, 0, "If the vulnerable lab does not trigger the check, the tests fail until it does."},
		},
		Refs: []Ref{{"OpenVAPT source code", "https://github.com/OpenVAPT/openvapt"}},
	},
}
