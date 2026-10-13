package academy

var refNIST115 = Ref{"NIST SP 800-115, Technical Guide to Information Security Testing and Assessment", "https://csrc.nist.gov/pubs/sp/800/115/final"}
var refCVSS = Ref{"FIRST, CVSS v3.1 Specification Document", "https://www.first.org/cvss/v3.1/specification-document"}

// Modules is the whole course in teaching order.
var Modules = append(append(append(foundation, practitioner...), stacks...), applied...)

var foundation = []Module{
	{
		ID: "F1", Title: "Security Basics", Level: Foundation, Minutes: 15,
		Summary: "The core ideas every later lesson builds on: what we protect, what threatens it, and how risk is reasoned about.",
		Objectives: []string{
			"Explain confidentiality, integrity and availability with server examples.",
			"Distinguish an asset, a threat, a vulnerability and a risk.",
			"Apply least privilege and defence in depth to a Linux web server.",
		},
		Sections: []Section{
			{"The CIA Triad", []string{
				"Security protects three properties of information. Confidentiality means only authorised people can read it. Integrity means it cannot be changed without authorisation, or changes are detected. Availability means it is there when legitimate users need it.",
				"On a web server: a leaked .env file breaks confidentiality, a defaced home page breaks integrity, and a flood of half-open connections that stops the site breaks availability. CVSS scores later in this course measure impact on exactly these three properties.",
			}},
			{"Assets, Threats, Vulnerabilities and Risk", []string{
				"An asset is anything of value: data, a service, a reputation. A threat is something that could cause harm, such as an attacker guessing passwords. A vulnerability is a weakness a threat can use, such as SSH accepting passwords for root. Risk combines how likely the harm is with how bad it would be.",
				"A vulnerability assessment finds and rates vulnerabilities. It does not by itself measure risk to your organisation, because likelihood and impact depend on your environment, which is why every OpenVAPT report states this limitation.",
			}},
			{"Least Privilege and Defence in Depth", []string{
				"Least privilege means every account, process and service gets only the access it needs. Defence in depth means layering protections so one failure is not fatal: a firewall, then a service bound to 127.0.0.1, then authentication, then logging.",
				"Most OpenVAPT checks test one layer. Reading a report as a set of layers, not isolated items, is the habit of a good assessor.",
			}},
		},
		KeyTerms:      []string{"CIA Triad", "Asset", "Threat", "Vulnerability", "Risk", "Least Privilege", "Defence in Depth", "Attack Surface"},
		RelatedChecks: []string{"HOST-USR-003", "NET-FW-001", "NET-DB-001"},
		Lab: []string{
			"Run: openvapt demo --lab vulnerable --out f1",
			"Open f1/report.html. For three findings, write which CIA property each one threatens.",
			"For NET-DB-001, list the layers that should have stopped the database being reachable.",
		},
		Quiz: []Question{
			{"A backup file containing customer records is downloadable from the website. Which property is mainly affected?", []string{"Availability", "Confidentiality", "Integrity"}, 1, "Anyone can read data they are not authorised to read: confidentiality."},
			{"Which statement best describes a vulnerability?", []string{"A person who attacks systems", "A weakness that a threat can use", "The money lost in an incident"}, 1, "A vulnerability is the weakness; the attacker is the threat; the loss is the impact."},
			{"Binding MySQL to 127.0.0.1 even though a firewall exists is an example of:", []string{"Defence in depth", "Security through obscurity", "Availability testing"}, 0, "A second, independent layer protects the service if the firewall fails."},
		},
		Refs: []Ref{{"NIST SP 800-12 Rev. 1, An Introduction to Information Security", "https://csrc.nist.gov/pubs/sp/800/12/r1/final"}, {"NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments", "https://csrc.nist.gov/pubs/sp/800/30/r1/final"}},
	},
	{
		ID: "F2", Title: "What VAPT Is, and Doing It Legally", Level: Foundation, Minutes: 20,
		Summary: "How vulnerability assessment and penetration testing differ, how professional assessments are structured, and why authorisation is the first rule.",
		Objectives: []string{
			"Explain the difference between vulnerability assessment and penetration testing.",
			"Describe the phases of NIST SP 800-115 and where OpenVAPT stops.",
			"Explain why written authorisation and scope come before any testing.",
		},
		Sections: []Section{
			{"VA Versus PT", []string{
				"A vulnerability assessment (VA) looks for known weaknesses and rates them, without exploiting anything. A penetration test (PT) is performed by skilled, authorised testers who try to exploit weaknesses to prove real impact and find chains a scanner cannot see.",
				"VAPT combines both. OpenVAPT teaches and performs only the VA part, automatically, on one machine. That is a deliberate design choice, not a missing feature.",
			}},
			{"Methodologies", []string{
				"NIST SP 800-115 describes four phases: planning, discovery, attack and reporting. Other widely used frameworks include the Penetration Testing Execution Standard (PTES), the OWASP Web Security Testing Guide (WSTG) for web applications, and OSSTMM.",
				"OpenVAPT implements planning (scope fixed in code), discovery (read-only collection), analysis (checks) and reporting. The attack phase is absent by design.",
			}},
			{"Authorisation, Scope and the Law", []string{
				"Testing a system without permission can be a crime. In Malaysia, unauthorised access to computer material is an offence under the Computer Crimes Act 1997, and the Cyber Security Act 2024 regulates providers of cyber security services. Other countries have similar laws.",
				"Professional testers work only with written authorisation that defines scope, timing and rules of engagement. OpenVAPT enforces the strictest possible scope in code: the machine it runs on and nothing else. Even so, you need the right to run it on that machine.",
			}},
		},
		KeyTerms:      []string{"VAPT", "Vulnerability Assessment", "Penetration Testing", "Scope", "Rules of Engagement", "NIST SP 800-115", "False Positive"},
		RelatedChecks: []string{"NET-LSN-001"},
		Lab: []string{
			"Run: openvapt scan --dry-run and read every operation it would perform.",
			"Find the loopback guard in internal/scope/scope.go and its test. Explain why host names are refused.",
			"Write a one-paragraph scope statement for assessing your own test server.",
		},
		Quiz: []Question{
			{"What does a penetration test do that a vulnerability assessment does not?", []string{"Rates findings by severity", "Attempts to exploit weaknesses to prove impact", "Produces a report"}, 1, "Exploitation to demonstrate impact is the defining activity of a penetration test."},
			{"Which NIST SP 800-115 phase does OpenVAPT deliberately leave out?", []string{"Discovery", "Reporting", "Attack"}, 2, "OpenVAPT is detection only; it never attacks."},
			{"What must exist before testing a system you do not own?", []string{"A fast internet connection", "Written authorisation with a defined scope", "A paid scanner licence"}, 1, "Authorisation and scope come first, always."},
		},
		Refs: []Ref{refNIST115, {"OWASP Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/"}, {"Penetration Testing Execution Standard", "http://www.pentest-standard.org/"}},
	},
	{
		ID: "F3", Title: "Vulnerabilities, CVE, CWE and CVSS", Level: Foundation, Minutes: 20,
		Summary: "How vulnerabilities are named, classified and rated, and how to read a severity rating critically.",
		Objectives: []string{
			"Explain the difference between a CVE and a CWE.",
			"Read a CVSS v3.1 vector and explain each metric.",
			"Explain false positives and false negatives and why both matter.",
		},
		Sections: []Section{
			{"CVE and CWE", []string{
				"A CVE identifier names one specific, publicly known vulnerability in a specific product, for example a flaw in one OpenSSL version. A CWE identifier names a type of weakness, for example CWE-732, incorrect permission assignment for a critical resource.",
				"OpenVAPT mostly finds configuration weaknesses, so its checks map to CWE types. Its patch checks detect when published fixes for CVEs are waiting to be installed.",
			}},
			{"Reading a CVSS v3.1 Vector", []string{
				"A vector such as CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H describes how a vulnerability can be exploited and what it affects. AV is the attack vector (N network, A adjacent, L local, P physical). AC is attack complexity. PR is privileges required. UI is user interaction. S is scope. C, I and A are impact on confidentiality, integrity and availability.",
				"Scores map to ratings: Critical 9.0 to 10.0, High 7.0 to 8.9, Medium 4.0 to 6.9, Low 0.1 to 3.9. A base score describes the vulnerability in general; your environment can raise or lower the real risk.",
			}},
			{"False Positives and False Negatives", []string{
				"A false positive is a reported problem that is not real; it wastes time and erodes trust. A false negative is a real problem that is missed; it creates false confidence. Every automated tool has both.",
				"OpenVAPT's tests run each check against a vulnerable and a hardened simulated server to show that it fires when it should and stays silent when it should not. That still does not prove the absence of real-world errors.",
			}},
		},
		KeyTerms:      []string{"CVE", "CWE", "CVSS", "Severity", "False Positive", "False Negative", "End of Life"},
		RelatedChecks: []string{"HOST-PKG-001", "HOST-OS-001", "WEB-PHP-004"},
		Lab: []string{
			"Run: openvapt explain WEB-EXP-002 and decode its CVSS vector metric by metric.",
			"Open the CWE link on any check page and compare the CWE description with the check's rationale.",
			"Run the demo against both labs and use openvapt diff to see every finding move to Fixed.",
		},
		Quiz: []Question{
			{"CWE-732 describes:", []string{"One specific bug in one product version", "A type of weakness: incorrect permission assignment", "A scoring formula"}, 1, "CWE names weakness types; CVE names specific vulnerabilities."},
			{"In a CVSS vector, PR:N means:", []string{"No privileges are required", "Network access is required", "No patch exists"}, 0, "PR is Privileges Required; N means none."},
			{"A scanner reports no findings. What can you conclude?", []string{"The system is secure", "Only that the checks performed did not find their weaknesses", "Nothing was scanned"}, 1, "Absence of findings is not proof of security."},
		},
		Refs: []Ref{refCVSS, {"CVE Program", "https://www.cve.org/"}, {"MITRE CWE", "https://cwe.mitre.org/"}},
	},
}
