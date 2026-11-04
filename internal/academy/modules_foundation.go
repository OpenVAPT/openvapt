package academy

var refNIST115 = Ref{"NIST SP 800-115, Technical Guide to Information Security Testing and Assessment", "https://csrc.nist.gov/pubs/sp/800/115/final"}
var refCVSS = Ref{"FIRST, CVSS v3.1 Specification Document", "https://www.first.org/cvss/v3.1/specification-document"}

// Modules is the whole course in teaching order.
var Modules = append(append(append(append(foundation, practitioner...), stacks...), accessLogging...), applied...)

var foundation = []Module{
	{
		ID: "F1", Title: "Security Basics", Level: Foundation, Minutes: 15,
		Summary: "The core ideas every later lesson builds on: what we protect, what threatens it, and how risk is reasoned about.",
		Prereqs: []string{},
		Objectives: []string{
			"Explain confidentiality, integrity and availability with server examples.",
			"Distinguish an asset, a threat, a vulnerability and a risk.",
			"Apply least privilege and defence in depth to a Linux web server.",
		},
		Sections: []Section{
			{"The CIA Triad", []string{
				"Security protects three properties of information. Confidentiality means only authorised people can read it. Integrity means it cannot be changed without authorisation, or changes are detected. Availability means it is there when legitimate users need it.",
				"On a web server, a leaked .env file breaks confidentiality. A defaced home page breaks integrity. A flood of half-open connections that stops the site breaks availability. CVSS scores later in this course measure impact on exactly these three properties.",
			}},
			{"Assets, Threats, Vulnerabilities and Risk", []string{
				"An asset is anything of value: data, a service, a reputation. A threat is something that could cause harm, such as an attacker guessing passwords. A vulnerability is a weakness a threat can use, such as SSH accepting passwords for root. Risk combines how likely the harm is with how bad it would be.",
				"A vulnerability assessment finds and rates vulnerabilities. It does not by itself measure risk to your organisation, because likelihood and impact depend on your environment. That is why every OpenVAPT report states this limitation.",
			}},
			{"Least Privilege and Defence in Depth", []string{
				"Least privilege means every account, process and service gets only the access it needs. Defence in depth means layering protections so one failure is not fatal: a firewall, then a service bound to 127.0.0.1, then authentication, then logging.",
				"Most OpenVAPT checks test one layer. Reading a report as a set of layers, not isolated items, is the habit of a good assessor.",
			}},
			{"In Summary", []string{
				"Security protects the confidentiality, integrity and availability of assets. Risk appears when a threat meets a vulnerability. Least privilege, defence in depth and a small attack surface reduce it.",
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
			{"A backup file containing customer records is downloadable from the website. Which property is mainly affected?", []string{"Availability", "Confidentiality", "Integrity", "None, because it is only a backup"}, 1, "Anyone can read data they are not authorised to read, so confidentiality is broken. A backup holds the same real data as the live system."},
			{"Which statement best describes a vulnerability?", []string{"A person who attacks systems", "A weakness that a threat can use", "The money lost in an incident", "The chance that an incident happens"}, 1, "A vulnerability is the weakness. The attacker is the threat, the loss is the impact, and likelihood combined with impact is risk."},
			{"Binding MySQL to 127.0.0.1 even though a firewall exists is an example of:", []string{"Defence in depth", "Security through obscurity", "Availability testing", "Risk acceptance"}, 0, "A second, independent layer protects the service if the firewall fails. Layering protections so one failure is not fatal is defence in depth."},
			{"A flood of half-open connections stops a web site answering real users. Which property is affected?", []string{"Confidentiality", "Integrity", "Availability", "Authorisation"}, 2, "Nothing is read or changed, but legitimate users cannot reach the service. That is a loss of availability."},
			{"Why does a vulnerability assessment not, by itself, measure risk to your organisation?", []string{"Because scanners cannot find vulnerabilities", "Because likelihood and impact depend on your environment", "Because risk only applies to networks, not servers", "Because the CVSS base score already includes your business impact"}, 1, "Risk combines likelihood and impact. Both depend on your environment, which a tool cannot see. The CVSS base score describes the vulnerability in general, not your business."},
			{"A web application's account can read every database on the server, but it needs only one. Which principle is broken?", []string{"Defence in depth", "Least privilege", "Availability", "Security through obscurity"}, 1, "Least privilege means every account gets only the access it needs. Access to the other databases is extra harm waiting for a compromise."},
		},
		Refs: []Ref{{"NIST SP 800-12 Rev. 1, An Introduction to Information Security", "https://csrc.nist.gov/pubs/sp/800/12/r1/final"}, {"NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments", "https://csrc.nist.gov/pubs/sp/800/30/r1/final"}},
	},
	{
		ID: "F2", Title: "What VAPT Is, and Doing It Legally", Level: Foundation, Minutes: 20,
		Summary: "How vulnerability assessment and penetration testing differ, how professional assessments are structured, and why authorisation is the first rule.",
		Prereqs: []string{"F1"},
		Objectives: []string{
			"Explain the difference between vulnerability assessment and penetration testing.",
			"Describe the phases of NIST SP 800-115 and where OpenVAPT stops.",
			"Explain why written authorisation and scope come before any testing.",
		},
		Sections: []Section{
			{"VA Versus PT", []string{
				"A vulnerability assessment (VA) looks for known weaknesses and rates them, without exploiting anything. A penetration test (PT) is performed by skilled, authorised testers. They try to exploit weaknesses to prove real impact and to find chains a scanner cannot see.",
				"VAPT combines both. OpenVAPT teaches and performs only the VA part, automatically, on one machine. That is a deliberate design choice, not a missing feature.",
			}},
			{"Methodologies", []string{
				"NIST SP 800-115 describes four phases: planning, discovery, attack and reporting. Other widely used frameworks include the Penetration Testing Execution Standard (PTES), the OWASP Web Security Testing Guide (WSTG) for web applications, and OSSTMM.",
				"OpenVAPT implements planning (scope fixed in code), discovery (read-only collection), analysis (checks) and reporting. The attack phase is absent by design.",
			}},
			{"Authorisation, Scope and the Law", []string{
				"Testing a system without permission is a crime in most countries. Examples include the Computer Fraud and Abuse Act in the United States and the Computer Misuse Act 1990 in the United Kingdom. Others are Directive 2013/40/EU in the European Union and the Computer Crimes Act 1997 in Malaysia. The Council of Europe Convention on Cybercrime has been joined by many countries. Some countries also license people who sell security testing as a service. Always follow the law where you and the machine are.",
				"Professional testers work only with written authorisation that defines scope, timing and rules of engagement. OpenVAPT enforces the strictest possible scope in code: the machine it runs on and nothing else. Even so, you need the right to run it on that machine.",
			}},
			{"In Summary", []string{
				"A vulnerability assessment finds and rates weaknesses. A penetration test also exploits them. Both need written authorisation and a clear scope. OpenVAPT assesses only the machine it runs on.",
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
			{"What does a penetration test do that a vulnerability assessment does not?", []string{"Rates findings by severity", "Attempts to exploit weaknesses to prove impact", "Produces a report", "Looks for known weaknesses"}, 1, "Both look for weaknesses, rate them and report. Exploitation to demonstrate real impact is the defining activity of a penetration test."},
			{"Which NIST SP 800-115 phase does OpenVAPT deliberately leave out?", []string{"Discovery", "Reporting", "Attack", "Planning"}, 2, "NIST SP 800-115 names planning, discovery, attack and reporting. OpenVAPT is detection only and never attacks."},
			{"What must exist before testing a system you do not own?", []string{"A fast internet connection", "Written authorisation with a defined scope", "A paid scanner licence", "A tool that is free to use"}, 1, "Authorisation and scope come first, always. The tool or its price does not give you the right to test."},
			{"Which scope does OpenVAPT enforce in its code?", []string{"Any host on the local network", "Only the machine it runs on", "Any host named on the command line", "Any host covered by written authorisation"}, 1, "The loopback guard limits OpenVAPT to the machine it runs on and nothing else, even if you have permission for other hosts."},
			{"Which of these is a methodology for testing web applications?", []string{"OWASP Web Security Testing Guide (WSTG)", "CVSS v3.1", "CWE", "Directive 2013/40/EU"}, 0, "The WSTG is a testing methodology for web applications. CVSS rates severity, CWE classifies weakness types and the directive is European Union law."},
			{"You run OpenVAPT on a server you rent but do not control. Does its loopback-only scope make the test lawful?", []string{"Yes, local scans are always lawful", "No, you still need the right to run it on that machine", "Yes, if the server is in another country", "Only if the scan finishes quickly"}, 1, "Scope limits what the tool touches. It does not grant permission. You still need the right to run it on that machine, under the law where you and the machine are."},
		},
		Refs: []Ref{refNIST115, {"OWASP Web Security Testing Guide", "https://owasp.org/projects/web-security-testing-guide"}, {"Penetration Testing Execution Standard (PTES) Technical Guidelines", "https://pentest-standard.readthedocs.io/en/latest/"}},
	},
	{
		ID: "F3", Title: "Vulnerabilities, CVE, CWE and CVSS", Level: Foundation, Minutes: 20,
		Summary: "How vulnerabilities are named, classified and rated, and how to read a severity rating critically.",
		Prereqs: []string{"F1", "F2"},
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
				"OpenVAPT's tests run each check against a vulnerable and a hardened simulated server. This shows that it fires when it should and stays silent when it should not. That still does not prove the absence of real-world errors.",
			}},
			{"In Summary", []string{
				"A CVE names one vulnerability in one product. A CWE names the type of weakness. CVSS rates how severe it is, from 0.0 to 10.0. Any finding can be a false positive, so always check the evidence.",
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
			{"CWE-732 describes:", []string{"One specific bug in one product version", "A type of weakness: incorrect permission assignment for a critical resource", "A scoring formula", "A list of exploited vulnerabilities"}, 1, "CWE names weakness types. CVE names specific vulnerabilities in specific products."},
			{"In a CVSS vector, PR:N means:", []string{"No privileges are required", "Network access is required", "No patch exists", "No user interaction is required"}, 0, "PR is Privileges Required and N means none. Network access is AV:N and no user interaction is UI:N."},
			{"A scanner reports no findings. What can you conclude?", []string{"The system is secure", "Only that the checks performed did not find their weaknesses", "Nothing was scanned", "Every CVE on the system is patched"}, 1, "Absence of findings is not proof of security. Every tool has false negatives and only tests what it was built to test."},
			{"A CVSS v3.1 base score is 7.5. Which rating does it map to?", []string{"Low", "Medium", "High", "Critical"}, 2, "In CVSS v3.1, High covers 7.0 to 8.9. Critical starts at 9.0."},
			{"In a CVSS v3.1 vector, AV:L means:", []string{"The attacker needs local access to the system", "The attack works over the network", "Attack complexity is low", "Low privileges are required"}, 0, "AV is the attack vector. L means local. Low complexity is AC:L and low privileges is PR:L."},
			{"Which of these is a false negative?", []string{"A reported problem that is not real", "A real weakness the tool missed", "A finding with Low severity", "A finding the owner has accepted"}, 1, "A false negative is a real problem that is missed. It creates false confidence. A reported problem that is not real is a false positive."},
		},
		Refs: []Ref{refCVSS, {"CVE Program", "https://www.cve.org/"}, {"MITRE CWE", "https://cwe.mitre.org/"}},
	},
}
