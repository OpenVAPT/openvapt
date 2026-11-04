package academy

// Modules that bring general software testing ideas into security
// self-assessment: test design, availability without load tests, self-hosted
// AI services, security testing in agile teams and CI, and tracing findings
// back to requirements. Written in OpenVAPT's own words; no syllabus text is
// reproduced.

var testingAIRefOWASPLLM = Ref{"OWASP Top 10 for Large Language Model Applications", "https://genai.owasp.org/llm-top-10/"}
var testingAIRefASVS = Ref{"OWASP Application Security Verification Standard (ASVS)", "https://owasp.org/www-project-application-security-verification-standard/"}

var testingAI = []Module{
	{
		ID: "P23", Title: "Test Design for Security Checks", Level: Practitioner, Minutes: 25,
		Prereqs: []string{"F3"},
		Summary: "How testers choose a small set of cases that still catches mistakes, and how the same ideas make a security check trustworthy.",
		Objectives: []string{
			"Use equivalence partitioning and boundary values to pick test cases.",
			"Explain why every check needs a failing and a passing example.",
			"Recognise false positives and false negatives as test design problems.",
		},
		Sections: []Section{
			{"Why Test Design Matters", []string{
				"A check that reads a configuration value can meet thousands of different files. Nobody can test them all, so testers group inputs and pick the cases most likely to expose a mistake.",
			}},
			{"Equivalence Partitioning", []string{
				"Split the possible inputs into groups the check should treat the same way. For an SSH setting such as PermitRootLogin, the groups are: allowed, forbidden, limited to keys, and missing.",
				"One case from each group is usually enough, because a mistake that affects one member of a group tends to affect all of them.",
			}},
			{"Boundary Values", []string{
				"Mistakes cluster at the edges of a group. If a check fails when MaxAuthTries is above 4, test 4 and 5, not only 3 and 10.",
				"The same applies to dates, sizes and version numbers: the version just before a fix and the fixed version itself are the most useful cases.",
			}},
			{"Two Labs, Two Directions", []string{
				"OpenVAPT tests every check against a vulnerable lab, where it must fail, and a hardened lab, where it must pass. The first catches false negatives and the second catches false positives.",
				"When a real machine shows a wrong result, the fix is a new test case in the lab first, then a change to the check.",
			}},
			{"In Summary", []string{
				"Group inputs, test one case per group, and test both sides of every boundary. A check is only trusted once it fails on a weak example and passes on a fixed one.",
			}},
		},
		KeyTerms:      []string{"Equivalence Partitioning", "Boundary Value", "False Positive", "False Negative", "Test Fixture"},
		RelatedChecks: []string{"HOST-SSH-001"},
		Lab: []string{
			"Run: openvapt explain HOST-SSH-001 and list the input groups its detection must handle.",
			"Run: openvapt demo vulnerable --only HOST-SSH-001 --out p23v and openvapt demo hardened --only HOST-SSH-001 --out p23h, then compare the evidence.",
		},
		Quiz: []Question{
			{"What is equivalence partitioning?", []string{"Testing every possible input", "Grouping inputs the system should treat the same and testing one from each group", "Splitting a disk into partitions", "Running tests in parallel"}, 1, "Each group behaves alike, so one representative per group finds most mistakes."},
			{"A check fails when a value is above 4. Which pair of cases tests the boundary best?", []string{"1 and 100", "4 and 5", "0 and 10", "Only 10"}, 1, "Mistakes such as using >= instead of > appear exactly at the edge."},
			{"What does the vulnerable lab catch?", []string{"False positives", "False negatives: checks that miss a real weakness", "Slow checks", "Spelling mistakes"}, 1, "A check that does not fail on a known weak setting has a false negative."},
			{"What does the hardened lab catch?", []string{"False positives: checks that flag a correct setting", "Missing documentation", "Network outages", "Expired certificates only"}, 0, "A check that fails on a fixed setting raises a false alarm."},
			{"A check gives a wrong result on a real server. What comes first?", []string{"Delete the check", "Add a lab case that reproduces the problem", "Lower its severity", "Ignore it"}, 1, "A reproducing test case proves the fix and stops the mistake returning."},
		},
		Refs: []Ref{refNIST115},
	},
	{
		ID: "P24", Title: "Securing Self-Hosted AI Services", Level: Practitioner, Minutes: 25,
		Prereqs: []string{"F2", "F3"},
		Summary: "Why model servers, AI web interfaces, AI dashboards and vector databases are often left open, and how to find and close them from the machine itself.",
		Objectives: []string{
			"Name the common self-hosted AI services and their default ports.",
			"Explain what an open model server or notebook gives an attacker.",
			"Bind AI services to loopback and publish them only behind authentication.",
		},
		Sections: []Section{
			{"A New Kind of Service", []string{
				"Teams now run language models, image generators, notebooks and vector databases on their own servers. Many of these tools were built for one person on a laptop, so many ship with no login enabled by default.",
			}},
			{"What an Attacker Gains", []string{
				"An open model server lets anyone use your computing power, pull or delete models, and sometimes read the documents stored for retrieval.",
				"An open notebook or AI cluster dashboard can be worse: it runs code, so reaching it can come close to having a shell on the machine.",
			}},
			{"Finding Them Without Touching Them", []string{
				"OpenVAPT is designed never to send a prompt or a request to an AI service. It reads the listening sockets the kernel reports and the configuration files on disk, which is often enough to see exposure.",
				"NET-AI-001 matches network-reachable sockets with the default ports of these tools. NET-AI-002 reads Jupyter configuration for a blank token or disabled request forgery protection.",
			}},
			{"Closing the Door", []string{
				"Bind each service to 127.0.0.1. If other people need it, put a reverse proxy with authentication and TLS in front, or reach it through an SSH tunnel or VPN.",
				"Testing how a model answers hostile prompts is a separate activity. It needs the owner's permission and its own plan, and OpenVAPT does not do it.",
			}},
			{"In Summary", []string{
				"Self-hosted AI tools often have no login. Keep them on loopback, publish them only behind authentication, and treat notebooks and dashboards as remote shells.",
			}},
		},
		KeyTerms:      []string{"Model Server", "Vector Database", "Attack Surface", "Loopback"},
		RelatedChecks: []string{"NET-AI-"},
		Lab: []string{
			"Run: openvapt demo vulnerable --only NET-AI- --out p24 and read the evidence for each finding.",
			"Write the one setting that binds Ollama to loopback and the Jupyter command that sets a password.",
		},
		Quiz: []Question{
			{"Why are many self-hosted AI tools risky on a server?", []string{"They use too much memory", "Many have no login and assume a single local user", "They need a GPU", "They are always out of date"}, 1, "Tools designed for a laptop often trust whoever can reach the port."},
			{"What does an open Jupyter server give an attacker?", []string{"Only read access to notebooks", "The ability to run code as the account that started it", "Nothing, because notebooks are static", "Access to the model weights only"}, 1, "Jupyter executes code, so an open server can act much like a remote shell."},
			{"How does OpenVAPT find exposed AI services?", []string{"It sends test prompts", "It reads listening sockets and configuration files on the machine", "It scans the internet", "It asks the model about itself"}, 1, "Detection is read-only: sockets from /proc/net and files on disk."},
			{"What is the safest default bind address for these services?", []string{"0.0.0.0", "127.0.0.1", "The public IP address", "Any address with a firewall rule later"}, 1, "Loopback keeps the service on the machine until access is deliberately published."},
			{"Is testing a model with hostile prompts part of a local self-assessment?", []string{"Yes, always", "No, it is a separate activity that needs the owner's permission and its own plan", "Only for vector databases", "Only at night"}, 1, "Prompt testing sends input to a live service. It needs its own authorisation and plan."},
		},
		Refs: []Ref{testingAIRefOWASPLLM, {"Jupyter Server documentation, Security in the Jupyter Server", "https://jupyter-server.readthedocs.io/en/latest/operators/security.html"}},
	},
	{
		ID: "P25", Title: "Availability Without Load Testing", Level: Practitioner, Minutes: 20,
		Prereqs: []string{"F3"},
		Summary: "Why a self-assessment never floods a server to test it, and which settings show whether a site can resist floods and slow requests.",
		Objectives: []string{
			"Explain the difference between performance testing and a configuration review.",
			"Name the settings that limit request rate, size and duration.",
			"Know when real load testing is appropriate and who must approve it.",
		},
		Sections: []Section{
			{"Two Different Activities", []string{
				"Performance testing sends heavy traffic on purpose to measure speed and find breaking points. Done without permission, the same traffic is a denial of service attack.",
				"A self-assessment instead reads the configuration that decides how the server behaves under pressure. No heavy traffic is sent, so the review is designed not to strain the service.",
			}},
			{"What to Look For", []string{
				"Rate limits stop one client sending too many requests. Size limits stop huge uploads. Time limits stop clients that send a request very slowly to hold a worker open.",
				"On nginx these are limit_req_zone, limit_conn_zone and client_max_body_size. On Apache they are mod_reqtimeout and optional modules such as mod_evasive.",
			}},
			{"Login Protection", []string{
				"Repeated failed logins are a flood aimed at one door. SSH MaxAuthTries and a log-based blocker such as fail2ban, sshguard or CrowdSec slow attackers down.",
			}},
			{"When Real Load Testing Is Right", []string{
				"Before a launch or a big event, a team may load test its own system. Do it on a copy where possible, in an agreed window, with written approval from the owner and the hosting provider.",
			}},
			{"In Summary", []string{
				"Never flood a server to assess it. Read its rate, size and time limits instead, and keep real load tests for your own systems, with written approval.",
			}},
		},
		KeyTerms:      []string{"Rate Limiting", "Slowloris", "Intrusion Prevention", "Brute Force"},
		RelatedChecks: []string{"WEB-APA-011", "WEB-APA-008", "WEB-NGX-006"},
		Lab: []string{
			"Run: openvapt demo vulnerable --only WEB-APA-011,WEB-NGX-006 --out p25 and list the missing limits.",
			"Write the nginx lines that add a login rate limit of 10 requests per minute per address.",
		},
		Quiz: []Question{
			{"Why does OpenVAPT not send heavy traffic to test availability?", []string{"It is too slow", "Heavy traffic can take a service down and, without permission, is an attack", "Servers block it anyway", "It needs a paid licence"}, 1, "Floods can break the system being assessed. A configuration review avoids that risk."},
			{"What does a slow request attack (Slowloris) exploit?", []string{"Weak passwords", "Workers kept busy by clients that send requests very slowly", "Old TLS versions", "Large images"}, 1, "Each slow client holds a worker. Enough of them use up every worker."},
			{"Which nginx directive limits request rate?", []string{"server_tokens", "limit_req_zone", "autoindex", "ssl_ciphers"}, 1, "limit_req_zone defines a shared rate limit, applied with limit_req."},
			{"Which Apache module protects against slow requests?", []string{"mod_rewrite", "mod_reqtimeout", "mod_ssl", "mod_status"}, 1, "mod_reqtimeout sets minimum read rates for headers and bodies."},
			{"Who must approve a real load test?", []string{"Nobody", "The system owner and, where relevant, the hosting provider, in writing", "Any team member", "Only the firewall"}, 1, "Load tests can affect shared infrastructure, so written approval comes first."},
		},
		Refs: []Ref{{"nginx documentation, ngx_http_limit_req_module", "https://nginx.org/en/docs/http/ngx_http_limit_req_module.html"}, {"Apache HTTP Server, mod_reqtimeout", "https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html"}},
	},
	{
		ID: "A7", Title: "Security Testing in Agile Teams and CI", Level: Applied, Minutes: 25,
		Prereqs: []string{"A2"},
		Summary: "How short development cycles change security testing, and how scan baselines, exit codes and SARIF output let a pipeline catch regressions.",
		Objectives: []string{
			"Explain why security checks move earlier and run more often in agile teams.",
			"Use a baseline and exit codes to fail a build only on new problems.",
			"Read SARIF output in a code review tool.",
		},
		Sections: []Section{
			{"Small Changes, Often", []string{
				"Agile teams ship small changes every week or every day. A security review once a year cannot keep up, so checks run with every change instead.",
				"Testing earlier is often called shifting left. A weakness found in a pull request costs minutes; the same weakness found in production costs an incident.",
			}},
			{"Regression Testing", []string{
				"A regression is something that worked and broke again. Keeping each report and comparing it with the next shows new findings at once.",
				"With openvapt scan --baseline old.json, or openvapt diff, the team sees what is new, what was fixed and what is still open.",
			}},
			{"Gates in a Pipeline", []string{
				"A pipeline needs a clear yes or no. OpenVAPT returns exit code 3 when a finding reaches the --fail-on severity, and 4 when coverage is incomplete; an incomplete scan takes precedence over findings.",
				"Accepted risks go in a suppression file with a reason and an expiry date, so they stop blocking builds without disappearing silently.",
			}},
			{"Where OpenVAPT Fits", []string{
				"OpenVAPT assesses the machine it runs on. In a pipeline, that means a test server or a container image built from the same configuration as production.",
				"SARIF output lets code review tools show findings next to the change that caused them.",
			}},
			{"In Summary", []string{
				"Run checks with every change, compare each report with a baseline, fail builds only on new serious findings, and record accepted risks with an expiry.",
			}},
		},
		KeyTerms:      []string{"Shift Left", "Regression Testing", "Baseline", "SARIF"},
		RelatedChecks: []string{"WEB-CVE-001"},
		Lab: []string{
			"Run: openvapt demo vulnerable --out a7a and openvapt demo hardened --out a7b, then openvapt diff a7a/report.json a7b/report.json.",
			"Run: openvapt demo vulnerable --fail-on critical --out a7c; echo $? and explain the exit code.",
		},
		Quiz: []Question{
			{"What does shifting left mean?", []string{"Moving servers to another data centre", "Testing earlier in development, close to each change", "Running tests only before release", "Writing code from left to right"}, 1, "Earlier tests find problems while they are cheap to fix."},
			{"What is a regression?", []string{"A new feature", "Something that worked and broke again", "A slow test", "An old report"}, 1, "Comparing reports over time catches regressions."},
			{"Which exit code means findings reached the --fail-on severity?", []string{"0", "2", "3", "6"}, 2, "Exit code 3 signals unsuppressed findings at or above the chosen severity."},
			{"How should an accepted risk be handled in a pipeline?", []string{"Delete the check", "Record it in a suppression file with a reason and an expiry", "Turn off the pipeline", "Lower every severity"}, 1, "Suppressions keep the decision visible and make it expire."},
			{"What is SARIF used for?", []string{"Encrypting reports", "Showing findings in code review and analysis tools", "Compressing logs", "Signing releases"}, 1, "SARIF is a standard format that review tools can display."},
		},
		Refs: []Ref{{"OASIS, Static Analysis Results Interchange Format (SARIF) Version 2.1.0", "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html"}, refNIST115},
	},
	{
		ID: "A8", Title: "Tracing Findings to Security Requirements", Level: Applied, Minutes: 20,
		Prereqs: []string{"A2"},
		Summary: "How to write security requirements that can be verified, and how standard identifiers link each finding back to the requirement it breaks.",
		Objectives: []string{
			"Write a security requirement that can be checked.",
			"Use OWASP ASVS, CIS Controls and NIST CSF identifiers to trace findings.",
			"Show coverage: which requirements were checked and which were not.",
		},
		Sections: []Section{
			{"Requirements Come First", []string{
				"A test can only pass or fail against an expectation. Security work goes better when the expectations are written down before the system is built.",
				"A good requirement is specific and checkable. Compare \"the site must be secure\" with \"responses must not reveal the server version\".",
			}},
			{"Traceability", []string{
				"Traceability links each requirement to the tests that check it and each finding to the requirement it breaks. It answers two questions: was this tested, and why does this matter?",
			}},
			{"Using Public Standards", []string{
				"Public standards give requirements stable identifiers. OWASP ASVS lists verifiable web application requirements, and CIS Controls and NIST CSF describe organisational safeguards.",
				"OpenVAPT tags each check with these identifiers where a clear match exists, so a report can be sorted by requirement instead of by finding.",
			}},
			{"Coverage Is Not Completeness", []string{
				"A requirement with no check is not proven met. Reports should say which requirements were checked automatically and which still need a person to review.",
			}},
			{"In Summary", []string{
				"Write checkable requirements, link findings to them with standard identifiers, and be honest about which requirements no automated check covers.",
			}},
		},
		KeyTerms:      []string{"Traceability", "Verification", "Evidence"},
		RelatedChecks: []string{"WEB-HDR-"},
		Lab: []string{
			"Run: openvapt checks --json and list the web checks that carry an ASVS identifier.",
			"Rewrite three vague requirements from a project you know as specific, checkable statements.",
		},
		Quiz: []Question{
			{"Which requirement can be verified?", []string{"The site must be secure", "Responses must not reveal the web server version", "Security is a priority", "Hackers must be stopped"}, 1, "A specific, observable statement can pass or fail."},
			{"What does traceability link?", []string{"Servers to cables", "Requirements to tests and findings to requirements", "Users to passwords", "Logs to backups"}, 1, "Traceability shows what was tested and why a finding matters."},
			{"What is OWASP ASVS?", []string{"A firewall product", "A list of verifiable web application security requirements", "A programming language", "A certificate authority"}, 1, "ASVS gives each web security requirement a stable identifier."},
			{"A requirement has no matching check. What should a report say?", []string{"That it passed", "That it was not checked automatically and needs review", "Nothing", "That it failed"}, 1, "Unchecked is not the same as met. Honest reports show the gap."},
			{"Why tag checks with standard identifiers?", []string{"To make reports longer", "So findings can be grouped by requirement and compared across tools", "To hide the check name", "Because the law requires one standard"}, 1, "Shared identifiers let teams map results to the requirements they follow."},
		},
		Refs: []Ref{testingAIRefASVS, {"CIS Critical Security Controls", "https://www.cisecurity.org/controls"}},
	},
}

var testingAITerms = map[string]string{
	"Equivalence Partitioning": "Grouping inputs that a system should treat the same way, then testing one representative of each group.",
	"Boundary Value":           "An input at the edge of a group, such as the largest allowed number; mistakes often appear exactly there.",
	"Model Server":             "A program that loads an AI model and answers requests over a network port, such as Ollama or LM Studio.",
	"Vector Database":          "A database that stores numeric representations of documents for AI search; it often holds copies of private text.",
	"Rate Limiting":            "Capping how many requests one client may send in a period, so a flood or a password guessing run slows down.",
	"Slowloris":                "An attack that opens many requests and sends them very slowly, keeping every web server worker busy.",
	"Shift Left":               "Moving testing earlier in development, so problems are found close to the change that caused them.",
	"Regression Testing":       "Re-running tests after a change to catch things that used to work and broke again.",
	"Traceability":             "Links between requirements, the tests that check them and the findings that break them.",
}

func init() {
	Modules = append(Modules, testingAI...)
	for k, v := range testingAITerms {
		if _, dup := Glossary[k]; dup {
			panic("duplicate glossary term " + k)
		}
		Glossary[k] = v
	}
	// Place the new modules in the semester course so every module is taught.
	if c := CourseByID("semester-14"); c != nil {
		for i := range c.Sessions {
			switch c.Sessions[i].Week {
			case 11:
				c.Sessions[i].Modules = append(c.Sessions[i].Modules, "P24", "P25")
			case 12:
				c.Sessions[i].Modules = append(c.Sessions[i].Modules, "P23")
			case 14:
				c.Sessions[i].Modules = append(c.Sessions[i].Modules, "A7", "A8")
			}
		}
	}
}
