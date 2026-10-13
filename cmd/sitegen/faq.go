package main

// FAQ entries are written as self-contained, factual answers, so that search
// engines (FAQPage rich results) and AI answer engines can quote any single
// answer on its own without losing meaning. Every claim here must stay true
// to the code and the legal documents.
type FAQ struct {
	Q, A string
}

var faqs = []FAQ{
	{"What is OpenVAPT?",
		"OpenVAPT is a free, academic, non-commercial vulnerability assessment (VA) tool for Linux servers, with open-source code on GitHub. It runs read-only checks on the machine it is installed on to identify weaknesses in the server, its network exposure and its websites, rates each finding with CVSS v3.1, proposes a fix with cited sources, and writes a local report. It is made for learning how a vulnerability assessment tool works."},
	{"Is OpenVAPT a free VAPT tool?",
		"Yes. OpenVAPT is free to download and use, with no paid tier, no account and no licence key. It covers the vulnerability assessment (VA) part of VAPT. It does not perform penetration testing (PT): it never exploits or attacks anything."},
	{"Is OpenVAPT open source?",
		"Every line of OpenVAPT's code is public on GitHub at github.com/OpenVAPT/openvapt to read, study and review. It is licensed under the PolyForm Noncommercial License 1.0.0 with an additional own-use permission, so it is source-available rather than open source under the Open Source Initiative definition, because commercial use and providing services are not allowed."},
	{"Can I use OpenVAPT for my company's servers?",
		"Yes, for your own use. Individuals and organisations, including companies, may run OpenVAPT free of charge on computers and servers they own or control, to learn and to assess those same machines. OpenVAPT itself is an academic project, not a business, and it may not be used to provide services to anyone else."},
	{"Can I use OpenVAPT to offer VAPT or security services to clients?",
		"No. OpenVAPT may not be sold, included in a product, or used to provide vulnerability assessment, penetration testing, auditing, scanning or any other service to anyone else, paid or unpaid. It is for academic, learning and own use only."},
	{"Can OpenVAPT scan other servers or websites?",
		"No. OpenVAPT only assesses the machine it runs on. Every network connection is restricted in code to loopback addresses (127.0.0.0/8 and ::1), and host names are never resolved, so it cannot be pointed at another server, network or website."},
	{"Is OpenVAPT a penetration test?",
		"No. OpenVAPT is an automated, non-intrusive vulnerability assessment following the planning, discovery, analysis and reporting phases of NIST SP 800-115, without the attack phase. It contains no exploit code. A report without findings does not prove a system is secure."},
	{"What does OpenVAPT check?",
		"OpenVAPT runs 56 checks: 28 for the server (OS support and patches, SSH, accounts, sudo, file permissions, SUID, cron, kernel hardening, logging, auditing, time sync), 7 for the network (listening services, exposed databases, cleartext services, host firewall, TLS versions and certificates) and 21 for web apps (security headers, cookies, HTTPS redirect, exposed .git, .env and backups, phpinfo, directory listing, status pages, PHP settings and WordPress hygiene)."},
	{"Which standards does OpenVAPT follow?",
		"OpenVAPT follows NIST SP 800-115 for methodology, rates severity with CVSS v3.1, and maps checks to the OWASP Top 10 (2021), OWASP ASVS 4.0.3, CWE and NIST SP 800-53 Rev. 5. Reports are available in HTML, JSON, SARIF 2.1.0 and Markdown."},
	{"Does OpenVAPT collect any data?",
		"No. The OpenVAPT tool makes no connection to any other machine and has no telemetry. The openvapt.com website sets no cookies, has no analytics, forms or accounts, and its server logs are turned off. Reports stay on the user's own machine."},
	{"Is OpenVAPT safe to run on a production server?",
		"OpenVAPT is read-only: it reads files, runs a short allow-list of read-only commands and sends GET requests to local websites through 127.0.0.1. It never changes, installs or restarts anything. Even so, it is provided as is and used 100% at your own risk; test it on a non-production machine first and preview every action with openvapt scan --dry-run."},
	{"How is OpenVAPT different from Lynis, OpenSCAP, OpenVAS, Nuclei or OWASP ZAP?",
		"OpenVAPT is primarily a teaching project: every check is documented and cited to its exact source code, and it combines server, network-exposure and local website checks in one read-only binary that can only assess its own machine. Mature tools such as Lynis and OpenSCAP (host hardening), OpenVAS (network vulnerability scanning), Nuclei (template-based scanning) and OWASP ZAP (web application testing) are broader and better suited to professional work."},
	{"Who made OpenVAPT?",
		"OpenVAPT is run by The OpenVAPT Project, whose operator chooses not to be named publicly. It is developed with substantial help from AI coding assistants: its code, tests, documentation and website were produced by Claude (Anthropic) through Claude Code under the owner's direction and review. The full history is public on GitHub."},
	{"Is OpenVAPT free for students and teachers?",
		"Yes. OpenVAPT is free for anyone. It includes a built-in simulated lab (openvapt demo) with a deliberately vulnerable server and a hardened server, so students can run a full scan, read a real report and compare the fixes on any computer without touching a real machine."},
}
