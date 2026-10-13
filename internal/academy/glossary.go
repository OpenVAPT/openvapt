package academy

import "sort"

// Glossary defines every key term used in the course, in plain words.
// A test ensures every module's KeyTerms has an entry here.
var Glossary = map[string]string{
	"ASLR":                      "Address space layout randomisation: the kernel places code and data at unpredictable memory addresses, which makes memory-corruption exploits harder.",
	"Asset":                     "Anything of value that needs protection, such as data, a service, a system or a reputation.",
	"Attack Surface":            "All the points where an attacker could try to interact with a system, such as listening ports, web pages and accounts.",
	"Baseline":                  "A previous report or known-good state used for comparison, so changes and regressions can be seen.",
	"Brute Force":               "Trying many passwords or keys in turn until one works.",
	"CIA Triad":                 "Confidentiality, integrity and availability: the three properties information security protects.",
	"CSRF":                      "Cross-site request forgery: tricking a logged-in user's browser into sending an unwanted request to another site.",
	"CVE":                       "Common Vulnerabilities and Exposures: an identifier for one specific, publicly known vulnerability in a product.",
	"CVSS":                      "Common Vulnerability Scoring System: a standard way to rate how severe a vulnerability is, from 0.0 to 10.0.",
	"CWE":                       "Common Weakness Enumeration: a catalogue of weakness types, such as incorrect permission assignment.",
	"Certificate":               "A signed digital document that binds a public key to names such as a website's domain, used by TLS to prove identity.",
	"Change Management":         "A controlled process for making changes to systems, with testing, approval and a way to roll back.",
	"Cipher":                    "An algorithm that encrypts and decrypts data.",
	"Cleartext":                 "Data sent or stored without encryption, readable by anyone who can see it.",
	"Clickjacking":              "Tricking a user into clicking something on a hidden, framed copy of another site.",
	"Content Security Policy":   "An HTTP response header that tells browsers which sources of scripts and other content a page may load.",
	"Cookie Flags":              "Attributes such as Secure, HttpOnly and SameSite that control when and how a browser sends or exposes a cookie.",
	"Cross-Site Scripting":      "XSS: injecting script into a web page so it runs in other users' browsers.",
	"Default Deny":              "A firewall or access policy that blocks everything except what is explicitly allowed.",
	"Defence in Depth":          "Using several independent layers of protection so that one failure does not lead to compromise.",
	"Detection Logic":           "The exact rules a check uses to decide whether a weakness is present.",
	"Directory Listing":         "A web server feature that shows every file in a folder when there is no index page.",
	"Downgrade Attack":          "Forcing a connection to use a weaker protocol or no encryption, for example from HTTPS to HTTP.",
	"Dry Run":                   "Previewing what an operation would do without performing it.",
	"End of Life":               "The date after which a product no longer receives security fixes from its maintainer.",
	"Evidence":                  "The observed data, such as a configuration line, that supports a finding.",
	"False Negative":            "A real problem that a tool fails to report.",
	"False Positive":            "A reported problem that is not real.",
	"Firewall":                  "Software or hardware that allows or blocks network traffic according to rules.",
	"HSTS":                      "HTTP Strict Transport Security: a header that tells browsers to use only HTTPS for a site.",
	"Hardening":                 "Reducing a system's attack surface and weaknesses through configuration.",
	"Information Disclosure":    "Exposing information, such as versions, paths or secrets, that helps an attacker.",
	"Key Exchange":              "The method two parties use to agree on encryption keys over an untrusted network.",
	"Least Privilege":           "Giving every account and process only the access it needs, nothing more.",
	"Limitations":               "A report's honest statement of what was not tested or could not be determined.",
	"Loopback":                  "The network interface that only reaches the same machine: 127.0.0.0/8 for IPv4 and ::1 for IPv6.",
	"MAC":                       "Message authentication code: a value that proves a message was not altered and came from someone with the key.",
	"NIST SP 800-115":           "A NIST guide describing how to plan, perform and report technical security testing and assessment.",
	"Patch Management":          "The process of finding, testing and installing software updates, especially security fixes.",
	"Penetration Testing":       "Authorised testing that tries to exploit weaknesses to demonstrate real impact.",
	"Privilege Escalation":      "Gaining higher privileges than intended, for example turning a normal user account into root.",
	"Password Hashing":          "Storing a one-way, salted, deliberately slow transformation of a password instead of the password itself.",
	"Account Lockout":           "Temporarily blocking an account after repeated failed logins to stop password guessing.",
	"Open Relay":                "A mail server that forwards mail from anyone to anyone, which spammers abuse.",
	"DNS Recursion":             "A DNS server resolving names on behalf of clients; open to everyone, it can amplify denial-of-service attacks.",
	"Container":                 "A group of processes isolated from the host and from each other by kernel namespaces, cgroups and capabilities.",
	"Namespace":                 "A Linux kernel feature that gives processes their own view of resources such as process ids, network or mounts.",
	"Capability":                "One of the separate privileges that together make up root's power, which can be granted or dropped individually.",
	"Port":                      "A number that identifies a network service on a machine, such as 22 for SSH or 443 for HTTPS.",
	"Public-Key Authentication": "Logging in by proving possession of a private key instead of typing a password.",
	"Remediation":               "Fixing a weakness or reducing its risk to an acceptable level.",
	"Report Signing":            "Adding a digital signature to a report so recipients can confirm it was not edited.",
	"Risk":                      "The combination of how likely harm is and how serious it would be.",
	"Rules of Engagement":       "The agreed rules for a security test: what may be tested, when, how and by whom.",
	"SARIF":                     "Static Analysis Results Interchange Format: an OASIS standard JSON format for tool findings.",
	"SUID":                      "Set-user-ID: a file permission that makes a program run with its owner's privileges, often root.",
	"Scope":                     "The exact systems and activities an assessment is allowed to cover.",
	"Secrets Management":        "Keeping passwords, keys and tokens out of code and public places, and rotating them safely.",
	"Security Misconfiguration": "A weakness caused by insecure settings rather than a software bug.",
	"Severity":                  "How serious a finding is, often expressed as Critical, High, Medium or Low.",
	"Sticky Bit":                "A permission on shared directories such as /tmp that stops users deleting each other's files.",
	"TLS":                       "Transport Layer Security: the protocol that encrypts connections such as HTTPS.",
	"Test Fixture":              "Prepared data or a simulated environment used to test software repeatably.",
	"Threat":                    "Anything that could cause harm to an asset, such as an attacker or a failure.",
	"Triage":                    "Sorting findings by importance and validity to decide what to handle first.",
	"VAPT":                      "Vulnerability Assessment and Penetration Testing: finding and rating weaknesses, then proving their impact.",
	"Verification":              "Confirming that a fix actually removed the weakness.",
	"Vulnerability":             "A weakness that a threat could use to cause harm.",
	"Vulnerability Assessment":  "Finding and rating known weaknesses without exploiting them.",
}

// Terms returns glossary terms sorted alphabetically.
func Terms() []string {
	out := make([]string, 0, len(Glossary))
	for t := range Glossary {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
