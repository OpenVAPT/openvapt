package academy

// Practitioner modules on service hardening, firewall correlation,
// application servers and CMS hardening.
var stacks = []Module{
	{
		ID: "P11", Title: "Service Hardening With systemd", Level: Practitioner, Minutes: 25,
		Summary: "How systemd starts services, why most services should not run as root, and how a few unit settings contain a compromised application.",
		Prereqs: []string{"P1"},
		Objectives: []string{
			"Read a systemd unit file and its drop-ins and know which settings win.",
			"Explain why a service's user, program location and unit file permissions decide what an attacker gains.",
			"Apply basic sandboxing settings and keep secrets out of unit files.",
		},
		Sections: []Section{
			{"How a Service Starts", []string{
				"systemd reads a service's unit file from /usr/lib/systemd/system or /lib/systemd/system (packages) or /etc/systemd/system (the administrator), then applies drop-in files from <name>.service.d/*.conf in order. ExecStart= names the program, User= the account it runs as. With no User= the service runs as root.",
				"Application services written by administrators, such as a Node.js API or a Django site, are the code most exposed to the internet. Running them as root turns any bug in the application into full control of the machine.",
			}},
			{"Who Can Change What Runs", []string{
				"A service is only as trustworthy as the files that define it. If a normal user can edit the unit file, or replace the program it starts (for example a binary in /tmp, or a file with world-write permission), that user can make systemd run their code as root at the next restart. This is a well-known privilege escalation and persistence technique (MITRE ATT&CK T1543.002 and T1574.010).",
			}},
			{"Sandboxing in a Few Lines", []string{
				"systemd can confine a service without changing its code. NoNewPrivileges=yes stops it gaining privileges through setuid programs; ProtectSystem=strict mounts the operating system read-only for it; PrivateTmp=yes gives it its own /tmp; ProtectHome=yes hides home directories. ReadWritePaths= then lists the few folders it really needs to write. systemd-analyze security <unit> scores how exposed a unit is and suggests more options.",
			}},
			{"Secrets Do Not Belong in Unit Files", []string{
				"Unit files are readable by every user, and systemctl show prints a service's Environment= values to anyone. Passwords and tokens belong in a root-only EnvironmentFile= or, better, in systemd credentials (LoadCredential=), which only the service can read.",
			}},
			{"In Summary", []string{
				"A systemd unit can run a service as a dedicated user inside a sandbox. Each hardening option removes something an attacker could abuse.",
			}},
		},
		KeyTerms:      []string{"Service Unit", "Sandboxing", "Least Privilege", "Privilege Escalation"},
		RelatedChecks: []string{"HOST-SYSD-"},
		Lab: []string{
			"Run: openvapt demo --only HOST-SYSD- --out p11 and list, for each vulnerable unit, the line you would add or change.",
			"Compare the shop-api.service unit in the vulnerable and hardened labs (internal/lab/fixtures_stacks.go) setting by setting.",
			"On a test machine: systemd-analyze security  and pick the service with the worst score; add NoNewPrivileges=yes with systemctl edit and re-run.",
		},
		Quiz: []Question{
			{"A unit file has no User= line. Which account runs the service?", []string{"nobody", "root", "the user who installed it"}, 1, "Without User= or DynamicUser=, systemd runs the service as root."},
			{"Why is a world-writable unit file dangerous?", []string{"It wastes disk space", "Any user can change ExecStart= and have their program run as root", "It slows down boot"}, 1, "Whoever controls the unit controls what root runs."},
			{"Where should a service's database password go?", []string{"Environment= in the unit file", "A root-only EnvironmentFile= or a systemd credential", "The service's description"}, 1, "Unit files and Environment= values are visible to every local user."},
		},
		Refs: []Ref{{"systemd.exec(5)", "https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html"}, {"systemd, System and Service Credentials", "https://systemd.io/CREDENTIALS/"}, {"MITRE ATT&CK T1543.002, Systemd Service", "https://attack.mitre.org/techniques/T1543/002/"}},
	},
	{
		ID: "P12", Title: "Firewall Policy Versus What Is Listening", Level: Practitioner, Minutes: 20,
		Summary: "Why \"the firewall is on\" is not the same as \"the service is protected\", and how to compare firewall rules with the sockets that are really open.",
		Prereqs: []string{"P3"},
		Objectives: []string{
			"Read incoming allow rules from ufw, nftables and iptables.",
			"Correlate firewall rules with listening sockets to find real exposure and stale rules.",
			"Explain how Docker's published ports bypass ufw and the INPUT chain.",
		},
		Sections: []Section{
			{"Exposure Has Two Halves", []string{
				"A service is reachable from the internet when it listens on a non-loopback address and the firewall lets traffic to its port through. Checking either half alone misleads: a default-deny firewall with \"allow 3306 from anywhere\" exposes the database as much as no firewall at all, and an allow rule for a port nothing listens on is a hole waiting for the next service.",
				"OpenVAPT reads the listening sockets from /proc/net and the incoming allow rules from ufw status verbose, nft list ruleset or iptables -S, then labels each socket: allowed from anywhere, allowed from a restricted source, blocked by default deny, or reachable because nothing filters it.",
			}},
			{"Stale Rules", []string{
				"Rules outlive the services they were added for. Each single-port allow rule should match something that listens; if it does not, delete it or write down why it stays. Ranges (for passive FTP or media) are reviewed by hand.",
			}},
			{"Docker and the Firewall", []string{
				"Docker writes its own iptables rules for published ports (-p 8080:80) into the nat table and the DOCKER chain, which traffic reaches before ufw's rules or the INPUT policy. A container port can therefore be open to the world while ufw reports it denied. Publish on 127.0.0.1 behind a reverse proxy, or filter in the DOCKER-USER chain, which Docker evaluates first and never overwrites.",
			}},
			{"In Summary", []string{
				"A firewall rule only matters if it matches what is listening. Compare the two lists. Remove stale rules and close unexpected ports.",
			}},
		},
		KeyTerms:      []string{"Firewall", "Default Deny", "Attack Surface", "Stale Rule"},
		RelatedChecks: []string{"NET-FW-003", "NET-FW-004", "NET-FW-005", "NET-FW-006"},
		Lab: []string{
			"Run: openvapt demo --only NET-FW-,NET-LSN- --out p12 and read the exposure map in NET-FW-006 for both labs (--lab vulnerable and --lab hardened).",
			"On a test machine with ufw: ufw status verbose  and  ss -tlnp ; pair every ALLOW rule with a listening socket by hand.",
			"Explain in two sentences why ufw deny 8080 does not stop docker run -p 8080:80 nginx.",
		},
		Quiz: []Question{
			{"The firewall default-denies incoming traffic but has 'allow 3306 from Anywhere' and MySQL listens on 0.0.0.0. Is MySQL exposed?", []string{"No, the default is deny", "Yes, the allow rule opens it to every address", "Only over IPv6"}, 1, "An explicit allow rule overrides the default policy for that port."},
			{"Why remove an allow rule for a port nothing listens on?", []string{"It slows the firewall", "Anything later started on that port becomes reachable without a decision", "It is required by law"}, 1, "Stale rules are latent exposure."},
			{"Where should you filter traffic to Docker-published ports?", []string{"In ufw only", "In the DOCKER-USER chain, or publish on 127.0.0.1", "In the OUTPUT chain"}, 1, "Docker's rules run before ufw; DOCKER-USER is evaluated first."},
		},
		Refs: []Ref{{"NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy", "https://csrc.nist.gov/pubs/sp/800/41/r1/final"}, {"Docker documentation, Packet filtering and firewalls", "https://docs.docker.com/engine/network/packet-filtering-firewalls/"}},
	},
	{
		ID: "P13", Title: "Application Servers: Tomcat, Node.js and Python", Level: Practitioner, Minutes: 30,
		Summary: "The recurring mistakes when Java, JavaScript and Python applications go to production: exposed app ports, debuggers, development servers, default credentials and unsupported runtimes.",
		Prereqs: []string{"P6"},
		Objectives: []string{
			"Explain why application servers belong behind a reverse proxy, bound to loopback.",
			"Recognise debuggers and development servers that give remote code execution.",
			"Harden the Tomcat Manager, AJP connector and shutdown port, and Django's production settings.",
		},
		Sections: []Section{
			{"Behind the Proxy", []string{
				"Tomcat (8080), Node.js (3000), Gunicorn or Django (8000) and PHP-FPM (9000) are meant to sit behind nginx or Apache, which terminate TLS, add security headers and absorb slow clients. Binding them to 127.0.0.1 keeps those protections in front of every request. Some default ports are worse than unprotected websites: the Node.js inspector (9229), Tomcat AJP (8009), PHP-FPM FastCGI and Jupyter (8888) all hand out code execution to whoever connects.",
			}},
			{"Debuggers and Development Servers", []string{
				"node --inspect opens the V8 debugger with no authentication. The Flask and Werkzeug debugger runs Python typed into an error page. Django with DEBUG = True prints source, settings and SQL on every error. manage.py runserver, flask run and python -m http.server are documented as not for production. In a systemd service, all of these show up in ExecStart= and Environment=, which is where OpenVAPT looks.",
			}},
			{"Tomcat", []string{
				"The Manager application deploys WAR files, so it is code execution behind a password; keep it limited to localhost with a RemoteAddrValve or remove it, and never keep default users such as tomcat/s3cret in tomcat-users.xml. AJP is an unauthenticated trusted protocol: Ghostcat (CVE-2020-1938) read files through any reachable AJP port, so disable the connector or bind it to loopback with a secret. Disable the shutdown port (port=\"-1\") and delete the examples and docs applications.",
			}},
			{"Runtimes Age Out", []string{
				"Node.js release lines reach end of life on a published schedule; after that there are no security releases. Prefer even-numbered LTS lines and plan upgrades before the date, the same way as for the operating system and PHP.",
			}},
			{"In Summary", []string{
				"Application servers belong behind a reverse proxy on loopback. Remove default apps and credentials. Turn off debug mode and keep the runtime supported.",
			}},
		},
		KeyTerms:      []string{"Reverse Proxy", "Debug Mode", "Default Credentials", "End of Life"},
		RelatedChecks: []string{"NET-APP-001", "WEB-TOM-", "WEB-NODE-", "WEB-PY-"},
		Lab: []string{
			"Run: openvapt demo --only NET-APP-,WEB-TOM-,WEB-NODE-,WEB-PY- --out p13",
			"For each vulnerable service in internal/lab/fixtures_stacks.go, write the corrected ExecStart= and Environment= lines.",
			"Read the Tomcat server.xml in both labs and explain what each of the three changes prevents.",
		},
		Quiz: []Question{
			{"Why bind Gunicorn to 127.0.0.1:8000 instead of 0.0.0.0:8000?", []string{"It is faster", "So every request passes through the hardened reverse proxy", "Gunicorn requires it"}, 1, "Loopback binding keeps the proxy's protections in front of the app."},
			{"What does node --inspect=0.0.0.0:9229 give an attacker who can connect?", []string{"Read-only logs", "The ability to run any JavaScript in the application", "Nothing without a password"}, 1, "The inspector has no authentication."},
			{"What is the safest fix for an unused Tomcat AJP connector?", []string{"Change its port", "Remove or comment out the connector", "Add a firewall rule for port 80"}, 1, "A connector that does not exist cannot be attacked."},
		},
		Refs: []Ref{{"Apache Tomcat, Security Considerations", "https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"}, {"Django, Deployment checklist", "https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/"}, {"OWASP Node.js Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html"}},
	},
	{
		ID: "P14", Title: "CMS Hardening in Depth: WordPress, Joomla and Drupal", Level: Practitioner, Minutes: 25,
		Summary: "Beyond version banners: protecting CMS configuration files, switching off debug output and in-browser code editing, and keeping security updates flowing.",
		Prereqs: []string{"P6"},
		Objectives: []string{
			"Set safe permissions on wp-config.php, configuration.php and settings.php.",
			"Turn off debug output and the WordPress file editor in production.",
			"Explain why disabling automatic security updates is a high-risk choice.",
		},
		Sections: []Section{
			{"The Configuration File Is the Crown Jewel", []string{
				"wp-config.php, Joomla's configuration.php and Drupal's settings.php hold the database password and the keys that sign logins, and they are PHP code that runs on every request. Readable by every user, they leak the site to anyone with a shell on the server; writable by others, they become a backdoor. Owner read and write, web server group read (640) is a common safe setting.",
			}},
			{"Debug Output and the File Editor", []string{
				"WP_DEBUG with display on, or Joomla debug and maximum error reporting, print paths and internals into pages. The WordPress Theme and Plugin File Editors let any administrator change PHP from the browser, so one stolen admin session becomes code execution; DISALLOW_FILE_EDIT turns them off.",
			}},
			{"Updates and Fingerprints", []string{
				"WordPress delivers security fixes as automatic minor updates; switching them off leaves the site exposed until someone updates by hand. Version files such as Joomla's joomla.xml manifest and Drupal's CHANGELOG.txt tell attackers exactly which advisories apply. Removing the fingerprint is not a substitute for patching, but there is no reason to publish it.",
			}},
			{"In Summary", []string{
				"A CMS is attacked through its admin pages, plugins and exposed files. Hide versions, lock down file permissions, remove installers and keep everything updated.",
			}},
		},
		KeyTerms:      []string{"Hardening", "Fingerprinting", "Debug Mode", "Patch Management"},
		RelatedChecks: []string{"WEB-CMS-"},
		Lab: []string{
			"Run: openvapt demo --only WEB-CMS- --out p14 and sort the findings by effort.",
			"Write the wp-config.php lines that fix WEB-CMS-006, WEB-CMS-007 and WEB-CMS-008, and the chmod that fixes WEB-CMS-004 and WEB-CMS-005.",
		},
		Quiz: []Question{
			{"What does define('DISALLOW_FILE_EDIT', true) prevent?", []string{"Uploading images", "Editing theme and plugin PHP files from the dashboard", "Logging in"}, 1, "It removes the in-browser code editors."},
			{"Why is a world-readable wp-config.php a problem on a shared server?", []string{"It is not; it has no secrets", "Every local user can read the database password and keys", "It slows WordPress"}, 1, "The file holds credentials and signing keys."},
			{"Is hiding the CMS version enough protection?", []string{"Yes", "No, it only removes a hint; patching is what fixes vulnerabilities", "Only for Drupal"}, 1, "Fingerprint removal complements patching, never replaces it."},
		},
		Refs: []Ref{{"WordPress, Hardening WordPress", "https://developer.wordpress.org/advanced-administration/security/hardening/"}, {"Joomla, Security Checklist", "https://docs.joomla.org/Security_Checklist"}, {"Drupal, Securing file permissions and ownership", "https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-file-permissions-and-ownership"}},
	},
}
