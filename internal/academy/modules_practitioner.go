package academy

var practitioner = []Module{
	{
		ID: "P1", Title: "Linux Server Hardening", Level: Practitioner, Minutes: 30,
		Summary: "Patching, accounts, privileges, file permissions, scheduled jobs and kernel settings: the foundations of a defensible Linux server.",
		Objectives: []string{
			"Explain why unsupported releases and pending security updates are high risk.",
			"Recognise dangerous account, sudo and permission configurations.",
			"Explain what common kernel hardening parameters protect against.",
		},
		Sections: []Section{
			{"Patching and Support Lifecycles", []string{
				"Most real-world compromises use vulnerabilities that already had a fix. A release past end of life receives no more fixes, so every new flaw stays open forever. Keeping a supported release and installing security updates promptly removes the largest class of risk on most servers.",
			}},
			{"Accounts and Privileges", []string{
				"Any account with user id 0 is root, whatever its name. Accounts with empty passwords can log in with nothing. Sudo rules marked NOPASSWD turn any takeover of that user into instant root. Each of these violates least privilege.",
			}},
			{"Permissions, SUID and Cron", []string{
				"World-writable files under /etc or in cron directories let any local user change what root runs. SUID programs run with their owner's rights; one placed in /tmp or a web folder is a classic privilege escalation trick. The sticky bit on /tmp stops users deleting each other's files.",
			}},
			{"Kernel Hardening and Logging", []string{
				"Kernel parameters such as address space layout randomisation, restricted kernel pointers and disabled ICMP redirects make exploitation harder. Persistent logs, an audit daemon and synchronised time are what let you investigate afterwards.",
			}},
		},
		KeyTerms:      []string{"End of Life", "Patch Management", "Least Privilege", "SUID", "Sticky Bit", "ASLR", "Hardening"},
		RelatedChecks: []string{"HOST-OS-", "HOST-PKG-", "HOST-UPD-", "HOST-FS-", "HOST-KRN-", "HOST-MAC-", "HOST-SVC-", "HOST-LOG-", "HOST-TIME-", "HOST-IDS-"},
		Lab: []string{
			"Run: openvapt demo --only HOST- --out p1",
			"For each failed HOST check, find the line in internal/lab/lab.go that differs between the vulnerable and hardened server.",
			"On a test machine you own: sudo openvapt scan --only HOST- and compare.",
		},
		Quiz: []Question{
			{"Why is an operating system past end of life high risk?", []string{"It runs slower", "New vulnerabilities in it will never be fixed", "It cannot run Go programs"}, 1, "No more security fixes means every future flaw stays open."},
			{"An account named backup has UID 0. What does that mean?", []string{"It is a normal user", "It has full root privileges", "It cannot log in"}, 1, "UID 0 is root regardless of the account name."},
			{"What does kernel.randomize_va_space = 2 provide?", []string{"Full address space layout randomisation", "Faster networking", "Disk encryption"}, 0, "Value 2 randomises stack, libraries, heap and VDSO."},
		},
		Refs: []Ref{{"NIST SP 800-123, Guide to General Server Security", "https://csrc.nist.gov/pubs/sp/800/123/final"}, {"NIST SP 800-40 Rev. 4, Enterprise Patch Management", "https://csrc.nist.gov/pubs/sp/800/40/r4/final"}},
	},
	{
		ID: "P2", Title: "SSH Security", Level: Practitioner, Minutes: 15,
		Summary: "How SSH authentication and cryptography settings decide whether remote administration is a strength or a door.",
		Objectives: []string{
			"Explain why key-based authentication beats passwords for SSH.",
			"Explain the risk of direct root login.",
			"Identify weak SSH ciphers, MACs and key exchange methods.",
		},
		Sections: []Section{
			{"Authentication", []string{
				"Internet-facing SSH is guessed at constantly by automated tools. Public-key authentication cannot be guessed like a password and is not reused across sites. Disabling password and keyboard-interactive logins, and refusing empty passwords, removes guessing as an attack.",
			}},
			{"Root Login and Attempt Limits", []string{
				"Root is the one account name every attacker knows, and logging in as root directly loses the record of which person acted. Log in as a named user and use sudo. A low MaxAuthTries makes guessing slower and noisier.",
			}},
			{"Cryptography", []string{
				"Old algorithms such as CBC-mode ciphers, RC4, MD5 and SHA-1 MACs, and 1024-bit Diffie-Hellman have known weaknesses. Modern OpenSSH defaults are strong; most weak settings come from old custom configuration lines.",
			}},
		},
		KeyTerms:      []string{"Public-Key Authentication", "Brute Force", "Cipher", "MAC", "Key Exchange"},
		RelatedChecks: []string{"HOST-SSH-"},
		Lab: []string{
			"Run: openvapt explain HOST-SSH-004 and read the detection logic.",
			"Run: openvapt demo --only HOST-SSH- and read the evidence lines for each finding.",
			"On your own server: sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|ciphers'",
		},
		Quiz: []Question{
			{"Why is public-key authentication stronger than passwords for SSH?", []string{"Keys cannot be guessed by trying common passwords", "Keys make SSH faster", "Keys hide the server"}, 0, "Keys remove password guessing and reuse as attack paths."},
			{"PermitRootLogin prohibit-password means:", []string{"Root may log in with a password", "Root may log in only with a key", "Root may never log in"}, 1, "It blocks password logins for root while allowing keys."},
			{"Which algorithm family is considered weak?", []string{"aes256-gcm", "chacha20-poly1305", "aes128-cbc"}, 2, "CBC-mode SSH ciphers have known weaknesses."},
		},
		Refs: []Ref{{"OpenBSD, sshd_config(5)", "https://man.openbsd.org/sshd_config"}, {"RFC 9142, Key Exchange Method Updates for SSH", "https://www.rfc-editor.org/rfc/rfc9142"}},
	},
	{
		ID: "P3", Title: "Network Exposure and Firewalls", Level: Practitioner, Minutes: 20,
		Summary: "What a server exposes to the network, why databases and cleartext services should not be reachable, and how a host firewall acts as a safety net.",
		Objectives: []string{
			"Explain the difference between binding to 127.0.0.1 and to 0.0.0.0.",
			"Explain why exposed databases and caches cause mass breaches.",
			"Explain default-deny firewall policy.",
		},
		Sections: []Section{
			{"Listening Services and Attack Surface", []string{
				"Every listening port is part of the attack surface. A service bound to 127.0.0.1 or ::1 is reachable only from the machine itself; one bound to 0.0.0.0, :: or a public address is reachable from the network unless a firewall blocks it. OpenVAPT reads this from the kernel's own socket tables instead of port scanning.",
			}},
			{"Databases, Caches and Cleartext Protocols", []string{
				"Redis, MongoDB, Elasticsearch and Memcached exposed to the internet, often without authentication, have caused many large data breaches and ransom wipes. Telnet, FTP, rsh and plain POP3, IMAP or LDAP send passwords unencrypted.",
			}},
			{"Host Firewalls", []string{
				"A default-deny host firewall allows only the ports you intend, such as SSH and HTTPS, and drops everything else. It protects you when a service is installed or misconfigured by mistake. Always allow SSH before enabling a firewall on a remote server.",
			}},
		},
		KeyTerms:      []string{"Attack Surface", "Port", "Loopback", "Firewall", "Default Deny", "Cleartext"},
		RelatedChecks: []string{"NET-LSN-", "NET-DB-", "NET-SVC-", "NET-FW-"},
		Lab: []string{
			"Run: openvapt demo --only NET- --out p3 and open the NET-LSN-001 evidence.",
			"Compare the vulnerable lab (MySQL and Redis on 0.0.0.0) with the hardened lab (127.0.0.1).",
			"On your own server: ss -tulpn and classify each socket as local only or network reachable.",
		},
		Quiz: []Question{
			{"A service bound to 127.0.0.1 is reachable from:", []string{"The whole internet", "Only the same machine", "Only the local network"}, 1, "Loopback addresses never leave the machine."},
			{"What does a default-deny firewall policy do?", []string{"Blocks everything not explicitly allowed", "Allows everything not explicitly blocked", "Logs traffic only"}, 0, "Default deny allows only what you intend."},
			{"Why is Telnet considered insecure?", []string{"It is slow", "It sends credentials unencrypted", "It only works on Windows"}, 1, "Anyone on the path can read the password."},
		},
		Refs: []Ref{{"NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy", "https://csrc.nist.gov/pubs/sp/800/41/r1/final"}, {"OWASP Database Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"}},
	},
	{
		ID: "P4", Title: "TLS, Certificates and HTTPS", Level: Practitioner, Minutes: 20,
		Summary: "How encryption in transit works in practice, which TLS versions are acceptable, and how certificates and HSTS keep users safe.",
		Objectives: []string{
			"Explain why TLS 1.0 and 1.1 are deprecated.",
			"Recognise expired, self-signed and mismatched certificates.",
			"Explain what HSTS and HTTP-to-HTTPS redirects protect against.",
		},
		Sections: []Section{
			{"Protocol Versions", []string{
				"TLS 1.0 and 1.1 were formally deprecated by RFC 8996 in 2021. Servers should offer TLS 1.2 and TLS 1.3 only. OpenVAPT tests this by attempting handshakes limited to the old versions against 127.0.0.1.",
			}},
			{"Certificates", []string{
				"A certificate proves a server's identity for the names it lists. Expired, self-signed or mismatched certificates cause browser warnings, which train users to click through the very warning that protects them from interception.",
			}},
			{"HTTPS Everywhere", []string{
				"Serving pages over plain HTTP lets anyone on the path read or change them. Redirecting HTTP to HTTPS, and sending Strict-Transport-Security so browsers refuse to downgrade, closes that gap.",
			}},
		},
		KeyTerms:      []string{"TLS", "Certificate", "HSTS", "Downgrade Attack"},
		RelatedChecks: []string{"NET-TLS-", "WEB-TLS-001", "WEB-HDR-001"},
		Lab: []string{
			"Run: openvapt demo --only NET-TLS-,WEB-TLS-001,WEB-HDR-001",
			"On your own server: openssl s_client -connect 127.0.0.1:443 -tls1_1 </dev/null and explain the result.",
		},
		Quiz: []Question{
			{"Which TLS versions should a server offer today?", []string{"TLS 1.0 and above", "TLS 1.2 and TLS 1.3", "SSL 3.0 and TLS 1.0"}, 1, "RFC 8996 deprecated TLS 1.0 and 1.1."},
			{"What does HSTS do?", []string{"Encrypts the database", "Tells browsers to always use HTTPS for the site", "Blocks bots"}, 1, "It prevents downgrade to plain HTTP."},
			{"Why are self-signed certificates a problem on public sites?", []string{"Browsers do not trust them, so users learn to ignore warnings", "They expire faster", "They use weak keys"}, 0, "Trained click-through removes protection against interception."},
		},
		Refs: []Ref{{"RFC 8996, Deprecating TLS 1.0 and TLS 1.1", "https://www.rfc-editor.org/rfc/rfc8996"}, {"NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations", "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}, {"RFC 6797, HTTP Strict Transport Security", "https://www.rfc-editor.org/rfc/rfc6797"}},
	},
	{
		ID: "P5", Title: "Web Security Headers and Cookies", Level: Practitioner, Minutes: 20,
		Summary: "The HTTP response headers and cookie flags that let browsers defend users against cross-site scripting, clickjacking and session theft.",
		Objectives: []string{
			"Explain what Content-Security-Policy, X-Frame-Options and X-Content-Type-Options defend against.",
			"Explain the Secure, HttpOnly and SameSite cookie flags.",
		},
		Sections: []Section{
			{"Browser-Enforced Defences", []string{
				"A Content-Security-Policy limits where scripts can load from, turning many cross-site scripting bugs into blocked requests. frame-ancestors or X-Frame-Options stop other sites framing yours for clickjacking. nosniff stops browsers guessing file types. Referrer-Policy and Permissions-Policy limit data leakage and powerful features.",
			}},
			{"Cookie Flags", []string{
				"Secure keeps a cookie off plain HTTP. HttpOnly hides it from JavaScript, so an XSS bug cannot read the session. SameSite limits when it is sent with cross-site requests, which reduces cross-site request forgery.",
			}},
		},
		KeyTerms:      []string{"Content Security Policy", "Cross-Site Scripting", "Clickjacking", "Cookie Flags", "CSRF"},
		RelatedChecks: []string{"WEB-HDR-002", "WEB-HDR-003", "WEB-HDR-004", "WEB-HDR-005", "WEB-HDR-006", "WEB-CK-", "WEB-COR-", "WEB-SEC-", "WEB-PHP-005"},
		Lab: []string{
			"Run: openvapt demo --only WEB-HDR-,WEB-CK-",
			"Open your browser's developer tools on any site you own and compare its response headers with the checks.",
		},
		Quiz: []Question{
			{"Which header limits where scripts may load from?", []string{"Referrer-Policy", "Content-Security-Policy", "Server"}, 1, "CSP controls allowed sources for scripts and other resources."},
			{"The HttpOnly cookie flag:", []string{"Hides the cookie from JavaScript", "Encrypts the cookie", "Makes the cookie permanent"}, 0, "XSS cannot read HttpOnly cookies."},
			{"Clickjacking is prevented by:", []string{"frame-ancestors or X-Frame-Options", "HSTS", "Compression"}, 0, "They stop other sites embedding your pages."},
		},
		Refs: []Ref{{"OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/"}, {"OWASP Session Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"}},
	},
	{
		ID: "P6", Title: "Information Exposure and Misconfiguration", Level: Practitioner, Minutes: 25,
		Summary: "How forgotten files, verbose errors and version banners hand attackers the map, and sometimes the keys.",
		Objectives: []string{
			"Explain the impact of exposed .git folders, .env files and backups.",
			"Explain why directory listing, status pages and version disclosure matter.",
			"Recognise risky PHP and CMS settings.",
		},
		Sections: []Section{
			{"Forgotten Files", []string{
				"An exposed .git folder lets anyone rebuild your source code and its history, often including committed secrets. A downloadable .env file usually means full compromise. Backups and SQL dumps left in the web root contain whole databases.",
			}},
			{"Reconnaissance Leaks", []string{
				"Directory listings show every file in a folder. Server status pages show live requests. Version numbers in headers let attackers match you to public exploit lists in seconds. Hiding versions does not fix vulnerabilities, but removes free reconnaissance.",
			}},
			{"Platform Settings", []string{
				"PHP's display_errors prints internals into pages, and allow_url_include turns a file-inclusion bug into remote code execution. Unsupported PHP versions stop receiving fixes. WordPress version disclosure and an open XML-RPC endpoint invite automated attacks.",
			}},
		},
		KeyTerms:      []string{"Information Disclosure", "Security Misconfiguration", "Directory Listing", "Secrets Management"},
		RelatedChecks: []string{"WEB-EXP-", "WEB-DOC-", "WEB-PHP-", "WEB-CMS-", "WEB-HDR-007"},
		Lab: []string{
			"Run: openvapt demo --only WEB-EXP-,WEB-PHP-,WEB-CMS- and read how the evidence is redacted.",
			"Find the bodyHas markers in internal/checks/web/exposure.go and explain how they avoid soft-404 false positives.",
		},
		Quiz: []Question{
			{"Why is an exposed .git folder serious?", []string{"It slows the site", "Anyone can rebuild the source code and history, including secrets", "It breaks HTTPS"}, 1, "History often contains credentials committed by mistake."},
			{"What should you do after finding an exposed .env file?", []string{"Delete it only", "Block it, remove it and rotate every secret in it", "Rename it"}, 1, "Treat every secret in it as leaked."},
			{"Why does OpenVAPT require content markers, not just HTTP 200?", []string{"To avoid false positives from sites that return 200 for every path", "To save bandwidth", "Because 200 means error"}, 0, "Soft-404 pages would otherwise trigger every check."},
		},
		Refs: []Ref{{"OWASP Top 10 2021, A05 Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"}, {"OWASP Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}},
	},
	{
		ID: "P7", Title: "Identity, Passwords and Privilege", Level: Practitioner, Minutes: 25,
		Summary: "How accounts, password storage, lockout and privilege escalation paths decide who really controls a server.",
		Objectives: []string{
			"Explain why password hashing algorithms and lengths matter.",
			"Recognise privilege escalation paths: UID 0 accounts, NOPASSWD sudo and the docker group.",
			"Explain why legacy trust files and service account shells are risky.",
		},
		Sections: []Section{
			{"Storing Passwords", []string{
				"Linux stores password hashes in /etc/shadow. Modern algorithms such as yescrypt and SHA-512 crypt are salted and deliberately slow, so a stolen shadow file is expensive to crack. MD5-crypt and DES are fast and obsolete. Old hashes stay until each user changes their password.",
				"NIST SP 800-63B emphasises length over complexity rules and recommends blocking known-breached passwords. A minimum of 12 characters and an account lockout after repeated failures make online guessing impractical.",
			}},
			{"Who Is Really Root", []string{
				"Root is not a name but user id 0. Extra UID 0 accounts, duplicate UIDs, NOPASSWD sudo rules and membership of the docker group (which can mount the host filesystem) all give root, often without a password.",
				"Sudo should run commands in a pseudo-terminal and log them to a dedicated file, so privileged actions are recorded and cannot linger.",
			}},
			{"Legacy Trust", []string{
				".rhosts and .shosts files trust whole machines instead of people, and .netrc files hold plain-text passwords. Legacy '+' NIS entries can import unexpected accounts. Service accounts should never have a login shell.",
			}},
		},
		KeyTerms:      []string{"Least Privilege", "Brute Force", "Privilege Escalation", "Password Hashing", "Account Lockout"},
		RelatedChecks: []string{"HOST-USR-", "HOST-PWD-", "HOST-SUDO-", "HOST-DKR-"},
		Lab: []string{
			"Run: openvapt demo --only HOST-USR-,HOST-PWD-,HOST-SUDO-,HOST-DKR- --out p7",
			"For each finding, explain how an attacker would turn it into root access.",
			"On your own machine: getent group docker sudo wheel and review who is listed.",
		},
		Quiz: []Question{
			{"Why is yescrypt or SHA-512 crypt preferred over MD5-crypt?", []string{"They are salted and deliberately slow to crack", "They make passwords shorter", "They encrypt the whole disk"}, 0, "Slow, salted hashing makes offline cracking expensive."},
			{"Why is membership of the docker group dangerous?", []string{"It slows the server", "It allows starting containers that mount the host filesystem, which is root access", "It disables SSH"}, 1, "Docker control is equivalent to root on the host."},
			{"What does an account lockout policy defend against?", []string{"Password guessing", "Disk failure", "TLS downgrade"}, 0, "Lockout limits repeated guesses."},
		},
		Refs: []Ref{{"NIST SP 800-63B, Authentication and Lifecycle Management", "https://pages.nist.gov/800-63-3/sp800-63b.html"}, {"MITRE ATT&CK T1548, Abuse Elevation Control Mechanism", "https://attack.mitre.org/techniques/T1548/"}},
	},
	{
		ID: "P8", Title: "Data Services: Databases, File Shares, DNS and Mail", Level: Practitioner, Minutes: 30,
		Summary: "Why databases, caches, file shares, DNS and mail servers cause so many breaches, and the configuration settings that decide whether they are safe.",
		Objectives: []string{
			"Explain why databases and caches must require authentication and bind to loopback.",
			"Recognise unsafe NFS exports and Samba guest access.",
			"Explain open DNS recursion, zone transfers and open mail relays.",
		},
		Sections: []Section{
			{"Databases and Caches", []string{
				"Redis, MongoDB, Elasticsearch and Memcached were designed for trusted networks and have historically shipped without authentication. Exposed instances are found by internet-wide scanners within hours and wiped or ransomed. PostgreSQL 'trust' entries in pg_hba.conf allow login with no password at all, and MySQL's local_infile lets a compromised application read server files.",
				"The safe pattern is the same everywhere: bind to 127.0.0.1 or a private interface, require authentication, and allow only the application servers that need access through the firewall.",
			}},
			{"File Shares", []string{
				"NFS exports with no_root_squash let a remote root user act as root on the share, and exports to '*' let anyone mount them. Samba shares with guest access, or servers still allowing SMB1, expose files to anonymous users and to old, wormable protocol flaws.",
			}},
			{"DNS and Mail", []string{
				"A DNS server that answers recursive queries for anyone is used to amplify denial-of-service attacks, and one that allows zone transfers to anyone publishes the whole internal name map. A mail server whose relay rules are too broad becomes a spam relay, and allowing passwords over unencrypted connections exposes mail accounts.",
			}},
		},
		KeyTerms:      []string{"Attack Surface", "Default Deny", "Open Relay", "DNS Recursion", "Cleartext"},
		RelatedChecks: []string{"NET-DB-", "NET-SVC-002", "NET-SVC-003"},
		Lab: []string{
			"Run: openvapt demo --only NET-DB- --out p8 and read the evidence for each data service.",
			"For each finding, name the single configuration line that fixes it.",
			"On your own server: ss -tlnp and match each database or cache port to its bind setting.",
		},
		Quiz: []Question{
			{"Why are exposed Redis or MongoDB instances so often breached?", []string{"They are slow", "They historically ran without authentication and are found quickly by internet-wide scanners", "They use too much memory"}, 1, "Unauthenticated, internet-reachable data services are found and abused quickly."},
			{"What does no_root_squash on an NFS export allow?", []string{"A remote root user to act as root on the share", "Faster file copies", "Encrypted transfers"}, 0, "Root on a client keeps root rights on the share."},
			{"Why is open DNS recursion dangerous?", []string{"It slows name resolution", "It can be abused to amplify denial-of-service attacks", "It deletes zones"}, 1, "Open resolvers amplify traffic toward victims."},
		},
		Refs: []Ref{{"OWASP Database Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"}, {"CISA, DNS Amplification Attacks (Alert TA13-088A)", "https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks"}, {"Redis security", "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"}},
	},
}
