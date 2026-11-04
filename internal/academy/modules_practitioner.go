package academy

var practitioner = []Module{
	{
		ID: "P1", Title: "Linux Server Hardening", Level: Practitioner, Minutes: 30,
		Summary: "Patching, accounts, privileges, file permissions, scheduled jobs and kernel settings: the foundations of a defensible Linux server.",
		Prereqs: []string{"F1", "F3"},
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
				"Kernel parameters such as address space layout randomisation, restricted kernel pointers and disabled ICMP redirects make exploitation harder. Persistent logs, an audit daemon and synchronised time are what let you investigate afterwards. Module P16 covers them in depth.",
			}},
			{"In Summary", []string{
				"Keep the release supported and patched. Watch for extra root accounts, NOPASSWD sudo rules and loose permissions. Kernel settings make exploitation harder. Logs and time sync let you investigate later.",
			}},
		},
		KeyTerms:      []string{"End of Life", "Patch Management", "Least Privilege", "SUID", "Sticky Bit", "ASLR", "Hardening"},
		RelatedChecks: []string{"HOST-OS-", "HOST-PKG-", "HOST-UPD-", "HOST-FS-", "HOST-KRN-", "HOST-MAC-", "HOST-SVC-"},
		Lab: []string{
			"Run: openvapt demo --only HOST- --out p1",
			"For each failed HOST check, find the line in internal/lab/lab.go that differs between the vulnerable and hardened server.",
			"On a test machine you own: sudo openvapt scan --only HOST- and compare.",
		},
		Quiz: []Question{
			{"Why is an operating system past end of life high risk?", []string{"It runs slower", "New vulnerabilities in it will never be fixed", "It cannot run Go programs", "It cannot be backed up"}, 1, "No more security fixes means every future flaw stays open forever."},
			{"An account named backup has UID 0. What does that mean?", []string{"It is a normal user", "It has full root privileges", "It cannot log in", "It is a system account with limited rights"}, 1, "UID 0 is root regardless of the account name."},
			{"What does kernel.randomize_va_space = 2 provide?", []string{"Full address space layout randomisation", "Faster networking", "Disk encryption", "Kernel module signing"}, 0, "Value 2 randomises the stack, shared libraries, the VDSO and the heap. Random addresses make memory exploits harder."},
			{"Why is a sudo rule marked NOPASSWD risky?", []string{"It logs every command", "Anyone who takes over that user gets root without knowing a password", "It disables sudo for that user", "It only works for root"}, 1, "NOPASSWD turns any takeover of that user into instant root, which breaks least privilege."},
			{"What does the sticky bit on /tmp do?", []string{"Makes files in /tmp permanent", "Stops users deleting each other's files", "Stops programs running from /tmp", "Encrypts /tmp"}, 1, "In a shared folder with the sticky bit, only a file's owner (or root) can delete or rename it."},
			{"Why is a SUID program in a web folder a warning sign?", []string{"It runs with its owner's rights, a classic privilege escalation trick", "It makes the site slower", "The web server cannot read SUID files", "It is the normal way to install web applications"}, 0, "SUID programs run with their owner's rights. One placed where users or a web application can write is a common way to gain root."},
		},
		Refs: []Ref{{"NIST SP 800-123, Guide to General Server Security", "https://csrc.nist.gov/pubs/sp/800/123/final"}, {"NIST SP 800-40 Rev. 4, Enterprise Patch Management", "https://csrc.nist.gov/pubs/sp/800/40/r4/final"}},
	},
	{
		ID: "P2", Title: "SSH Security", Level: Practitioner, Minutes: 15,
		Summary: "How SSH authentication and cryptography settings decide whether remote administration is a strength or a door.",
		Prereqs: []string{"P1"},
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
				"Root is the one account name every attacker knows, and logging in as root directly loses the record of which person acted. Log in as a named user and use sudo. PermitRootLogin no blocks root entirely, and prohibit-password allows root to use keys only. A low MaxAuthTries makes guessing slower and noisier.",
			}},
			{"Cryptography", []string{
				"Old algorithms such as CBC-mode ciphers, RC4 and MD5 MACs have known weaknesses. RFC 9142 deprecates key exchange methods that use SHA-1, including 1024-bit Diffie-Hellman. SHA-1 MACs are also best avoided. Modern OpenSSH defaults are strong. Most weak settings come from old custom configuration lines.",
			}},
			{"In Summary", []string{
				"Use keys, not passwords. Do not let root log in directly. Keep attempt limits low. Remove old cipher, MAC and key exchange lines so OpenSSH uses its modern defaults.",
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
			{"Why is public-key authentication stronger than passwords for SSH?", []string{"Keys cannot be guessed by trying common passwords", "Keys make SSH faster", "Keys hide the server", "Keys let any user log in as root"}, 0, "Keys remove password guessing and password reuse as attack paths."},
			{"PermitRootLogin prohibit-password means:", []string{"Root may log in with a password", "Root may log in only with a key", "Root may never log in", "Root may log in only from the console"}, 1, "It blocks password and keyboard-interactive logins for root while still allowing keys."},
			{"Which SSH cipher is considered weak?", []string{"aes256-gcm", "chacha20-poly1305", "aes128-cbc", "aes256-ctr"}, 2, "CBC-mode SSH ciphers have known weaknesses. GCM, ChaCha20-Poly1305 and CTR modes are accepted."},
			{"Why log in as a named user and use sudo instead of logging in as root?", []string{"Sudo is faster", "It keeps a record of which person acted and avoids the one name every attacker knows", "Root cannot use SSH keys", "It turns off MaxAuthTries"}, 1, "Direct root logins lose the record of who acted, and root is the account name every attacker tries first."},
			{"What does a low MaxAuthTries setting do?", []string{"Blocks the address forever", "Makes guessing slower and noisier by ending a connection after a few failures", "Disables password logins", "Limits the number of open sessions"}, 1, "MaxAuthTries caps failed attempts per connection. Attackers must reconnect more often, which is slower and leaves more log lines."},
			{"Where do most weak SSH cryptography settings come from today?", []string{"Modern OpenSSH defaults", "Old custom configuration lines", "The client's web browser", "RFC 9142"}, 1, "Modern OpenSSH defaults are strong. Weak algorithms usually come from old lines someone added to sshd_config. RFC 9142 deprecates weak key exchange methods."},
		},
		Refs: []Ref{{"OpenBSD, sshd_config(5)", "https://man.openbsd.org/sshd_config"}, {"RFC 9142, Key Exchange Method Updates for SSH", "https://www.rfc-editor.org/rfc/rfc9142.html"}},
	},
	{
		ID: "P3", Title: "Network Exposure and Firewalls", Level: Practitioner, Minutes: 20,
		Summary: "What a server exposes to the network, and why databases and cleartext services should not be reachable. How a host firewall acts as a safety net.",
		Prereqs: []string{"F1", "F3"},
		Objectives: []string{
			"Explain the difference between binding to 127.0.0.1 and to 0.0.0.0.",
			"Explain why exposed databases and caches cause mass breaches.",
			"Explain default-deny firewall policy.",
		},
		Sections: []Section{
			{"Listening Services and Attack Surface", []string{
				"Every listening port is part of the attack surface. A service bound to 127.0.0.1 or ::1 is reachable only from the machine itself. One bound to 0.0.0.0, :: or a public address is reachable from the network unless a firewall blocks it. OpenVAPT reads this from the kernel's own socket tables instead of port scanning.",
			}},
			{"Databases, Caches and Cleartext Protocols", []string{
				"Redis, MongoDB, Elasticsearch and Memcached exposed to the internet, often without authentication, have caused many large data breaches and ransom wipes. Telnet, FTP, rsh and plain POP3, IMAP or LDAP send passwords unencrypted.",
			}},
			{"Host Firewalls", []string{
				"A default-deny host firewall allows only the ports you intend, such as SSH and HTTPS, and drops everything else. It protects you when a service is installed or misconfigured by mistake. Always allow SSH before enabling a firewall on a remote server.",
			}},
			{"In Summary", []string{
				"Every listening port is attack surface. Bind services to loopback where you can. A default deny firewall closes the rest. Cleartext services belong behind TLS or off the network.",
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
			{"A service bound to 127.0.0.1 is reachable from:", []string{"The whole internet", "Only the same machine", "Only the local network", "Any machine the firewall allows"}, 1, "Loopback addresses never leave the machine, whatever the firewall says."},
			{"What does a default-deny firewall policy do?", []string{"Blocks everything not explicitly allowed", "Allows everything not explicitly blocked", "Logs traffic only", "Blocks only known bad addresses"}, 0, "Default deny allows only the ports you intend and drops everything else."},
			{"Why is Telnet considered insecure?", []string{"It is slow", "It sends credentials unencrypted", "It only works on Windows", "It cannot be firewalled"}, 1, "Anyone on the network path can read the password."},
			{"A service is bound to 0.0.0.0 and no firewall is running. Who can reach it?", []string{"Only the same machine", "Any network that can route to the server", "Only IPv6 clients", "Only clients that know a password"}, 1, "0.0.0.0 means every IPv4 address on the machine. Without a firewall, anyone who can route to the server can connect."},
			{"How does OpenVAPT find listening services?", []string{"It port scans the network", "It reads the kernel's own socket tables", "It asks each service for its version", "It reads the firewall rules only"}, 1, "Reading the kernel's socket tables shows every listener without sending any traffic."},
			{"What must you do before enabling a default-deny firewall on a remote server?", []string{"Allow SSH", "Stop the web server", "Disable IPv6", "Reboot the server"}, 0, "If SSH is not allowed first, the new policy can lock you out of the server."},
		},
		Refs: []Ref{{"NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy", "https://csrc.nist.gov/pubs/sp/800/41/r1/final"}, {"OWASP Database Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"}},
	},
	{
		ID: "P4", Title: "TLS, Certificates and HTTPS", Level: Practitioner, Minutes: 20,
		Summary: "How encryption in transit works in practice, which TLS versions are acceptable, and how certificates and HSTS keep users safe.",
		Prereqs: []string{"P3"},
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
			{"In Summary", []string{
				"Offer TLS 1.2 and 1.3 only. A certificate must match the name, be valid and be renewed in time. HSTS stops a downgrade to plain HTTP.",
			}},
		},
		KeyTerms:      []string{"TLS", "Certificate", "HSTS", "Downgrade Attack"},
		RelatedChecks: []string{"NET-TLS-", "WEB-TLS-001", "WEB-HDR-001"},
		Lab: []string{
			"Run: openvapt demo --only NET-TLS-,WEB-TLS-001,WEB-HDR-001",
			"On your own server: openssl s_client -connect 127.0.0.1:443 -tls1_1 </dev/null and explain the result.",
		},
		Quiz: []Question{
			{"Which TLS versions should a server offer today?", []string{"TLS 1.0 and above", "TLS 1.2 and TLS 1.3", "SSL 3.0 and TLS 1.0", "TLS 1.1 and TLS 1.2"}, 1, "RFC 8996 deprecated TLS 1.0 and 1.1, so only TLS 1.2 and 1.3 remain."},
			{"What does HSTS do?", []string{"Encrypts the database", "Tells browsers to always use HTTPS for the site", "Blocks bots", "Hides the server version"}, 1, "Strict-Transport-Security makes browsers refuse to downgrade to plain HTTP for that site."},
			{"Why are self-signed certificates a problem on public sites?", []string{"Browsers do not trust them, so users learn to ignore warnings", "They expire faster", "They use weak keys", "They cannot be used with TLS 1.3"}, 0, "Users trained to click through warnings lose their protection against interception."},
			{"Which RFC deprecated TLS 1.0 and TLS 1.1?", []string{"RFC 6797", "RFC 8996", "RFC 9142", "RFC 5246"}, 1, "RFC 8996 (2021) deprecated them. RFC 6797 defines HSTS, RFC 9142 covers SSH key exchange and RFC 5246 defines TLS 1.2."},
			{"A valid certificate lists only www.example.com. A user visits shop.example.com on the same server. What happens?", []string{"Nothing, any certificate from that server works", "The browser warns that the name does not match", "The connection falls back to TLS 1.0", "HSTS fixes the mismatch"}, 1, "A certificate proves identity only for the names it lists. Any other name gets a mismatch warning."},
			{"How does OpenVAPT test for old TLS versions?", []string{"It reads the certificate expiry date", "It attempts handshakes limited to the old versions against 127.0.0.1", "It scans other servers on the internet", "It checks the HSTS header"}, 1, "If a handshake limited to TLS 1.0 or 1.1 succeeds on loopback, the server still offers it."},
		},
		Refs: []Ref{{"RFC 8996, Deprecating TLS 1.0 and TLS 1.1", "https://www.rfc-editor.org/rfc/rfc8996.html"}, {"NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations", "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}, {"RFC 6797, HTTP Strict Transport Security", "https://www.rfc-editor.org/rfc/rfc6797.html"}},
	},
	{
		ID: "P5", Title: "Web Security Headers and Cookies", Level: Practitioner, Minutes: 20,
		Summary: "The HTTP response headers and cookie flags that let browsers defend users against cross-site scripting, clickjacking and session theft.",
		Prereqs: []string{"F3"},
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
			{"In Summary", []string{
				"Headers tell the browser what to allow. CSP limits scripts and frame-ancestors stops clickjacking. Cookies need the Secure, HttpOnly and SameSite flags.",
			}},
		},
		KeyTerms:      []string{"Content Security Policy", "Cross-Site Scripting", "Clickjacking", "Cookie Flags", "CSRF"},
		RelatedChecks: []string{"WEB-HDR-002", "WEB-HDR-003", "WEB-HDR-004", "WEB-HDR-005", "WEB-HDR-006", "WEB-CK-", "WEB-COR-", "WEB-SEC-", "WEB-PHP-005"},
		Lab: []string{
			"Run: openvapt demo --only WEB-HDR-,WEB-CK-",
			"Open your browser's developer tools on any site you own and compare its response headers with the checks.",
		},
		Quiz: []Question{
			{"Which header limits where scripts may load from?", []string{"Referrer-Policy", "Content-Security-Policy", "Server", "Strict-Transport-Security"}, 1, "CSP controls allowed sources for scripts and other resources."},
			{"The HttpOnly cookie flag:", []string{"Hides the cookie from JavaScript", "Encrypts the cookie", "Makes the cookie permanent", "Sends the cookie only over HTTPS"}, 0, "An XSS bug cannot read an HttpOnly cookie. Sending only over HTTPS is the Secure flag."},
			{"Clickjacking is prevented by:", []string{"frame-ancestors or X-Frame-Options", "HSTS", "Compression", "The SameSite cookie flag"}, 0, "They stop other sites framing your pages."},
			{"Which cookie flag keeps a cookie off plain HTTP connections?", []string{"HttpOnly", "Secure", "SameSite", "Path"}, 1, "Secure means the browser sends the cookie only over HTTPS."},
			{"What does the SameSite cookie flag help reduce?", []string{"Cross-site request forgery", "SQL injection", "Clickjacking", "TLS downgrade"}, 0, "SameSite limits when a cookie is sent with cross-site requests, which reduces CSRF."},
			{"What does X-Content-Type-Options: nosniff do?", []string{"Stops browsers guessing file types", "Blocks all scripts", "Hides the server version", "Turns off caching"}, 0, "nosniff makes the browser trust the declared content type instead of guessing, so a file cannot be treated as script by mistake."},
		},
		Refs: []Ref{{"OWASP Secure Headers Project", "https://owasp.org/projects/secure-headers-project"}, {"OWASP Session Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"}},
	},
	{
		ID: "P6", Title: "Information Exposure and Misconfiguration", Level: Practitioner, Minutes: 25,
		Summary: "How forgotten files, verbose errors and version banners hand attackers the map, and sometimes the keys.",
		Prereqs: []string{"P5"},
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
			{"In Summary", []string{
				"Exposed .git, .env, backup files and directory listings leak secrets and code. Default pages and version banners help attackers aim. Debug mode must be off in production.",
			}},
		},
		KeyTerms:      []string{"Information Disclosure", "Security Misconfiguration", "Directory Listing", "Secrets Management"},
		RelatedChecks: []string{"WEB-EXP-", "WEB-DOC-", "WEB-PHP-", "WEB-CMS-", "WEB-HDR-007"},
		Lab: []string{
			"Run: openvapt demo --only WEB-EXP-,WEB-PHP-,WEB-CMS- and read how the evidence is redacted.",
			"Find the bodyHas markers in internal/checks/web/exposure.go and explain how they avoid soft-404 false positives.",
		},
		Quiz: []Question{
			{"Why is an exposed .git folder serious?", []string{"It slows the site", "Anyone can rebuild the source code and history, including secrets", "It breaks HTTPS", "It only reveals the folder name"}, 1, "The history often contains credentials committed by mistake."},
			{"What should you do after finding an exposed .env file?", []string{"Delete it only", "Block it, remove it and rotate every secret in it", "Rename it", "Set its permissions to 600 and keep the same secrets"}, 1, "Treat every secret in it as leaked. Hiding the file now does not undo earlier downloads."},
			{"Why does OpenVAPT require content markers, not just HTTP 200?", []string{"To avoid false positives from sites that return 200 for every path", "To save bandwidth", "Because 200 means error", "Because real files never return 200"}, 0, "Soft-404 pages return 200 for any path and would otherwise trigger every check."},
			{"What can PHP's allow_url_include turn a file-inclusion bug into?", []string{"A harmless warning", "Remote code execution", "A denial of service only", "A cookie leak only"}, 1, "With allow_url_include on, an inclusion bug can load and run code from another server."},
			{"Does hiding version numbers fix vulnerabilities?", []string{"Yes, attackers cannot attack what they cannot identify", "No, it removes free reconnaissance but patching is what fixes them", "Yes, if the Server header is removed too", "No, and versions should always be shown"}, 1, "Hiding versions removes a free hint. The vulnerable code is still there until it is patched."},
			{"A database dump named backup.sql sits in the web root. What is the main risk?", []string{"It uses disk space", "Anyone who finds it can download the whole database", "It slows the database down", "It breaks HTTPS"}, 1, "Backups and SQL dumps in the web root contain whole databases that anyone can fetch."},
		},
		Refs: []Ref{{"OWASP Top 10 2021, A05 Security Misconfiguration", "https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/"}, {"OWASP Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}},
	},
	{
		ID: "P7", Title: "Identity, Passwords and Privilege", Level: Practitioner, Minutes: 25,
		Summary: "How accounts, password storage, lockout and privilege escalation paths decide who really controls a server.",
		Prereqs: []string{"P1"},
		Objectives: []string{
			"Explain why password hashing algorithms and lengths matter.",
			"Recognise privilege escalation paths: UID 0 accounts, NOPASSWD sudo and the docker group.",
			"Explain why legacy trust files and service account shells are risky.",
		},
		Sections: []Section{
			{"Storing Passwords", []string{
				"Linux stores password hashes in /etc/shadow. Modern algorithms such as yescrypt and SHA-512 crypt are salted and deliberately slow, so a stolen shadow file is expensive to crack. MD5-crypt and DES are fast and obsolete. Old hashes stay until each user changes their password.",
				"NIST SP 800-63B-4 favours length over complexity rules and asks for known-breached passwords to be blocked. It requires at least 15 characters when a password is the only factor, or 8 when it is used with another factor. It also requires limits on failed attempts. OpenVAPT flags a minimum below 15 characters and recommends a lockout after repeated failures. Together they make online guessing impractical.",
			}},
			{"Who Is Really Root", []string{
				"Root is not a name but user id 0. Extra UID 0 accounts, duplicate UIDs and NOPASSWD sudo rules all give root, often without a password. So does membership of the docker group, which can mount the host filesystem.",
				"Sudo should run commands in a pseudo-terminal and log them to a dedicated file, so privileged actions are recorded and cannot linger.",
			}},
			{"Legacy Trust", []string{
				".rhosts and .shosts files trust whole machines instead of people, and .netrc files hold plain-text passwords. Legacy '+' NIS entries can import unexpected accounts. Service accounts should never have a login shell.",
			}},
			{"In Summary", []string{
				"Root is UID 0, not a name. Slow, salted hashing protects a stolen password file. Lockout slows guessing. NOPASSWD sudo and the docker group are root without a password.",
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
			{"Why is yescrypt or SHA-512 crypt preferred over MD5-crypt?", []string{"They are salted and deliberately slow to crack", "They make passwords shorter", "They encrypt the whole disk", "They need no salt"}, 0, "Slow, salted hashing makes offline cracking of a stolen shadow file expensive."},
			{"Why is membership of the docker group dangerous?", []string{"It slows the server", "It allows starting containers that mount the host filesystem, which is root access", "It disables SSH", "It gives read-only access to container logs"}, 1, "Control of Docker is equivalent to root on the host."},
			{"What does an account lockout policy defend against?", []string{"Password guessing", "Disk failure", "TLS downgrade", "Session theft through XSS"}, 0, "Lockout limits repeated guesses against an account."},
			{"What does NIST SP 800-63B-4 favour for passwords?", []string{"Composition rules such as one symbol and one digit", "Length, and blocking known-breached passwords", "Changing every password every 30 days", "Exactly 8 characters"}, 1, "NIST favours length over complexity rules and asks verifiers to block passwords known to be breached."},
			{"Why are .rhosts files risky?", []string{"They store password hashes", "They trust whole machines instead of people", "They make SSH slower", "They disable sudo logging"}, 1, "Legacy trust files let anyone on a trusted machine in, without proving who they are."},
			{"The system now uses yescrypt. Why can old MD5-crypt hashes still be in /etc/shadow?", []string{"yescrypt cannot read them", "A hash changes only when the user next changes their password", "MD5 hashes can never be removed", "/etc/shadow is read-only"}, 1, "Old hashes stay until each user changes their password, so a policy change needs follow-up."},
		},
		Refs: []Ref{{"NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management", "https://pages.nist.gov/800-63-4/sp800-63b.html"}, {"MITRE ATT&CK T1548, Abuse Elevation Control Mechanism", "https://attack.mitre.org/techniques/T1548/"}},
	},
	{
		ID: "P8", Title: "Data Services: Databases, File Shares, DNS and Mail", Level: Practitioner, Minutes: 30,
		Summary: "Why databases, caches, file shares, DNS and mail servers cause so many breaches, and the configuration settings that decide whether they are safe.",
		Prereqs: []string{"P3"},
		Objectives: []string{
			"Explain why databases and caches must require authentication and bind to loopback.",
			"Recognise unsafe NFS exports and Samba guest access.",
			"Explain open DNS recursion, zone transfers and open mail relays.",
		},
		Sections: []Section{
			{"Databases and Caches", []string{
				"Redis, MongoDB, Elasticsearch and Memcached were designed for trusted networks and have historically shipped without authentication. Exposed instances are found by internet-wide scanners within hours and wiped or ransomed. PostgreSQL 'trust' entries in pg_hba.conf allow login with no password at all, and MySQL's local_infile lets a compromised application read server files.",
				"The safe pattern is the same everywhere. Bind to 127.0.0.1 or a private interface and require authentication. Let only the application servers that need access through the firewall.",
			}},
			{"File Shares", []string{
				"NFS exports with no_root_squash let a remote root user act as root on the share, and exports to '*' let anyone mount them. Samba shares with guest access, or servers still allowing SMB1, expose files to anonymous users and to old, wormable protocol flaws.",
			}},
			{"DNS and Mail", []string{
				"A DNS server that answers recursive queries for anyone is used to amplify denial-of-service attacks. One that allows zone transfers to anyone publishes the whole internal name map. A mail server whose relay rules are too broad becomes a spam relay, and allowing passwords over unencrypted connections exposes mail accounts.",
			}},
			{"In Summary", []string{
				"Databases, file shares, DNS and mail should listen only where they are needed. Default accounts, open relays and open recursion invite abuse.",
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
			{"Why are exposed Redis or MongoDB instances so often breached?", []string{"They are slow", "They historically ran without authentication and are found quickly by internet-wide scanners", "They use too much memory", "They cannot use TLS"}, 1, "Unauthenticated, internet-reachable data services are found and abused within hours."},
			{"What does no_root_squash on an NFS export allow?", []string{"A remote root user to act as root on the share", "Faster file copies", "Encrypted transfers", "Maps remote root to the nobody user"}, 0, "Root on a client keeps root rights on the share. Mapping root to nobody is what root_squash does."},
			{"Why is open DNS recursion dangerous?", []string{"It slows name resolution", "It can be abused to amplify denial-of-service attacks", "It deletes zones", "It reveals the server's private keys"}, 1, "Open resolvers send large answers to forged addresses, amplifying traffic toward victims."},
			{"A DNS server allows zone transfers to anyone. What does that reveal?", []string{"The DNS server's password", "The whole internal name map", "The site's TLS certificate", "Nothing, zone data is always public"}, 1, "A zone transfer hands over every name in the zone, including internal hosts."},
			{"pg_hba.conf has a 'trust' entry. What does it allow?", []string{"Login with no password for matching connections", "Login only with a client certificate", "Read-only access", "Login only through the firewall"}, 0, "trust skips authentication entirely for connections that match the line."},
			{"What is the safe pattern for a database server?", []string{"Bind to 0.0.0.0 and rely on a strong password", "Bind to 127.0.0.1 or a private interface, require authentication, and allow only the application servers through the firewall", "Move it to a non-default port", "Turn off its logs"}, 1, "The same three layers apply to every data service: narrow binding, authentication and firewall rules."},
		},
		Refs: []Ref{{"OWASP Database Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"}, {"CISA, DNS Amplification Attacks (Alert TA13-088A)", "https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks"}, {"Redis security", "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"}},
	},
	{
		ID: "P9", Title: "Containers and Kubernetes", Level: Practitioner, Minutes: 25,
		Summary: "How container isolation really works, the configuration mistakes that break it, and how to protect the Docker and Kubernetes control planes on a host.",
		Prereqs: []string{"P1"},
		Objectives: []string{
			"Explain why control of the Docker API equals root on the host.",
			"Recognise privileged containers, host namespaces, dangerous capabilities and sensitive mounts.",
			"Explain kubelet authentication and why etcd and kubeconfig files must be protected.",
		},
		Sections: []Section{
			{"Containers Are Processes", []string{
				"A container is a set of ordinary Linux processes isolated by namespaces, cgroups, capabilities and security profiles. Each of those layers can be switched off. --privileged removes almost all of them. Host namespaces share the host's processes or network. Added capabilities such as SYS_ADMIN reopen kernel interfaces.",
				"NIST SP 800-190 recommends running containers with least privilege, read-only where possible and as non-root users. Images should be minimal and scanned for known vulnerabilities.",
			}},
			{"The Docker Control Plane", []string{
				"Whoever can talk to the Docker API can start a container that mounts the host's root filesystem. That makes the docker group, the docker.sock socket and any TCP listener as powerful as root. Exposing the API over TCP without mutual TLS is a common cause of cryptomining infections. Daemon defaults such as no-new-privileges, user namespace remapping and disabled inter-container communication reduce the damage a compromised container can do.",
			}},
			{"Kubernetes on the Node", []string{
				"Each node runs a kubelet whose API can execute commands in its pods. It must require authentication and use Webhook authorisation, never anonymous access or AlwaysAllow. Its unauthenticated read-only port should be off. etcd stores every cluster object, including Secrets, so its data directory and the cluster's kubeconfig and CA key files must be readable only by root.",
			}},
			{"In Summary", []string{
				"Containers share the host kernel. Privileged containers, host mounts and extra capabilities break isolation. Kubernetes needs the same least privilege thinking at every layer.",
			}},
		},
		KeyTerms:      []string{"Container", "Namespace", "Capability", "Least Privilege", "Privilege Escalation"},
		RelatedChecks: []string{"HOST-CTR-", "HOST-K8S-", "HOST-DKR-"},
		Lab: []string{
			"Run: openvapt demo --only HOST-CTR-,HOST-K8S-,HOST-DKR- --out p9",
			"For the vulnerable container, list every isolation layer that was switched off and the docker run flag that switched it off.",
			"On a test host with Docker: docker inspect --format '{{.HostConfig.Privileged}} {{.HostConfig.Binds}}' $(docker ps -q)",
		},
		Quiz: []Question{
			{"Why is mounting /var/run/docker.sock into a container dangerous?", []string{"It slows the container", "The container can control Docker and therefore the host", "It disables logging", "It only lets the container read its own logs"}, 1, "The Docker API is equivalent to root on the host."},
			{"What does --privileged do?", []string{"Runs the container faster", "Removes most isolation, giving the container nearly full host access", "Encrypts the container", "Runs the container as a non-root user"}, 1, "Privileged containers have almost no isolation left."},
			{"Which kubelet setting is the hardened one?", []string{"authorization mode AlwaysAllow", "anonymous authentication enabled", "authorization mode Webhook with anonymous access disabled", "read-only port left on"}, 2, "Webhook authorisation with anonymous access off protects the kubelet API. The read-only port should be off."},
			{"What is a container?", []string{"A small virtual machine with its own kernel", "A set of ordinary Linux processes isolated by namespaces, cgroups, capabilities and security profiles", "A compressed file of the host", "A separate physical server"}, 1, "Containers share the host kernel. Their isolation comes from kernel features that can be switched off."},
			{"Why must etcd's data directory be readable only by root?", []string{"It holds every cluster object, including Secrets", "It holds container logs only", "It stores the kubelet program", "It is too large to share"}, 0, "Anyone who reads etcd's data reads every Secret in the cluster."},
			{"Which practice does NIST SP 800-190 recommend?", []string{"Run containers as root so they can repair themselves", "Run as non-root, read-only where possible, from minimal scanned images", "Use --privileged for stability", "Share the host network namespace"}, 1, "Least privilege, read-only filesystems and small scanned images reduce what a compromised container can do."},
		},
		Refs: []Ref{{"NIST SP 800-190, Application Container Security Guide", "https://csrc.nist.gov/pubs/sp/800/190/final"}, {"OWASP Docker Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"}, {"Kubernetes, Kubelet authentication and authorization", "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/"}},
	},
	{
		ID: "P10", Title: "Vulnerability Management: CVE, OSV and Known Exploited Vulnerabilities", Level: Practitioner, Minutes: 25,
		Summary: "How known vulnerabilities are matched to installed software, why version comparison is subtle, and how to prioritise with the CISA Known Exploited Vulnerabilities list.",
		Prereqs: []string{"F3"},
		Objectives: []string{
			"Explain how a package inventory is matched against vulnerability data.",
			"Explain why Debian, RPM and semantic versions must be compared with their own rules.",
			"Prioritise findings using severity and known exploitation.",
		},
		Sections: []Section{
			{"From Inventory to Advisory", []string{
				"Vulnerability matching starts with an inventory. It lists the installed operating system packages (from dpkg or rpm). It also lists the libraries a web application ships (from lock files such as composer.lock or package-lock.json). Each item is compared with advisories that state which versions are affected and which version fixes the problem.",
				"OSV (osv.dev) publishes advisories in one open format for many ecosystems, including Debian, Ubuntu, AlmaLinux, Rocky Linux, Packagist and npm. Distributions often backport fixes without changing the upstream version number, which is why matching must use the distribution's own advisory data and exact package versions.",
			}},
			{"Comparing Versions Correctly", []string{
				"Version strings are not simple numbers. In Debian versions an epoch (1:) outranks everything. A tilde sorts before anything, so 1.0~rc1 comes before 1.0. The revision after the last hyphen counts too. RPM has its own rules, including a caret for post-release snapshots. A tool that compares versions naively reports false positives and, worse, false negatives.",
			}},
			{"Prioritising", []string{
				"Severity alone is a poor queue. The CISA Known Exploited Vulnerabilities catalogue lists flaws attackers are known to use in practice; those should be fixed first. Offline data also ages: a snapshot from months ago cannot know about last week's vulnerabilities, so every report states the snapshot date.",
			}},
			{"In Summary", []string{
				"Know what software you run. Match it against CVE and OSV data. Fix known exploited vulnerabilities first.",
			}},
		},
		KeyTerms:      []string{"CVE", "CVSS", "Patch Management", "Software Inventory", "Known Exploited Vulnerability"},
		RelatedChecks: []string{"HOST-CVE-", "WEB-CVE-"},
		Lab: []string{
			"Run: openvapt vulndb and note the snapshot date and whether it is test data.",
			"Run: openvapt demo --only HOST-CVE-,WEB-CVE- --out p10 and read how each finding names the installed and fixed version.",
			"Read internal/vulndb/review_test.go and explain why 1.0~rc1 is older than 1.0.",
		},
		Quiz: []Question{
			{"Why can't versions be compared as plain numbers?", []string{"Because ecosystems such as Debian and RPM have their own rules, such as epochs and tilde pre-releases", "Because versions are secret", "Because numbers are too large", "Because only RPM has ordering rules"}, 0, "Each ecosystem defines its own ordering rules, and a naive comparison gives wrong answers."},
			{"Which findings should usually be fixed first?", []string{"Low severity", "Vulnerabilities listed as known exploited by CISA", "Informational findings", "The oldest findings"}, 1, "Known exploitation is strong evidence of real risk."},
			{"Why does every report state the vulnerability data snapshot date?", []string{"For decoration", "Because offline data cannot include vulnerabilities published after it was built", "Because the law requires it", "Because the data changes during the scan"}, 1, "Old data misses newer vulnerabilities, so the reader must know its age."},
			{"Which of these Debian versions is the oldest?", []string{"1.0~rc1", "1.0", "1.0-1", "1:0.9"}, 0, "A tilde sorts before anything, so 1.0~rc1 comes before 1.0. The epoch in 1:0.9 makes it newer than all of them."},
			{"Why must matching use the distribution's own advisory data?", []string{"Distributions often backport fixes without changing the upstream version number", "Upstream data is secret", "Distributions never fix vulnerabilities", "Advisories exist only for Debian"}, 0, "A backported fix keeps the old upstream number, so only the distribution's data knows which package version is fixed."},
			{"Where does a web application's library inventory come from?", []string{"Lock files such as composer.lock or package-lock.json", "The web server's access log", "Downloading the site from the internet", "The CVE website"}, 0, "Lock files list the exact library versions the application ships."},
		},
		Refs: []Ref{{"OSV, Open Source Vulnerability format and database", "https://osv.dev/"}, {"CISA Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}, {"Debian Policy Manual, Version numbering", "https://www.debian.org/doc/debian-policy/ch-controlfields.html#version"}},
	},
}
