package academy

// Practitioner modules for the two control areas the course taught only in
// passing before 2026-10-14: access control (who may log in and what they may
// do) and logging and monitoring (how you find out afterwards). They sit
// after the stack modules and before the Applied level.
var accessLogging = []Module{
	{
		ID: "P15", Title: "Access Control: Accounts, Sudo and Logins", Level: Practitioner, Minutes: 25,
		Summary: "Who may log in, from where, and what they may do once inside: the account, PAM, sudo and SSH settings that enforce it, and the files that define it.",
		Prereqs: []string{"P2", "P7"},
		Objectives: []string{
			"Tell authentication and authorisation apart and explain why both are needed.",
			"Identify login paths that bypass access control: empty passwords, service accounts with shells, direct root login.",
			"Explain what sudo rules, lockout and SSH authentication settings each enforce.",
			"Explain why the permissions on account files and the default umask are access control too.",
		},
		Sections: []Section{
			{"What Access Control Means", []string{
				"Access control answers one question: may this subject do this action on this object? The subject is a user or a program. The object is a file, a service or a command.",
				"Authentication proves who the subject is. Authorisation decides what that subject may do. A strong password with a NOPASSWD sudo rule behind it is good authentication and no authorisation.",
				"Two habits make access control work. Least privilege gives each account only what its job needs. Default deny refuses anything that is not explicitly allowed.",
				"NIST SP 800-53 groups these controls in the Access Control (AC) and Identification and Authentication (IA) families. CIS Controls v8 covers them in Controls 5 and 6.",
			}},
			{"Who May Log In", []string{
				"Every account that can log in is a door. Service accounts such as www-data or postgres should have a nologin shell, because nothing should ever log in as them.",
				"An account with an empty password field is a door with no lock. OpenVAPT treats it as Critical, and so should you. SSH must also refuse empty passwords.",
				"Root should not log in over SSH at all. Named users log in and then use sudo. That keeps a record of which person acted.",
				"Lockout limits guessing. PAM faillock locks an account for a while after a few failed attempts. SSH adds MaxAuthTries and a short LoginGraceTime.",
				"Password logins over SSH should be the exception. Where they remain, AuthenticationMethods can require a key as well, so a stolen password alone is not enough.",
			}},
			{"What They May Do: Sudo", []string{
				"Sudo is where authorisation is written down. Each rule says which user may run which commands as which target user.",
				"NOPASSWD removes the second proof. Any process running as that user, including a hijacked web application, becomes root with one command.",
				"Sudo should run commands in a pseudo-terminal and log to its own file. Then privileged actions are recorded and cannot linger after the session ends.",
				"Separation of duties means the person who approves a change is not the only person who can make it. On a small server, sudo logs are often the only evidence of who did what.",
			}},
			{"The Files That Define Access", []string{
				"Access control is only as strong as the files that store it. /etc/passwd and /etc/group must not be writable by others, or anyone can add a root account.",
				"/etc/shadow and /etc/gshadow hold password hashes and must not be readable by others. A readable shadow file turns every local user into an offline password cracker.",
				"Duplicate user ids give two names the same rights. Legacy '+' NIS entries can import accounts from elsewhere. Trust files such as .rhosts and .netrc grant access or hold passwords in plain text.",
				"The default umask decides who can read every new file. With 022 every new file is readable by every local user. 027 or stricter keeps new files private by default.",
			}},
			{"In Summary", []string{
				"Authentication proves identity and authorisation grants rights. Close every login path that is not needed. Keep sudo rules specific, with a password and a log. Protect the files that store accounts and passwords, and set a strict umask.",
			}},
		},
		KeyTerms:      []string{"Authentication", "Authorisation", "Least Privilege", "Default Deny", "Account Lockout", "Separation of Duties", "Login Shell", "PAM", "umask"},
		RelatedChecks: []string{"HOST-USR-", "HOST-PWD-", "HOST-SUDO-", "HOST-SSH-001", "HOST-SSH-002", "HOST-SSH-003", "HOST-SSH-006", "HOST-SSH-008", "HOST-FS-001", "HOST-FS-009"},
		Lab: []string{
			"Run: openvapt demo --only HOST-USR-,HOST-PWD-,HOST-SUDO-,HOST-SSH-001,HOST-SSH-003,HOST-FS-001 --out p15",
			"For each failed check, write one line: who gets in, or what they can do, that they should not.",
			"Run: openvapt explain HOST-PWD-004 and read how pam_faillock is detected in both PAM positions.",
			"On your own machine: awk -F: '$7 !~ /nologin|false/ {print $1}' /etc/passwd and ask why each listed account needs a shell.",
			"On your own machine: sudo -l and read your own sudo rules. Which ones carry NOPASSWD, and why?",
		},
		Quiz: []Question{
			{"A user logs in with a strong password and runs a command through a NOPASSWD sudo rule. What is weak here?", []string{"Authentication", "Authorisation", "Encryption", "Logging"}, 1, "The login proved identity well. The rule grants root with no second proof, so authorisation is weak."},
			{"Why should service accounts such as www-data have a nologin shell?", []string{"It makes the service start faster", "Nothing should ever log in as them, so the door is closed", "It hides the account from /etc/passwd", "It stops the service writing logs"}, 1, "A login shell on a service account is a door that nothing legitimate uses."},
			{"What does PAM faillock enforce?", []string{"A minimum password length", "A temporary lock after repeated failed logins", "Key-based SSH authentication", "A dedicated sudo log file"}, 1, "faillock counts failures and locks the account for a while, which slows guessing."},
			{"Why is a world-readable /etc/shadow a High finding even though nobody can write to it?", []string{"It lets any local user copy the hashes and crack them offline", "It stops users changing their passwords", "It makes logins slower", "It disables sudo"}, 0, "Reading the hashes is enough; cracking happens elsewhere, at leisure."},
			{"What does a default umask of 022 mean for a report an administrator saves?", []string{"Only root can read it", "Every local user can read it", "It is encrypted at rest", "It is deleted on reboot"}, 1, "022 leaves the read bit for others set, so every new file is readable by every local account."},
		},
		Refs: []Ref{
			{"NIST SP 800-53 Rev. 5, Security and Privacy Controls (AC and IA families)", "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
			{"NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management", "https://pages.nist.gov/800-63-4/sp800-63b.html"},
			{"sudoers(5) manual", "https://www.sudo.ws/docs/man/sudoers.man/"},
			{"pam_faillock(8) manual", "https://man7.org/linux/man-pages/man8/pam_faillock.8.html"},
		},
	},
	{
		ID: "P16", Title: "Logging, Auditing and Time", Level: Practitioner, Minutes: 20,
		Summary: "How logs, the audit daemon, synchronised time and log-driven blocking turn a server from a black box into something you can investigate and defend.",
		Prereqs: []string{"P1", "P15"},
		Objectives: []string{
			"Explain why logging is a control in its own right, not an afterthought.",
			"Describe what makes logs useful after an incident: persistence, protection, rotation and correct time.",
			"Explain what the audit daemon records that ordinary logs do not.",
			"Explain how log-driven blocking and sudo and SSH logging settings turn records into defence.",
		},
		Sections: []Section{
			{"Why Logs Are a Control", []string{
				"Most controls try to stop an attack. Logs are the control that tells you an attack happened, how far it got and what to fix.",
				"Without logs there is no evidence. You cannot say which account was used, which files changed or when it started. Every later decision becomes a guess.",
				"CIS Controls v8 gives this its own control, number 8, Audit Log Management. NIST CSF 2.0 calls it Continuous Monitoring (DE.CM). NIST SP 800-92 is the public guide to doing it well.",
			}},
			{"System Logs That Survive", []string{
				"Logs must survive a reboot. rsyslog and syslog-ng write to /var/log. The systemd journal keeps logs only in memory unless /var/log/journal exists.",
				"Logs must also survive an attacker. Authentication logs hold user names, source addresses and sometimes passwords typed into the wrong field. Only administrators should read them.",
				"Logs must not fill the disk. logrotate, or a SystemMaxUse limit for the journal, keeps them bounded. A full disk stops services and is itself an attack.",
				"Where you can, send a copy to another machine. Logs that live only on the compromised server can be edited by whoever compromised it.",
			}},
			{"Auditing With auditd", []string{
				"Ordinary logs record what programs choose to say. The Linux audit daemon records what the kernel saw: a file opened, a permission changed, a privilege used.",
				"Rules decide what auditd watches. Common choices are changes to /etc/passwd and /etc/shadow, use of sudo, and deletions by ordinary users.",
				"Audit logs cost disk and attention. Start with a small rule set that answers the questions an investigation would ask, then grow it.",
			}},
			{"Time and Correlation", []string{
				"An investigation puts events from several sources in order. That only works if every clock agrees. A few minutes of drift can swap cause and effect.",
				"chrony, ntpd or systemd-timesyncd keep the clock in step with public time servers. TLS certificates and one-time password codes also fail when the clock drifts.",
			}},
			{"From Logs to Action", []string{
				"A log-based blocker such as fail2ban, sshguard or CrowdSec reads the authentication log and blocks sources that fail repeatedly. The log becomes an active defence.",
				"Sudo should log to its own file and use a pseudo-terminal, so every privileged command is recorded and sessions end cleanly.",
				"SSH at LogLevel VERBOSE records the fingerprint of the key used for each login. That is how you learn which key, not just which user, opened the session.",
			}},
			{"In Summary", []string{
				"Logs are how you find out. Keep them after a reboot, keep them from other users, keep them bounded and keep the clock right. Add auditd for what the kernel sees. Let a blocker act on the log, and make sudo and SSH say who did what.",
			}},
		},
		KeyTerms:      []string{"Audit Log", "Log Rotation", "Time Synchronisation", "Intrusion Prevention", "Correlation", "Evidence"},
		RelatedChecks: []string{"HOST-LOG-", "HOST-IDS-", "HOST-TIME-", "HOST-SUDO-001", "HOST-SSH-012"},
		Lab: []string{
			"Run: openvapt demo --only HOST-LOG-,HOST-IDS-,HOST-TIME-,HOST-SSH-012 --out p16",
			"For each failed check, write what question an investigator could no longer answer.",
			"Run: openvapt explain HOST-LOG-003 and note that the check reads file metadata only, never log contents.",
			"On your own machine: ls -l /var/log/auth.log /var/log/secure 2>/dev/null and timedatectl, then compare with the two checks.",
		},
		Quiz: []Question{
			{"What is lost when the systemd journal is kept only in memory?", []string{"Nothing, the journal is copied to syslog automatically", "Every log entry from before the last reboot", "Only kernel messages", "Only messages from user services"}, 1, "Without /var/log/journal the journal is volatile and a reboot erases the evidence."},
			{"Why should /var/log/auth.log not be readable by every user?", []string{"It slows down logins", "It contains user names, source addresses and sometimes mistyped passwords", "It is needed only by auditd", "Reading it changes its timestamps"}, 1, "Authentication logs are sensitive data; only administrators should read them."},
			{"What does auditd record that rsyslog does not?", []string{"Web server access lines", "Kernel-level events such as a file opened or a permission changed", "Package update progress", "Cron job output"}, 1, "auditd records what the kernel saw, independent of what programs choose to log."},
			{"Why does time synchronisation matter for an investigation?", []string{"Events from different machines can be put in the right order", "It encrypts the logs", "It makes logs smaller", "It is required by logrotate"}, 0, "Correlation across sources only works when every clock agrees."},
			{"What does a log-based blocker such as fail2ban do?", []string{"Deletes old log files", "Blocks sources that repeatedly fail to log in, based on the log", "Replaces the firewall", "Synchronises the clock"}, 1, "It reads failures from the log and adds temporary firewall blocks, turning the log into defence."},
		},
		Refs: []Ref{
			{"NIST SP 800-92, Guide to Computer Security Log Management", "https://csrc.nist.gov/pubs/sp/800/92/final"},
			{"NIST SP 800-53 Rev. 5, Security and Privacy Controls (AU family)", "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
			{"auditd(8) manual", "https://man7.org/linux/man-pages/man8/auditd.8.html"},
			{"RFC 5905, Network Time Protocol Version 4", "https://www.rfc-editor.org/rfc/rfc5905.html"},
		},
	},
}
