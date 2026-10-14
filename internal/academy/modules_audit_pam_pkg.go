package academy

// Modules for the audit logging depth (HOST-AUD), authentication policy
// (HOST-PAM), package hygiene (HOST-PKG-002 to 006) and legacy service
// inventory (HOST-SVC-002 to 012) checks. They cover only these check ids;
// the existing Logging and Access Control modules teach the earlier checks.
// Registered from init so no other file's module list has to change.

var auditPamPkg = []Module{
	{
		ID: "P21", Title: "Audit Logging and Monitoring Depth", Level: Practitioner, Minutes: 30,
		Prereqs: []string{"P16"},
		Summary: "What the Linux audit daemon should record, how its rules and log files are protected, and why a copy of every log must leave the machine.",
		Objectives: []string{
			"Explain the difference between a running audit daemon and a useful audit trail.",
			"Read an audit rule file and say which events it records (identity files, logins, time changes, kernel modules, privileged commands).",
			"Explain why the immutable flag, log file permissions and full-disk actions protect the evidence an investigation depends on.",
			"Explain why journald persistence, compression and remote forwarding matter.",
		},
		Sections: []Section{
			{"From Running to Recording", []string{
				"HOST-LOG-002 asks whether auditd is active. That is the first question, not the last: an audit daemon with no rules records almost nothing, and one started by hand stops at the next reboot (HOST-AUD-001). NIST SP 800-92 describes log management as deciding what to record, protecting what was recorded and reviewing it. The HOST-AUD checks follow that order.",
				"Audit rules live in /etc/audit/rules.d and are loaded at boot. A watch rule (-w /etc/passwd -p wa) records every write to a file with the user, process and time. A system call rule (-a always,exit -S settimeofday) records every use of a kernel call. Together they turn a handful of files and calls into an audit trail.",
			}},
			{"What to Record", []string{
				"Identity files (HOST-AUD-002): /etc/passwd, group, shadow, gshadow and the sudoers files are how an intruder adds an account or grants themselves privilege. Login records (HOST-AUD-003): lastlog, the failed-login store, wtmp and btmp are what investigators read first and intruders clean first. Time changes (HOST-AUD-004): moving the clock forges timestamps and confuses every timeline. Kernel modules (HOST-AUD-005): a rootkit is usually a module. Privileged commands (HOST-AUD-006): setuid programs such as sudo, su and passwd are where ordinary users become root.",
				"The rule for each of these is a few lines. The checks map them to NIST SP 800-53 AU-2 (event logging) and AU-12 (audit record generation) and to CIS Controls v8 safeguards 8.2 and 8.5, by number only.",
			}},
			{"Protecting the Evidence", []string{
				"Whoever gains root can delete the rules (auditctl -D) unless the rule set ends with -e 2, which locks it until reboot (HOST-AUD-007). The audit log directory and files hold command lines, file names and sometimes secrets, so they must be root-only (HOST-AUD-008). And auditd must be told what to do when the disk fills: with max_log_file_action set to ignore or suspend an attacker switches auditing off by filling the disk (HOST-AUD-009). NIST SP 800-53 calls this AU-9, protection of audit information, and AU-5, response to logging failures.",
			}},
			{"journald and Remote Copies", []string{
				"systemd-journald keeps the journal in memory unless Storage=persistent (or auto with /var/log/journal present); a reboot or a crash then erases it. Compression keeps a persistent journal small enough to retain for weeks (HOST-AUD-010).",
				"Every local log can be edited by root. A copy that already left the machine, through rsyslog forwarding, syslog-ng or systemd-journal-upload, is the record an investigation can trust (HOST-AUD-011). Forward over TLS so the logs are not readable in transit. This is AU-9(2), storing audit records on a separate system, and CIS Controls v8 safeguard 8.9.",
			}},
			{"In Summary", []string{
				"Running auditd is not the same as recording. Load rules for identity files, logins, time changes, modules and privileged commands, lock the configuration, protect the log directory, make the daemon act when the disk fills, keep the journal persistent and send a copy somewhere an attacker cannot reach.",
			}},
		},
		KeyTerms:      []string{"Audit Rule", "Audit Trail", "Immutable Audit Configuration", "Log Forwarding", "Persistent Journal"},
		RelatedChecks: []string{"HOST-AUD-001", "HOST-AUD-002", "HOST-AUD-003", "HOST-AUD-004", "HOST-AUD-005", "HOST-AUD-006", "HOST-AUD-007", "HOST-AUD-008", "HOST-AUD-009", "HOST-AUD-010", "HOST-AUD-011"},
		Lab: []string{
			"Run: openvapt demo --only HOST-AUD- --out p21",
			"Open internal/lab/fixtures_audit_pam_pkg.go and compare the vulnerable audit.rules (four housekeeping lines) with the hardened 50-lab.rules. For each failed HOST-AUD check, find the rule line that makes it pass.",
			"Write one audit rule of your own for a file you care about (for example /etc/ssh/sshd_config) and explain which HOST-AUD check would notice its absence.",
			"On a test machine you own: sudo openvapt scan --only HOST-AUD- and read auditctl -l alongside the report.",
		},
		Quiz: []Question{
			{"auditd is active but /etc/audit/rules.d contains only -D and -b 8192. What is being recorded?", []string{"Every file change on the system", "Almost nothing: there are no watch or system call rules", "Only failed logins"}, 1, "Those lines clear the rules and set a buffer size. Without -w or -a rules, there is no audit trail."},
			{"What does -e 2 at the end of the audit rules do?", []string{"Enables two audit log files", "Locks the rules until the next reboot so root cannot remove them", "Sets the log level to 2"}, 1, "The immutable flag means the only way to change the rules is a reboot, which is itself a logged event."},
			{"Why forward logs to another machine when the local disk has plenty of space?", []string{"To save disk space", "Because an intruder with root can edit or delete the local copy", "Because journald cannot write to disk"}, 1, "A copy that already left the machine is the one an investigation can trust."},
			{"journald.conf has Storage=volatile. What happens to the journal at reboot?", []string{"It is compressed", "It is kept in /var/log/journal", "It is lost: volatile means memory only"}, 2, "Set Storage=persistent (and create /var/log/journal) so the journal survives."},
		},
		Refs: []Ref{
			{"NIST SP 800-92, Guide to Computer Security Log Management", "https://csrc.nist.gov/pubs/sp/800/92/final"},
			{"NIST SP 800-53 Rev. 5, AU family (Audit and Accountability)", "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
			{"auditctl(8), Linux man-pages", "https://man7.org/linux/man-pages/man8/auditctl.8.html"},
			{"journald.conf(5), systemd", "https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html"},
		},
	},
	{
		ID: "P22", Title: "Authentication Policy and Package Hygiene", Level: Practitioner, Minutes: 35,
		Prereqs: []string{"P7", "P15"},
		Summary: "The PAM and login.defs settings that decide how passwords are checked, reused and locked, how root's environment can be hijacked, and how packages arrive on the machine and which services came with them.",
		Objectives: []string{
			"Explain what pam_pwquality, pam_faillock, pam_pwhistory and pam_wheel each decide, and read their options from a PAM stack.",
			"Explain the login.defs and useradd defaults that govern password age and inactive accounts, and where current NIST guidance differs from older practice.",
			"Recognise an unsafe root PATH and explain the privilege escalation it allows.",
			"Explain why repository signatures, third-party repositories, retained kernels and legacy services are patch management problems.",
		},
		Sections: []Section{
			{"PAM: Where Password Rules Are Enforced", []string{
				"Linux checks passwords through Pluggable Authentication Modules. A setting in pwquality.conf does nothing unless the password stack (/etc/pam.d/common-password or system-auth) calls pam_pwquality (HOST-PAM-001). NIST SP 800-63B-4 asks verifiers to reject dictionary words and known-breached passwords rather than to impose composition rules, so the check looks at the module and its dictionary and user-name checks, not at character classes.",
				"pam_faillock counts failures (HOST-PWD-004); its unlock_time decides how long the lock lasts. The default of 600 seconds lets guessing resume every ten minutes; 900 or more, or 0 for a manual unlock, makes online guessing impractical (HOST-PAM-002). pam_pwhistory or pam_unix remember= stops a user who was told to change a compromised password from setting it straight back (HOST-PAM-004). pam_wheel restricts su to an administrative group so a compromised service account cannot sit and guess the root password (HOST-PAM-003).",
			}},
			{"login.defs and Account Lifecycle", []string{
				"/etc/login.defs sets the defaults new accounts inherit. PASS_MIN_DAYS 1 stops a user cycling through several changes to defeat history (HOST-PAM-005). PASS_WARN_AGE 7 gives notice before an expiry, where expiry is used at all; HOST-PWD-005 explains why NIST no longer recommends routine expiry, so this one is informational (HOST-PAM-006). INACTIVE in /etc/default/useradd makes accounts lock themselves a fixed number of days after their password expires, so accounts of people who left do not stay usable for years (HOST-PAM-007). These map to CIS Controls v8 safeguards 5.2 and 5.3 and to NIST SP 800-53 IA-5 and AC-2(3).",
			}},
			{"Root's Environment", []string{
				"When root's PATH contains . or an empty element, typing ls in a directory an attacker controls runs the attacker's ls as root. A world-writable directory on the PATH has the same effect for any command name not found earlier. HOST-PAM-008 reads root's shell start-up files for these entries; MITRE ATT&CK calls the technique path interception. TMOUT (HOST-PAM-009) closes an idle shell so a root session left on an unattended terminal is not free privilege for the next person.",
			}},
			{"How Packages Arrive", []string{
				"Package installation runs as root, so each repository is a supplier trusted with the whole machine. apt and dnf verify a signature over the repository index before trusting any package; trusted=yes, AllowUnauthenticated or gpgcheck=0 switches that off and lets a mirror operator or anyone on the network path deliver modified packages (HOST-PKG-002). Third-party repositories are not wrong in themselves, but each needs an owner and a reason (HOST-PKG-003); NIST SP 800-161 treats this as supply chain risk.",
				"Updates only help once they are in effect. Repository metadata must be refreshed on a schedule or no tool can see pending updates (HOST-PKG-006); a kernel update protects nothing until the machine boots into it (HOST-PKG-005); and every old kernel left installed stays bootable with every vulnerability it had (HOST-PKG-004). NIST SP 800-40 Rev. 4 covers this lifecycle; the checks map to CIS Controls v8 safeguard 7.4.",
			}},
			{"Services That Came Along", []string{
				"A service that is installed but stopped comes back with the next upgrade or reboot and is one command away from running. HOST-SVC-001 asks what is active now; HOST-SVC-002 to 012 read the package database and the systemd boot links for Telnet, the r-services and finger, TFTP, FTP, NIS, Avahi and CUPS, NFS and rpcbind, DHCP and DNS servers, Samba, SNMP and Squid, and inetd super-servers. The cleartext protocols (Telnet, rsh, TFTP, FTP, NIS) rate Medium because they send credentials or data unencrypted; the rest rate Low as attack surface with no purpose on a typical server. Where a machine legitimately runs one, the suppression file records the reason so the finding stays visible but accepted. This is NIST SP 800-123's advice to remove or disable unnecessary services, NIST SP 800-53 CM-7, and CIS Controls v8 safeguard 4.8.",
			}},
			{"In Summary", []string{
				"Password policy is enforced by PAM and login.defs together, so check both. Keep root's PATH clean, expire and warn on schedule, only install packages from signed repositories you recognise, refresh package lists, retire old kernels and remove the legacy services that arrived with the image.",
			}},
		},
		KeyTerms: []string{"PAM", "Password History", "Path Interception", "Repository Signing", "Legacy Service", "Idle Timeout"},
		RelatedChecks: []string{"HOST-PAM-001", "HOST-PAM-002", "HOST-PAM-003", "HOST-PAM-004", "HOST-PAM-005", "HOST-PAM-006", "HOST-PAM-007", "HOST-PAM-008", "HOST-PAM-009",
			"HOST-PKG-002", "HOST-PKG-003", "HOST-PKG-004", "HOST-PKG-005", "HOST-PKG-006",
			"HOST-SVC-002", "HOST-SVC-003", "HOST-SVC-004", "HOST-SVC-005", "HOST-SVC-006", "HOST-SVC-007", "HOST-SVC-008", "HOST-SVC-009", "HOST-SVC-010", "HOST-SVC-011", "HOST-SVC-012"},
		Lab: []string{
			"Run: openvapt demo --only HOST-PAM- --out p22a  and read the common-password stacks in internal/lab/fixtures_audit_pam_pkg.go side by side.",
			"Run: openvapt demo --only HOST-PKG- --out p22b  and find the sources.list entry that fails HOST-PKG-002 and the one listed by HOST-PKG-003.",
			"Run: openvapt demo --only HOST-SVC- --out p22c  and, for each failed check, decide whether removing the package or disabling the unit would be the right fix on a real server.",
			"On a test machine you own: sudo openvapt scan --only HOST-PAM-,HOST-PKG-,HOST-SVC- and compare with  grep pam_ /etc/pam.d/common-password  and  dpkg -l | grep '^ii' .",
		},
		Quiz: []Question{
			{"pwquality.conf sets minlen = 14, but /etc/pam.d/common-password has no pam_pwquality line. What is enforced?", []string{"A 14-character minimum", "Nothing from pwquality: the module is never called", "Only a dictionary check"}, 1, "PAM settings take effect only through the modules the stack actually calls."},
			{"Root's .bashrc sets PATH=.:/usr/bin:/bin. What can a local user do?", []string{"Nothing: . is harmless", "Place a program named ls in a directory root will visit and have it run as root", "Read root's files"}, 1, "A leading . (or empty element) runs programs from the current directory first."},
			{"A sources.list entry carries [trusted=yes]. What does apt skip for it?", []string{"Downloading the package", "Verifying the repository signature", "Installing dependencies"}, 1, "Without signature verification a tampered mirror or intercepted download installs as root."},
			{"telnetd is installed but systemctl says telnet.socket is inactive. Why do the HOST-SVC checks still report it?", []string{"Because active and installed are the same thing", "Because an installed service comes back with the next upgrade or reboot and is one command from running", "Because Telnet is encrypted"}, 1, "Installed-but-stopped is latent attack surface; remove what is not needed."},
		},
		Refs: []Ref{
			{"NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management", "https://pages.nist.gov/800-63-4/sp800-63b.html"},
			{"NIST SP 800-53 Rev. 5, IA-5, AC-7 and CM-7", "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
			{"NIST SP 800-40 Rev. 4, Guide to Enterprise Patch Management Planning", "https://csrc.nist.gov/pubs/sp/800/40/r4/final"},
			{"NIST SP 800-123, Guide to General Server Security", "https://csrc.nist.gov/pubs/sp/800/123/final"},
			{"pam.conf(5), Linux man-pages (PAM configuration)", "https://man7.org/linux/man-pages/man5/pam.conf.5.html"},
		},
	},
}

func init() {
	Modules = append(Modules, auditPamPkg...)
	for k, v := range map[string]string{
		"Audit Rule":                    "One line in the Linux audit configuration that tells the kernel which file writes or system calls to record, with the user, process and time attached.",
		"Audit Trail":                   "The ordered record of security-relevant events (logins, privilege use, changes to key files) that lets an investigator reconstruct what happened and who did it.",
		"Immutable Audit Configuration": "The -e 2 flag at the end of the audit rules, which locks them until the next reboot so that even root cannot switch auditing off quietly.",
		"Log Forwarding":                "Sending a copy of log messages to another machine as they are written, so an intruder who edits the local logs does not reach the only copy.",
		"Persistent Journal":            "A systemd journal stored on disk (Storage=persistent, under /var/log/journal) rather than only in memory, so it survives a reboot.",
		"PAM":                           "Pluggable Authentication Modules: the Linux framework through which programs check passwords and apply rules such as lockout, quality and history, configured in /etc/pam.d.",
		"Password History":              "Remembering a user's recent password hashes so that a changed password cannot be changed straight back to an old one.",
		"Path Interception":             "Getting a privileged user to run an attacker's program by placing it in a directory that appears on their PATH before the real command, for example through a . or empty PATH entry.",
		"Repository Signing":            "The digital signature over a package repository's index that apt and dnf verify before trusting any package in it; disabling the check lets a tampered mirror install code as root.",
		"Legacy Service":                "A network service such as Telnet, rsh, TFTP or NIS that predates modern encrypted alternatives and is rarely needed, but is still packaged and easy to leave installed.",
		"Idle Timeout":                  "Closing an interactive session automatically after a period without input (TMOUT in the shell), so an unattended logged-in terminal does not stay open.",
	} {
		Glossary[k] = v
	}
	// The semester course must teach every module; these join the Linux
	// Server Hardening week rather than editing teaching.go in place.
	for i := range Courses {
		if Courses[i].ID != "semester-14" {
			continue
		}
		for j := range Courses[i].Sessions {
			if Courses[i].Sessions[j].Week == 4 {
				Courses[i].Sessions[j].Modules = append(Courses[i].Sessions[j].Modules, "P21", "P22")
			}
		}
	}
}
