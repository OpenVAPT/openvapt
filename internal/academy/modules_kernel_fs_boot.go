package academy

// Module P15 teaches the kernel parameter depth, filesystem depth and boot
// and integrity check families (HOST-KRN-019 onwards, HOST-FS-010 onwards,
// HOST-BOOT). It is appended to the course from init so this file never
// edits the module list another file owns.

var kernelFSBoot = []Module{
	{
		ID: "P17", Title: "Kernel, Filesystem and Boot Hardening", Level: Practitioner, Minutes: 35,
		Prereqs: []string{"P1"},
		Summary: "Why the kernel's own switches, the layout and permissions of the filesystem, and what happens before login decide how far an attacker with a foothold can get.",
		Objectives: []string{
			"Explain what the main kernel hardening parameters protect against and where their values live.",
			"Explain why temporary, home and log directories are mounted separately with nodev, nosuid and noexec.",
			"Audit SUID programs, unowned files, sticky bits, cron access lists and the default umask.",
			"Explain how a boot loader password, Secure Boot, module restrictions and file integrity monitoring work together.",
		},
		Sections: []Section{
			{"Kernel Parameters Beyond the Basics", []string{
				"Every value under /proc/sys is a switch in the running kernel, and OpenVAPT reads those files directly instead of running sysctl. Module P1 covered address space layout randomisation, hidden kernel pointers and the common network settings. The depth checks add the rest of the set the Kernel Self Protection Project recommends for servers. Protected FIFOs and regular files in shared directories (fs.protected_fifos and fs.protected_regular) close the last of the classic /tmp tricks. User namespaces, userfaultfd, TTY line discipline autoload and io_uring are features normal users rarely need. Each has been the first step of real local privilege escalations. kexec lets root swap the running kernel and so bypass Secure Boot. BPF just-in-time hardening stops attacker-chosen constants landing in executable kernel memory.",
				"On the network side, the depth checks close the IPv6 copies of the IPv4 rules (source routing, router advertisements). They also cover the secure_redirects setting, often forgotten when accept_redirects is turned off. The magic SysRq key is disabled because anyone at a console can otherwise reboot or dump memory without a password. A permanent setting goes in a file under /etc/sysctl.d, which is applied at every boot by sysctl --system.",
			}},
			{"Mounts and Mount Options", []string{
				"A filesystem that is a separate mount can carry options that the root filesystem cannot. nodev stops device files being created where users can write, nosuid stops a planted setuid program gaining privilege, and noexec stops downloaded tools running at all. Temporary directories, user homes and the log tree are where untrusted users or runaway processes write. Putting each on its own mount also stops a full disk in one place from stopping the whole server. OpenVAPT reads the mount table from /proc/mounts, so what it reports is what the kernel is enforcing now, not what /etc/fstab promises after the next reboot.",
			}},
			{"Ownership, SUID Inventory and Shared Directories", []string{
				"A file whose owner id no longer exists in /etc/passwd will belong to the next account created with that id. That is how a new intern inherits an old administrator's scripts. Set-user-ID programs run with their owner's rights, so each one is a potential door to root. The inventory check compares every SUID program in the system directories with a documented baseline of what distributions ship. It lists the rest for a human decision. A shared writable directory needs the sticky bit so one user cannot delete or replace another user's files, and a service's upload folder is the same problem as /tmp.",
				"The default umask decides what new files everyone else can read. /etc/login.defs sets it for logins, but a umask line in /etc/profile or /etc/bash.bashrc overrides it for every interactive shell, which is why both are checked. Cron and at should use allow lists rather than deny lists, and the cron configuration should be unreadable to normal users so they cannot learn which root scripts run when. Backup copies of the account database (passwd-, shadow-) carry the same secrets as the live files and need the same ownership and modes.",
			}},
			{"Boot Loader, Secure Boot and Kernel Modules", []string{
				"Everything above assumes the kernel that is running is the one you installed. A boot loader without a password lets anyone at the console add init=/bin/bash to the kernel command line and get root. GRUB fixes that with a superuser and a PBKDF2 password hash. Secure Boot makes the firmware refuse unsigned boot loaders and kernels, and OpenVAPT reads its state from the EFI variable rather than running a command. Once booted, kernel module signing (module.sig_enforce), lockdown mode or kernel.modules_disabled stop a root-level attacker loading a rootkit module. modprobe.d install lines disable drivers nobody needs, such as rarely used filesystems and USB storage.",
			}},
			{"Integrity Monitoring, Prelink and Core Dumps", []string{
				"After a compromise the question is which files changed. A file integrity tool such as AIDE records a baseline of hashes and permissions and compares against it on a schedule. A tool that is installed but never scheduled protects nothing, so the check wants both. Prelink rewrites binaries in place, which breaks those hashes and package verification, so it should be absent. Core dumps are copies of a crashed program's memory, including any passwords or keys it held. A hard core 0 limit in PAM, and Storage=none where systemd-coredump collects dumps, keep them from being written at all.",
			}},
			{"In Summary", []string{
				"The kernel, the mounts and the boot chain decide what a process may do before any application code runs. Read sysctl values from /proc/sys and give temporary and shared directories noexec, nosuid and nodev. Keep the SUID list short and known, and protect the boot loader and the module list. Let an integrity tool and a core dump policy show when something changed.",
			}},
		},
		KeyTerms:      []string{"Sysctl", "Mount Option", "Sticky Bit", "SUID", "Umask", "Secure Boot", "Kernel Module", "File Integrity Monitoring", "Core Dump", "Hardening"},
		RelatedChecks: []string{"HOST-KRN-019", "HOST-KRN-020", "HOST-KRN-021", "HOST-KRN-022", "HOST-KRN-023", "HOST-KRN-024", "HOST-KRN-025", "HOST-KRN-026", "HOST-KRN-027", "HOST-KRN-028", "HOST-KRN-029", "HOST-KRN-030", "HOST-KRN-031", "HOST-FS-010", "HOST-FS-011", "HOST-FS-012", "HOST-FS-013", "HOST-FS-014", "HOST-FS-015", "HOST-FS-016", "HOST-FS-017", "HOST-FS-018", "HOST-FS-019", "HOST-FS-020", "HOST-FS-021", "HOST-FS-022", "HOST-BOOT-"},
		Lab: []string{
			"Run: openvapt demo --only HOST-KRN- --out p15 and read the evidence line of each failed kernel parameter; find its hardened value in internal/lab/fixtures_kernel_fs_boot.go.",
			"Run: openvapt explain HOST-FS-016 and compare the baseline list in the source with the SUID programs on a test machine you own: find /usr/bin /usr/sbin -perm /6000 -type f",
			"Run: openvapt demo --only HOST-BOOT- and explain, for each finding, what an attacker with console access could do before the fix.",
			"On a test machine you own: findmnt -no TARGET,OPTIONS /tmp /var/tmp /dev/shm /home and decide which options are missing.",
		},
		Quiz: []Question{
			{"Where does OpenVAPT read kernel parameter values from?", []string{"The output of the sysctl command", "Files under /proc/sys", "/etc/sysctl.conf", "The kernel boot log from dmesg"}, 1, "Reading /proc/sys shows the value the kernel enforces now, without running a command."},
			{"What does the noexec mount option on /tmp prevent?", []string{"Creating files in /tmp", "Running programs stored in /tmp", "Reading other users' files in /tmp", "Deleting other users' files in /tmp"}, 1, "Downloaded tools cannot be executed from a noexec filesystem."},
			{"A file is owned by uid 1003, which is not in /etc/passwd. What is the risk?", []string{"The file cannot be opened by anyone", "The next account created with uid 1003 inherits it", "The kernel deletes it at reboot", "Root automatically takes ownership of it"}, 1, "Ownership is numeric; a new account with that id silently owns old files."},
			{"Why does a GRUB password matter on a server in a locked room?", []string{"It encrypts the disk", "Console and virtual console access still allows editing the boot command line", "It is required by Secure Boot", "It makes the server boot faster"}, 1, "Anyone with console or out-of-band management access can otherwise boot to a root shell."},
			{"AIDE is installed but no timer or cron job runs it. Does the integrity check pass?", []string{"Yes, the tool is present", "No, a baseline that is never compared protects nothing", "Only if prelink is absent", "Yes, if it came from a signed package"}, 1, "The check wants the tool and a scheduled comparison."},
		},
		Refs: []Ref{
			{"Linux kernel documentation, /proc/sys/kernel", "https://docs.kernel.org/admin-guide/sysctl/kernel.html"},
			{"Kernel Self Protection Project, Recommended Settings", "https://kspp.github.io/Recommended_Settings"},
			{"NIST SP 800-123, Guide to General Server Security", "https://csrc.nist.gov/pubs/sp/800/123/final"},
			{"GNU GRUB Manual, Security", "https://www.gnu.org/software/grub/manual/grub/html_node/Security.html"},
			{"AIDE, Advanced Intrusion Detection Environment", "https://aide.github.io/"},
		},
	},
}

func init() { Modules = append(Modules, kernelFSBoot...) }
