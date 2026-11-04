package academy

// Glossary terms introduced by module P15 (kernel, filesystem and boot
// hardening). Added from init so this file never edits the map literal
// another file owns.
func init() {
	for k, v := range map[string]string{
		"Sysctl":                    "The kernel's run-time settings, each one a file under /proc/sys; the sysctl command reads and writes them and /etc/sysctl.d makes a value permanent.",
		"Mount Option":              "A flag applied when a filesystem is mounted, such as nodev, nosuid or noexec, that limits what files on it may do.",
		"Umask":                     "The permission bits removed from every new file a process creates; 027 keeps new files unreadable to other users, 022 does not.",
		"Secure Boot":               "A UEFI firmware feature that refuses to run boot loaders and kernels that are not signed by a trusted key.",
		"Kernel Module":             "A piece of kernel code loaded at run time, such as a driver or filesystem; loading one gives full control of the kernel, so loading is restricted on hardened systems.",
		"File Integrity Monitoring": "Recording hashes, permissions and owners of important files as a baseline and comparing against it on a schedule to detect unexpected changes.",
		"Core Dump":                 "A file holding a crashed program's memory, written for debugging; it can contain passwords and keys the program held.",
	} {
		Glossary[k] = v
	}
}
