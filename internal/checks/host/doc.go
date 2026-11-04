// Package host contains checks that look at the operating system itself:
// patch level, SSH daemon, accounts, file permissions, kernel hardening,
// logging and time synchronisation.
package host

import "github.com/openvapt/openvapt/internal/check"

// Shared references, cited by several checks in this package.
var (
	refSSHDManual = check.Ref{Title: "OpenBSD, sshd_config(5) manual page", URL: "https://man.openbsd.org/sshd_config"}
	refNIST80053  = check.Ref{Title: "NIST SP 800-53 Rev. 5, Security and Privacy Controls", URL: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"}
	refNIST800123 = check.Ref{Title: "NIST SP 800-123, Guide to General Server Security", URL: "https://csrc.nist.gov/pubs/sp/800/123/final"}
	refKernelDocs = check.Ref{Title: "Linux kernel documentation, /proc/sys/kernel", URL: "https://docs.kernel.org/admin-guide/sysctl/kernel.html"}
	refKernelNet  = check.Ref{Title: "Linux kernel documentation, IP sysctl", URL: "https://docs.kernel.org/networking/ip-sysctl.html"}
)
