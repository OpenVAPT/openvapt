package host

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Kernel parameter depth: the second table of sysctl rules. Every row is a
// parameter that kernel.go does not already cover (the first table holds
// ASLR, kptr_restrict, dmesg_restrict, suid_dumpable, ptrace_scope,
// unprivileged_bpf_disabled, protected_symlinks and hardlinks, rp_filter,
// log_martians, send_redirects, the ICMP and source-route settings and
// perf_event_paranoid). Values come from /proc/sys; no command is run.
//
// Sources: Linux kernel documentation (docs.kernel.org), the Kernel
// Self Protection Project recommended settings, NIST SP 800-123 and SP
// 800-53 CM-6 and CM-7, CIS Controls v8 safeguard 4.1 by id.

var (
	refKSPP      = check.Ref{Title: "Kernel Self Protection Project, Recommended Settings", URL: "https://kspp.github.io/Recommended_Settings"}
	refKernelFS  = check.Ref{Title: "Linux kernel documentation, /proc/sys/fs", URL: "https://docs.kernel.org/admin-guide/sysctl/fs.html"}
	refKernelVM  = check.Ref{Title: "Linux kernel documentation, /proc/sys/vm", URL: "https://docs.kernel.org/admin-guide/sysctl/vm.html"}
	refKernelUNS = check.Ref{Title: "user_namespaces(7), Linux man-pages", URL: "https://man7.org/linux/man-pages/man7/user_namespaces.7.html"}
	refSysRq     = check.Ref{Title: "Linux kernel documentation, Linux Magic System Request Key Hacks", URL: "https://docs.kernel.org/admin-guide/sysrq.html"}
)

var sysctlDepthRules = []sysctlRule{
	{"HOST-KRN-019", "Magic SysRq Key Enabled", "kernel.sysrq", "0",
		"Checks that the magic SysRq key combination is disabled or limited to keyboard synchronisation.",
		"With SysRq enabled, anyone at a console or with access to /proc/sysrq-trigger can reboot the machine, kill every process or dump memory without logging in.",
		check.Low, "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", refSysRq, "CWE-749", []string{"4"}},
	{"HOST-KRN-020", "FIFO Protection in Shared Directories Disabled", "fs.protected_fifos", "1",
		"Checks that the kernel refuses to open FIFOs in world-writable sticky directories that another user owns.",
		"A FIFO planted in /tmp can make a privileged program block or write into an attacker-controlled pipe, a classic step in local attacks.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKernelFS, "CWE-59", []string{"2"}},
	{"HOST-KRN-021", "Regular File Protection in Shared Directories Disabled", "fs.protected_regular", "1",
		"Checks that the kernel refuses to open, with O_CREAT, regular files in world-writable sticky directories that another user owns.",
		"Without it, a user can pre-create a file that a root-run script later writes to in /tmp, redirecting privileged output into a file they control.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKernelFS, "CWE-59", []string{"2"}},
	{"HOST-KRN-023", "IPv6 Source-Routed Packets Accepted", "net.ipv6.conf.all.accept_source_route", "0",
		"Checks that the kernel drops IPv6 packets that dictate their own route.",
		"IPv6 routing headers can be used to bypass filters and spoof trusted addresses, as source routing could in IPv4.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-024", "Secure ICMP Redirects Accepted", "net.ipv4.conf.all.secure_redirects", "0",
		"Checks that the kernel also ignores ICMP redirects that come from its configured gateways.",
		"An attacker who spoofs the gateway address can still reroute traffic unless secure redirects are off as well; a server has no reason to accept redirects at all.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-025", "IPv6 Router Advertisements Accepted", "net.ipv6.conf.all.accept_ra", "0",
		"Checks that the server does not reconfigure its IPv6 addresses and routes from router advertisements.",
		"A rogue router advertisement on the local network can add a default route through an attacker's machine or assign addresses that bypass firewall rules; servers use static addressing.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-026", "Bogus ICMP Error Responses Logged", "net.ipv4.icmp_ignore_bogus_error_responses", "1",
		"Checks that the kernel silently ignores malformed ICMP error responses instead of logging each one.",
		"Logging every bogus ICMP error lets a remote sender fill the kernel log and disk at will, hiding real events among noise.",
		check.Low, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", refKernelNet, "CWE-779", nil},
	{"HOST-KRN-027", "Kexec Kernel Replacement Allowed", "kernel.kexec_load_disabled", "1",
		"Checks that a running kernel cannot be replaced at run time with kexec.",
		"kexec lets root boot a different kernel without going through the firmware, which bypasses Secure Boot and module signing and is used to load unsigned kernels after a compromise.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:L", refKSPP, "CWE-749", nil},
	{"HOST-KRN-028", "Unprivileged userfaultfd Allowed", "vm.unprivileged_userfaultfd", "0",
		"Checks that only privileged processes can use userfaultfd.",
		"userfaultfd lets a process pause the kernel at a chosen moment, which has turned many kernel race conditions into reliable local exploits.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKernelVM, "CWE-749", nil},
	{"HOST-KRN-029", "TTY Line Discipline Autoloading Enabled", "dev.tty.ldisc_autoload", "0",
		"Checks that unprivileged users cannot make the kernel load terminal line discipline modules.",
		"Automatically loaded line disciplines have carried several exploitable kernel bugs; disabling autoload shrinks the kernel attack surface reachable from a normal shell.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKSPP, "CWE-1188", nil},
	{"HOST-KRN-030", "BPF JIT Hardening Off", "net.core.bpf_jit_harden", "2",
		"Checks that the BPF just-in-time compiler blinds constants in generated code for every user.",
		"Without hardening, attacker-chosen constants in BPF programs land in executable kernel memory, a known technique for building kernel exploit payloads.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKSPP, "CWE-1188", []string{"1"}},
	{"HOST-KRN-031", "io_uring Open to Unprivileged Users", "kernel.io_uring_disabled", "2",
		"Checks that io_uring is disabled, or limited to privileged processes, on kernels that offer the setting.",
		"io_uring has produced a long run of local privilege-escalation bugs; several large operators disable it for untrusted workloads.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKSPP, "CWE-749", []string{"1"}},
}

func init() {
	for _, r := range sysctlDepthRules {
		registerSysctl(r)
	}

	check.Register(&check.Check{
		ID: "HOST-KRN-022", Title: "Unprivileged User Namespaces Allowed", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that normal users cannot create user namespaces, unless the server runs containers that need them.",
		Rationale: "User namespaces give an unprivileged process a fake root inside a namespace, which exposes kernel code paths that were written for root only; many local kernel exploits start by unsharing a user namespace.",
		Detection: "Reads /proc/sys/kernel/unprivileged_userns_clone (Debian and Ubuntu kernels) and, when that does not exist, /proc/sys/user/max_user_namespaces. The first is hardened at 0; the second at 0. Kernels with neither parameter are skipped. Passes with a note when /proc/sys/kernel/apparmor_restrict_unprivileged_userns is 1 (Ubuntu 23.10 and later), because AppArmor then denies the namespace capabilities to unconfined programs. Container hosts that need rootless namespaces should suppress this check deliberately.",
		Fix:       "Create /etc/sysctl.d/60-openvapt-hardening.conf containing  kernel.unprivileged_userns_clone = 0  (Debian family) or  user.max_user_namespaces = 0  (other kernels), then apply with: sysctl --system. Rootless Docker, Podman, Flatpak and some browsers need user namespaces, so test first.",
		Verify:    "sysctl kernel.unprivileged_userns_clone user.max_user_namespaces",
		Refs:      []check.Ref{refKernelUNS, refKSPP},
		Standards: check.Standards{CWE: []string{"CWE-749"}, NIST: []string{"CM-6", "CM-7"}, CISTopic: "Kernel parameters: user namespaces (CIS Controls v8 4.1)"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			// Ubuntu 23.10 and later: AppArmor confines unprivileged user
			// namespaces by default, which removes the exposed code paths.
			if v, err := collect.Sysctl(s, "kernel.apparmor_restrict_unprivileged_userns"); err == nil && strings.TrimSpace(v) == "1" {
				return []check.Result{check.PassR("kernel.apparmor_restrict_unprivileged_userns", "Unprivileged user namespaces are restricted by AppArmor (kernel.apparmor_restrict_unprivileged_userns = 1, the Ubuntu 23.10 and later default): only profiled programs get full namespace rights", "kernel.apparmor_restrict_unprivileged_userns = 1")}
			}
			for _, k := range []string{"kernel.unprivileged_userns_clone", "user.max_user_namespaces"} {
				v, err := collect.Sysctl(s, k)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						continue
					}
					return []check.Result{check.IncompleteR(k, "Parameter could not be read")}
				}
				v = strings.TrimSpace(v)
				if v == "0" {
					return []check.Result{check.PassR(k, k+" = 0")}
				}
				return []check.Result{check.FailR(k, k+" = "+v+" (hardened value: 0)")}
			}
			return []check.Result{check.SkipR("kernel.unprivileged_userns_clone", "Parameter not available on this kernel")}
		},
	})
}
