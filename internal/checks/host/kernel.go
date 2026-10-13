package host

import (
	"context"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// sysctlRule describes one kernel parameter and its hardened value.
type sysctlRule struct {
	id, title, key, want, summary, rationale string
	sev                                      check.Severity
	cvss                                     string
	ref                                      check.Ref
	cwe                                      string
	allowed                                  []string // values that also pass
}

// One table, one loop: each row becomes its own registered check, so every
// kernel setting has its own catalogue page, id and result.
var sysctlRules = []sysctlRule{
	{"HOST-KRN-001", "Address Space Layout Randomisation Not Fully Enabled", "kernel.randomize_va_space", "2",
		"Checks that the kernel randomises memory layout for stack, libraries, heap and VDSO.",
		"ASLR makes memory-corruption exploits much harder because attackers cannot predict where code lives.",
		check.Medium, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", refKernelDocs, "CWE-1260", nil},
	{"HOST-KRN-002", "Kernel Pointers Exposed to Unprivileged Users", "kernel.kptr_restrict", "1",
		"Checks that kernel memory addresses are hidden from normal users.",
		"Leaked kernel addresses defeat kernel ASLR and are the first step of most local kernel exploits.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKernelDocs, "CWE-200", []string{"2"}},
	{"HOST-KRN-003", "Kernel Log Readable by Unprivileged Users", "kernel.dmesg_restrict", "1",
		"Checks that only privileged users can read the kernel log (dmesg).",
		"The kernel log can reveal addresses, hardware and driver details useful for local exploitation.",
		check.Low, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", refKernelDocs, "CWE-200", nil},
	{"HOST-KRN-004", "Setuid Programs May Dump Core", "fs.suid_dumpable", "0",
		"Checks that privileged programs do not write core dumps.",
		"A core dump of a setuid program can contain password hashes or keys and may be readable by the user who crashed it.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", check.Ref{Title: "Linux kernel documentation, /proc/sys/fs", URL: "https://docs.kernel.org/admin-guide/sysctl/fs.html"}, "CWE-528", nil},
	{"HOST-KRN-005", "IP Forwarding Enabled", "net.ipv4.ip_forward", "0",
		"Checks that the server does not route packets between networks.",
		"A server that forwards packets can be used to pivot between networks. Only routers, VPN gateways and container hosts need this.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N", refKernelNet, "CWE-16", nil},
	{"HOST-KRN-006", "ICMP Redirects Accepted", "net.ipv4.conf.all.accept_redirects", "0",
		"Checks that the kernel ignores ICMP redirect messages.",
		"Forged ICMP redirects let an attacker on the local network reroute the server's traffic through themselves.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-007", "Source-Routed Packets Accepted", "net.ipv4.conf.all.accept_source_route", "0",
		"Checks that the kernel drops packets that dictate their own route.",
		"Source routing lets an attacker bypass network filtering and spoof trusted addresses.",
		check.Low, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-008", "TCP SYN Cookies Disabled", "net.ipv4.tcp_syncookies", "1",
		"Checks that SYN cookies protect the server from SYN flood attacks.",
		"Without SYN cookies a simple flood of half-open connections can make every service unreachable.",
		check.Low, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", refKernelNet, "CWE-400", nil},
	{"HOST-KRN-009", "Unprivileged eBPF Allowed", "kernel.unprivileged_bpf_disabled", "1",
		"Checks that normal users cannot load eBPF programs into the kernel.",
		"Unprivileged eBPF has been the entry point for many local privilege-escalation bugs.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", refKernelDocs, "CWE-269", []string{"2"}},
}

func init() {
	for _, r := range sysctlRules {
		r := r
		ok := append([]string{r.want}, r.allowed...)
		check.Register(&check.Check{
			ID: r.id, Title: r.title, Domain: check.DomainHost, Severity: r.sev, CVSS: r.cvss,
			Summary:   r.summary,
			Rationale: r.rationale,
			Detection: "Reads /proc/sys/" + slash(r.key) + " directly (no command is run) and compares it with the hardened value " + r.want + ".",
			Fix:       "Create /etc/sysctl.d/60-openvapt-hardening.conf containing:  " + r.key + " = " + r.want + "  then apply with: sysctl --system",
			Verify:    "sysctl " + r.key + "  should print " + r.want + ".",
			Refs:      []check.Ref{r.ref},
			Standards: check.Standards{CWE: []string{r.cwe}, NIST: []string{"CM-6", "SI-16"}, CISTopic: "Kernel parameters: " + r.key},
			Run: func(_ context.Context, s sys.System) []check.Result {
				v, err := collect.Sysctl(s, r.key)
				if err != nil {
					return []check.Result{check.SkipR(r.key, "Parameter not available on this kernel")}
				}
				for _, good := range ok {
					if v == good {
						return []check.Result{check.PassR(r.key, r.key+" = "+v)}
					}
				}
				return []check.Result{check.FailR(r.key, r.key+" = "+v+" (hardened value: "+r.want+")")}
			},
		})
	}
}

func slash(k string) string {
	b := []byte(k)
	for i := range b {
		if b[i] == '.' {
			b[i] = '/'
		}
	}
	return string(b)
}
