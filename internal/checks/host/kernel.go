package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

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
		check.Medium, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", refKernelDocs, "CWE-693", nil},
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
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", check.Ref{Title: "Linux kernel documentation, /proc/sys/fs", URL: "https://docs.kernel.org/admin-guide/sysctl/fs.html"}, "CWE-528", nil},
	{"HOST-KRN-005", "IP Forwarding Enabled", "net.ipv4.ip_forward", "0",
		"Checks that the server does not route packets between networks.",
		"A server that forwards packets can be used to pivot between networks. Only routers, VPN gateways and container hosts need this.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-1188", nil},
	{"HOST-KRN-006", "ICMP Redirects Accepted", "net.ipv4.conf.all.accept_redirects", "0",
		"Checks that the kernel ignores ICMP redirect messages.",
		"Forged ICMP redirects let an attacker on the local network reroute the server's traffic through themselves.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-007", "Source-Routed Packets Accepted", "net.ipv4.conf.all.accept_source_route", "0",
		"Checks that the kernel drops packets that dictate their own route.",
		"Source routing lets an attacker bypass network filtering and spoof trusted addresses.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-008", "TCP SYN Cookies Disabled", "net.ipv4.tcp_syncookies", "1",
		"Checks that SYN cookies protect the server from SYN flood attacks.",
		"Without SYN cookies a simple flood of half-open connections can make every service unreachable.",
		check.Low, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", refKernelNet, "CWE-400", nil},
	{"HOST-KRN-009", "Unprivileged eBPF Allowed", "kernel.unprivileged_bpf_disabled", "1",
		"Checks that normal users cannot load eBPF programs into the kernel.",
		"Unprivileged eBPF has been the entry point for many local privilege-escalation bugs.",
		check.Medium, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", refKernelDocs, "CWE-269", []string{"2"}},
	{"HOST-KRN-010", "Process Tracing Not Restricted", "kernel.yama.ptrace_scope", "1",
		"Checks that processes cannot attach a debugger to other processes of the same user.",
		"Unrestricted ptrace lets any compromised process read the memory of others, for example to steal SSH agent keys or browser sessions.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", check.Ref{Title: "Linux kernel documentation, Yama LSM", URL: "https://docs.kernel.org/admin-guide/LSM/Yama.html"}, "CWE-269", []string{"2", "3"}},
	{"HOST-KRN-011", "Symlink Protection Disabled", "fs.protected_symlinks", "1",
		"Checks that the kernel blocks following symlinks owned by other users in world-writable sticky directories.",
		"Without it, classic /tmp symlink races let local users trick root-run programs into overwriting files.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", check.Ref{Title: "Linux kernel documentation, /proc/sys/fs", URL: "https://docs.kernel.org/admin-guide/sysctl/fs.html"}, "CWE-59", nil},
	{"HOST-KRN-012", "Hardlink Protection Disabled", "fs.protected_hardlinks", "1",
		"Checks that users cannot create hard links to files they do not own.",
		"Hard links to privileged files enable time-of-check races and keep vulnerable setuid binaries alive after updates.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", check.Ref{Title: "Linux kernel documentation, /proc/sys/fs", URL: "https://docs.kernel.org/admin-guide/sysctl/fs.html"}, "CWE-59", nil},
	{"HOST-KRN-013", "Reverse Path Filtering Disabled", "net.ipv4.conf.all.rp_filter", "1",
		"Checks that the kernel drops packets whose source address could not be routed back through the receiving interface.",
		"Reverse path filtering blocks many spoofed-source packets used in attacks and amplification.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-940", []string{"2"}},
	{"HOST-KRN-014", "Martian Packets Not Logged", "net.ipv4.conf.all.log_martians", "1",
		"Checks that packets with impossible source addresses are logged.",
		"Logging martian packets helps detect spoofing and misrouting attempts.",
		check.Low, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-778", nil},
	{"HOST-KRN-015", "Server Sends ICMP Redirects", "net.ipv4.conf.all.send_redirects", "0",
		"Checks that the server does not send ICMP redirects, which only routers should do.",
		"A non-router sending redirects can be abused to influence other hosts' routing on the local network.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-1188", nil},
	{"HOST-KRN-016", "Broadcast ICMP Echo Answered", "net.ipv4.icmp_echo_ignore_broadcasts", "1",
		"Checks that the server ignores ping requests sent to broadcast addresses.",
		"Answering broadcast pings makes the server a participant in Smurf-style amplification attacks.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", refKernelNet, "CWE-406", nil},
	{"HOST-KRN-017", "IPv6 ICMP Redirects Accepted", "net.ipv6.conf.all.accept_redirects", "0",
		"Checks that the kernel ignores IPv6 ICMP redirect messages.",
		"Forged IPv6 redirects let an attacker on the local network reroute traffic through themselves.",
		check.Low, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", refKernelNet, "CWE-940", nil},
	{"HOST-KRN-018", "Performance Events Open to Unprivileged Users", "kernel.perf_event_paranoid", "2",
		"Checks that unprivileged users cannot use kernel performance events to observe the system.",
		"Unrestricted perf events expose kernel and other processes' activity and have been used in local exploits.",
		check.Low, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", refKernelDocs, "CWE-200", []string{"3", "4"}},
}

func init() {
	for _, r := range sysctlRules {
		r := r
		ok := append([]string{r.want}, r.allowed...)
		check.Register(&check.Check{
			ID: r.id, Title: r.title, Domain: check.DomainHost, Severity: r.sev, CVSS: r.cvss,
			Summary:   r.summary,
			Rationale: r.rationale,
			Detection: sysctlDetection(r),
			Fix:       "Create /etc/sysctl.d/60-openvapt-hardening.conf containing:  " + r.key + " = " + r.want + "  then apply with: sysctl --system",
			Verify:    "sysctl " + r.key + "  should print " + r.want + ".",
			Refs:      []check.Ref{r.ref},
			Standards: check.Standards{CWE: []string{r.cwe}, NIST: sysctlNIST(r.id, r.key), CISTopic: "Kernel parameters: " + r.key},
			Run: func(_ context.Context, s sys.System) []check.Result {
				if combinedSysctl[r.id] != nil {
					return runCombinedSysctl(s, r.id, r.key, r.want)
				}
				if perInterfaceSysctl[r.id] {
					return runPerInterfaceSysctl(s, r.key, r.want, ok)
				}
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

// perInterfaceSysctl lists the rules whose kernel parameter also exists per
// network interface. The kernel combines "all" with each interface value, so
// every one of all, default and each interface must hold the hardened value.
var perInterfaceSysctl = map[string]bool{"HOST-KRN-006": true, "HOST-KRN-015": true, "HOST-KRN-017": true}

// combinedSysctl lists IPv4 rules where the kernel combines the "all" value
// with each interface value in a rule-specific way (include/linux/inetdevice.h):
// rp_filter uses the larger of the two, log_martians is on when either is on,
// and accept_redirects needs both on when the interface forwards packets but
// either one otherwise. good reports whether the combined result is hardened.
var combinedSysctl = map[string]func(all, iface int, forwarding bool) bool{
	"HOST-KRN-006": func(all, iface int, fwd bool) bool {
		if fwd {
			return all == 0 || iface == 0
		}
		return all == 0 && iface == 0
	},
	"HOST-KRN-013": func(all, iface int, _ bool) bool { m := max(all, iface); return m == 1 || m == 2 },
	"HOST-KRN-014": func(all, iface int, _ bool) bool { return all == 1 || iface == 1 },
}

var combinedDetection = map[string]string{
	"HOST-KRN-006": "The kernel ignores redirects on an interface when both values are 0 or, on an interface that forwards packets (net.ipv4.ip_forward or the interface's forwarding setting), when either one is 0; any interface where redirects remain accepted fails.",
	"HOST-KRN-013": "The kernel uses the larger of the two values, so an interface passes when that larger value is 1 (strict) or 2 (loose).",
	"HOST-KRN-014": "The kernel logs martians on an interface when either value is 1, so an interface passes when all or the interface value is 1.",
}

func sysctlDetection(r sysctlRule) string {
	if d, ok := combinedDetection[r.id]; ok {
		g := strings.Replace(slash(r.key), "/all/", "/*/", 1)
		return "Reads /proc/sys/" + g + " directly (all, default for future interfaces, and every interface except loopback; no command is run) and combines the all value with each interface value as the kernel does. " + d
	}
	if perInterfaceSysctl[r.id] {
		g := strings.Replace(slash(r.key), "/all/", "/*/", 1)
		return "Reads /proc/sys/" + g + " directly (all, default and every interface; no command is run) and fails if any of them differs from the hardened value " + r.want + "."
	}
	return "Reads /proc/sys/" + slash(r.key) + " directly (no command is run) and compares it with the hardened value " + r.want + "."
}

// sysctlNIST maps a kernel rule to NIST SP 800-53 Rev. 5 controls: SI-16 for
// memory protection, SC-7 for network boundary settings, SC-5 for denial of
// service protection and AC-6 for least privilege on local information.
func sysctlNIST(id, key string) []string {
	switch id {
	case "HOST-KRN-001", "HOST-KRN-002", "HOST-KRN-009", "HOST-KRN-018":
		return []string{"CM-6", "SI-16"}
	case "HOST-KRN-008", "HOST-KRN-016":
		return []string{"SC-5", "CM-6"}
	}
	if strings.HasPrefix(key, "net.") {
		return []string{"SC-7", "CM-6"}
	}
	return []string{"AC-6", "CM-6"}
}

// runPerInterfaceSysctl evaluates a ".conf.all." parameter together with its
// "default" and per-interface siblings.
func runPerInterfaceSysctl(s sys.System, key, want string, ok []string) []check.Result {
	base := "/proc/sys/" + slash(key)
	pat := strings.Replace(base, "/all/", "/*/", 1)
	paths, _ := s.Glob(pat)
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
	}
	for _, p := range []string{base, strings.Replace(base, "/all/", "/default/", 1)} {
		if !seen[p] {
			paths = append(paths, p)
			seen[p] = true
		}
	}
	sort.Strings(paths)
	var bad []string
	read, unreadable := 0, 0
	for _, p := range paths {
		// Read the path directly: interface names may contain dots
		// (VLANs such as eth0.100), which a dotted sysctl key cannot express.
		k := strings.TrimPrefix(p, "/proc/sys/")
		rr, err := s.ReadFile(context.Background(), p)
		if err != nil || !rr.Complete {
			if !errors.Is(err, fs.ErrNotExist) {
				unreadable++
			}
			continue
		}
		v := strings.TrimSpace(string(rr.Data))
		read++
		good := false
		for _, g := range ok {
			if v == g {
				good = true
				break
			}
		}
		if !good {
			bad = append(bad, k+" = "+v)
		}
	}
	if read == 0 {
		return []check.Result{check.SkipR(key, "Parameter not available on this kernel")}
	}
	if len(bad) > 0 {
		return []check.Result{check.FailR(key, fmt.Sprintf("%d of %d setting(s) differ from the hardened value %s", len(bad), read, want), bad...)}
	}
	if unreadable > 0 {
		return []check.Result{check.IncompleteR(key, fmt.Sprintf("%d setting(s) could not be read; the readable ones hold the hardened value", unreadable))}
	}
	return []check.Result{check.PassR(key, fmt.Sprintf("%s = %s for all, default and every interface (%d settings)", key, want, read))}
}

// runCombinedSysctl evaluates an IPv4 ".conf.all." parameter the way the
// kernel applies it: the all value combined with each interface value (and
// with default, which new interfaces inherit). Loopback is skipped: these
// settings concern packets arriving from a network.
func runCombinedSysctl(s sys.System, id, key, want string) []check.Result {
	good := combinedSysctl[id]
	base := "/proc/sys/" + slash(key)
	name := base[strings.LastIndex(base, "/")+1:]
	read := func(p string) (int, bool, bool) { // value, ok, unreadable
		rr, err := s.ReadFile(context.Background(), p)
		if err != nil || !rr.Complete {
			return 0, false, !errors.Is(err, fs.ErrNotExist)
		}
		var n int
		if _, err := fmt.Sscan(strings.TrimSpace(string(rr.Data)), &n); err != nil {
			return 0, false, true
		}
		return n, true, false
	}
	all, ok, _ := read(base)
	if !ok {
		return []check.Result{check.SkipR(key, "Parameter not available on this kernel")}
	}
	ipFwd, _, _ := read("/proc/sys/net/ipv4/ip_forward")
	paths, _ := s.Glob(strings.Replace(base, "/all/", "/*/", 1))
	def := strings.Replace(base, "/all/", "/default/", 1)
	seen := map[string]bool{base: true}
	ifaces := []string{}
	for _, p := range append(paths, def) {
		dir := strings.TrimSuffix(p, "/"+name)
		ifn := dir[strings.LastIndex(dir, "/")+1:]
		if seen[p] || ifn == "lo" {
			continue
		}
		seen[p] = true
		ifaces = append(ifaces, p)
	}
	sort.Strings(ifaces)
	var bad []string
	checked, unreadable := 0, 0
	for _, p := range ifaces {
		v, ok, unr := read(p)
		if !ok {
			if unr {
				unreadable++
			}
			continue
		}
		checked++
		dir := strings.TrimSuffix(p, "/"+name)
		fwd := ipFwd == 1
		if f, ok, _ := read(dir + "/forwarding"); ok && f == 1 {
			fwd = true
		}
		if !good(all, v, fwd) {
			note := fmt.Sprintf(" (all = %d", all)
			if id == "HOST-KRN-006" && fwd {
				note += ", interface forwards packets"
			}
			bad = append(bad, strings.TrimPrefix(p, "/proc/sys/")+fmt.Sprintf(" = %d", v)+note+")")
		}
	}
	if checked == 0 && unreadable == 0 {
		// No interface or default value is visible: judge all by itself.
		if !good(all, all, ipFwd == 1) {
			return []check.Result{check.FailR(key, fmt.Sprintf("%s = %d (hardened value: %s)", key, all, want))}
		}
		return []check.Result{check.PassR(key, fmt.Sprintf("%s = %d", key, all))}
	}
	if len(bad) > 0 {
		return []check.Result{check.FailR(key, fmt.Sprintf("%d interface setting(s) are not hardened once combined with all (hardened value: %s)", len(bad), want), bad...)}
	}
	if unreadable > 0 {
		return []check.Result{check.IncompleteR(key, fmt.Sprintf("%d setting(s) could not be read; the readable ones are hardened", unreadable))}
	}
	return []check.Result{check.PassR(key, fmt.Sprintf("%s = %d; hardened on every interface once combined (%d checked)", key, all, checked))}
}
