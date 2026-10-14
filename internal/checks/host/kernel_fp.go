package host

import (
	"context"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Cautions appended to the Fix of kernel parameter rules whose hardened
// value can break a service or a network path, and pass-with-note hooks for
// hosts where the "weak" value is the correct operational choice.

var sysctlFixCaution = map[string]string{
	"HOST-KRN-025": ". Caution: on a host that gets its IPv6 address or default route from router advertisements (SLAAC, most cloud dual-stack VMs), accept_ra = 0 removes the IPv6 default route and cuts IPv6 connectivity. Use it only with static IPv6 addressing; otherwise keep accept_ra = 1 and rely on RA Guard on the switch or a host firewall rule for RA sources.",
	"HOST-KRN-027": ". Caution: kexec_load_disabled = 1 also stops kdump from loading its crash kernel (kdump.service on the RHEL family, kdump-tools on Debian and Ubuntu), so crash dumps are lost. Keep it 0 where kdump is used, or accept that trade-off deliberately. The setting cannot be turned back off without a reboot.",
	"HOST-KRN-028": ". Caution: unprivileged live migration tools (for example QEMU post-copy migration or CRIU run as a normal user) need userfaultfd; test those first.",
	"HOST-KRN-031": ". Caution: applications that use io_uring for fast I/O (some databases, proxies and runtimes) fall back or fail to start when it is disabled; test them first, or use 1 to allow only a chosen group.",
}

var sysctlDetectionNote = map[string]string{
	"HOST-KRN-025": " Passes with a note when IPv6 forwarding is off and /proc/net/ipv6_route shows a default route learned from a router advertisement (RTF_DEFAULT or RTF_ADDRCONF flag), because turning advertisements off would remove that route.",
	"HOST-KRN-027": " Passes with a note when the allow-listed systemctl is-enabled reports kdump or kdump-tools enabled, because kdump needs kexec to load its crash kernel.",
}

// sysctlPassNote returns a Pass message when a failing value is the right
// operational choice on this host.
var sysctlPassNote = map[string]func(ctx context.Context, s sys.System) (msg string, ev []string, pass bool){
	"HOST-KRN-027": kdumpInUse,
	"HOST-KRN-025": ipv6DefaultRouteFromRA,
}

func hasFail(rs []check.Result) bool {
	for _, r := range rs {
		if r.Status == check.Fail {
			return true
		}
	}
	return false
}

func failEvidence(rs []check.Result) []string {
	var out []string
	for _, r := range rs {
		if r.Status == check.Fail {
			out = append(out, r.Message)
			out = append(out, r.Evidence...)
		}
	}
	return out
}

// kdumpInUse passes HOST-KRN-027 when a kdump service is enabled, because
// disabling kexec would stop crash dumps.
func kdumpInUse(ctx context.Context, s sys.System) (string, []string, bool) {
	for _, unit := range []string{"kdump", "kdump-tools"} {
		out, err := s.Run(ctx, "systemctl", "is-enabled", unit)
		if err == nil && strings.TrimSpace(out) == "enabled" {
			return "kexec is allowed and " + unit + ".service is enabled: kdump needs kexec to load its crash kernel, so keeping kexec_load_disabled = 0 is the expected trade-off", []string{"systemctl is-enabled " + unit + ": enabled"}, true
		}
	}
	return "", nil, false
}

// ipv6DefaultRouteFromRA passes HOST-KRN-025 on a host that does not
// forward IPv6 and whose IPv6 default route was learned from a router
// advertisement: accept_ra = 0 would cut its IPv6 connectivity.
func ipv6DefaultRouteFromRA(ctx context.Context, s sys.System) (string, []string, bool) {
	fwd, err := collect.Sysctl(s, "net.ipv6.conf.all.forwarding")
	if err != nil || strings.TrimSpace(fwd) != "0" {
		return "", nil, false
	}
	rr, err := s.ReadFile(ctx, "/proc/net/ipv6_route")
	if err != nil {
		return "", nil, false
	}
	const rtfDefault, rtfAddrconf = 0x00010000, 0x00040000
	for _, line := range strings.Split(string(rr.Data), "\n") {
		f := strings.Fields(line)
		if len(f) != 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[9] == "lo" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&(rtfDefault|rtfAddrconf) == 0 {
			continue
		}
		return "Router advertisements are accepted, and this host (IPv6 forwarding off) learned its IPv6 default route on " + f[9] + " from one; accept_ra = 0 would remove that route, so the setting is expected here. Use RA Guard on the network to block rogue advertisements",
			[]string{"net.ipv6.conf.all.forwarding = 0", "/proc/net/ipv6_route: default route via " + f[9] + " flags " + f[8] + " (learned from a router advertisement)"}, true
	}
	return "", nil, false
}
