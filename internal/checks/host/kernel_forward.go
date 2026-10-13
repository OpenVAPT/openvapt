package host

import (
	"context"
	"regexp"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// containerMarkers are read-only signs that a container runtime or a
// Kubernetes node runs on this machine. Such hosts need IP forwarding so
// container traffic can leave the bridge network.
var containerMarkers = []string{
	"/var/run/docker.sock", "/run/docker.sock",
	"/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
	"/run/crio/crio.sock", "/var/run/crio/crio.sock",
	"/etc/kubernetes",
	"/sys/class/net/docker0", "/sys/class/net/cni0", "/sys/class/net/cbr0",
	"/sys/class/net/flannel.1", "/sys/class/net/cilium_host", "/sys/class/net/podman0",
}

// containerRuntime returns the first container runtime marker present, or "".
func containerRuntime(s sys.System) string {
	for _, p := range containerMarkers {
		if _, err := s.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

var nftForwardPolicy = regexp.MustCompile(`hook\s+forward[^;]*;[^}]*?policy\s+(accept|drop)`)

// forwardFiltered reads the FORWARD policy read-only. It returns
// (filtered, known, evidence): filtered is true when the forward path drops
// by default or Docker's DOCKER-USER chain filters it.
func forwardFiltered(ctx context.Context, s sys.System) (bool, bool, string) {
	if out, err := s.Run(ctx, "iptables", "-S"); err == nil && strings.Contains(out, "-P FORWARD") {
		lastDockerUser := ""
		policy := ""
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-P FORWARD ") {
				policy = strings.TrimSpace(strings.TrimPrefix(line, "-P FORWARD "))
			}
			if strings.HasPrefix(line, "-A DOCKER-USER ") {
				lastDockerUser = line
			}
		}
		if policy == "DROP" || policy == "REJECT" {
			return true, true, "iptables FORWARD policy " + policy
		}
		// DOCKER-USER filters the forward path only when it ends in an
		// unconditional deny; a DROP that matches one source still lets all
		// other forwarded traffic through.
		if dockerUserDefaultDeny(lastDockerUser) {
			return true, true, "iptables DOCKER-USER chain drops or rejects forwarded traffic"
		}
		return false, true, "iptables FORWARD policy " + policy
	}
	if out, err := s.Run(ctx, "nft", "list", "ruleset"); err == nil && strings.Contains(out, "hook forward") {
		if m := nftForwardPolicy.FindStringSubmatch(out); m != nil {
			return m[1] == "drop", true, "nftables forward chain policy " + m[1]
		}
	}
	return false, false, ""
}

// dockerUserDefaultDeny reports whether the last DOCKER-USER rule denies
// everything, or everything arriving on one interface (the documented way to
// block outside access to containers): "-j DROP" or "-j REJECT" with at most
// an "-i <iface>" match (REJECT may carry --reject-with). A rule matching a
// source, destination, protocol or module is too narrow to count.
func dockerUserDefaultDeny(rule string) bool {
	f := strings.Fields(rule)
	if len(f) >= 4 && f[0] == "-A" && f[1] == "DOCKER-USER" && f[2] == "-i" && !strings.HasPrefix(f[3], "!") {
		f = append([]string{"-A", "DOCKER-USER"}, f[4:]...)
	}
	if len(f) < 4 || f[0] != "-A" || f[1] != "DOCKER-USER" || f[2] != "-j" {
		return false
	}
	switch {
	case f[3] == "DROP" && len(f) == 4:
		return true
	case f[3] == "REJECT" && (len(f) == 4 || (len(f) == 6 && f[4] == "--reject-with")):
		return true
	}
	return false
}

// runIPForward evaluates HOST-KRN-005 with container context: a container or
// Kubernetes host needs forwarding, so it passes with context when the
// forward path is filtered, fails when forwarded traffic is accepted by
// default, and is incomplete when the policy cannot be read.
func runIPForward(ctx context.Context, s sys.System, key, v string) check.Result {
	rt := containerRuntime(s)
	if rt == "" {
		return check.FailR(key, key+" = "+v+" (hardened value: 0)")
	}
	ctxNote := "container runtime detected (" + rt + "); forwarding is required by the runtime"
	filtered, known, ev := forwardFiltered(ctx, s)
	switch {
	case !known:
		return check.IncompleteR(key, key+" = "+v+"; "+ctxNote+", but the FORWARD policy could not be read. Confirm forwarded traffic is filtered (FORWARD policy DROP or DOCKER-USER rules; see NET-FW-005)", ctxNote)
	case filtered:
		return check.PassR(key, key+" = "+v+" is expected on this container host and the forward path is filtered (see NET-FW-005 for published ports)", ctxNote, ev)
	}
	return check.FailR(key, key+" = "+v+"; "+ctxNote+", but forwarded traffic is accepted by default. Set the FORWARD policy to DROP or add DOCKER-USER rules (see NET-FW-005)", ctxNote, ev)
}
