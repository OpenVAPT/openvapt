package collect

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// Container describes whether the scan runs inside a container. Detection
// is read-only and uses files only: the /.dockerenv and /run/.containerenv
// marker files, container= in /proc/1/environ (only when readable), and
// container runtime patterns in /proc/1/cgroup and /proc/self/mountinfo.
type Container struct {
	Inside   bool   // true when a container was detected
	Type     string // docker, podman, kubernetes, lxc, containerd or the container= value
	Evidence string // which marker matched
}

// cgroupPatterns maps a substring of a cgroup or mountinfo line to the
// container runtime it indicates. Order matters: the first match wins.
var cgroupPatterns = []struct{ pat, typ string }{
	{"kubepods", "kubernetes"},
	{"/docker/", "docker"},
	{"/containers/", "container"},
	{"/docker-", "docker"},
	{"/libpod-", "podman"},
	{"/lxc/", "lxc"},
	{"/lxc.payload", "lxc"},
	{"containerd", "containerd"},
}

// DetectContainer reports whether s looks like the inside of a container.
func DetectContainer(ctx context.Context, s sys.System) Container {
	if _, err := s.Stat("/.dockerenv"); err == nil {
		return Container{Inside: true, Type: "docker", Evidence: "/.dockerenv exists"}
	}
	if _, err := s.Stat("/run/.containerenv"); err == nil {
		return Container{Inside: true, Type: "podman", Evidence: "/run/.containerenv exists"}
	}
	if r, err := s.ReadFile(ctx, "/proc/1/environ"); err == nil {
		for _, kv := range strings.Split(string(r.Data), "\x00") {
			if v, ok := strings.CutPrefix(kv, "container="); ok && v != "" {
				return Container{Inside: true, Type: sanitizeType(v), Evidence: "container= is set in the environment of process 1"}
			}
		}
	}
	if r, err := s.ReadFile(ctx, "/proc/1/cgroup"); err == nil {
		for _, line := range strings.Split(string(r.Data), "\n") {
			if t := matchRuntime(line); t != "" {
				return Container{Inside: true, Type: t, Evidence: "a container cgroup path in /proc/1/cgroup"}
			}
		}
	}
	// In mountinfo only the source (field 4) of the mounts a runtime bind
	// mounts into every container is considered. A host running containers
	// has many /var/lib/docker mount points, but its own /etc/hosts is
	// never bind mounted from a container directory.
	if r, err := s.ReadFile(ctx, "/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(r.Data), "\n") {
			f := strings.Fields(line)
			if len(f) < 5 {
				continue
			}
			switch f[4] {
			case "/etc/hosts", "/etc/hostname", "/etc/resolv.conf":
				if t := matchRuntime(f[3]); t != "" {
					return Container{Inside: true, Type: t, Evidence: f[4] + " is bind mounted from a container runtime directory (/proc/self/mountinfo)"}
				}
			}
		}
	}
	return Container{}
}

// matchRuntime returns the runtime a cgroup or mount source path indicates.
func matchRuntime(path string) string {
	for _, c := range cgroupPatterns {
		if strings.Contains(path, c.pat) {
			return c.typ
		}
	}
	return ""
}

// sanitizeType keeps a container= value short and printable.
func sanitizeType(v string) string {
	var b strings.Builder
	for _, r := range v {
		if b.Len() >= 32 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// hostOnly lists the checks whose setting belongs to the host, not to a
// container: the boot loader and Secure Boot, kernel modules, kernel
// parameters that are not namespaced, mount separation of host paths, time
// synchronisation, the host firewall and the audit daemon. Network kernel
// parameters (net.*) are namespaced and still apply inside a container.
var hostOnly = map[string]bool{
	"HOST-BOOT-001": true, "HOST-BOOT-002": true, "HOST-BOOT-003": true, "HOST-BOOT-004": true, "HOST-BOOT-005": true,
	"HOST-FS-006": true, "HOST-FS-008": true, "HOST-FS-010": true, "HOST-FS-011": true, "HOST-FS-012": true, "HOST-FS-013": true, "HOST-FS-018": true,
	"HOST-KRN-001": true, "HOST-KRN-002": true, "HOST-KRN-003": true, "HOST-KRN-004": true, "HOST-KRN-009": true, "HOST-KRN-010": true,
	"HOST-KRN-011": true, "HOST-KRN-012": true, "HOST-KRN-018": true, "HOST-KRN-019": true, "HOST-KRN-020": true, "HOST-KRN-021": true,
	"HOST-KRN-022": true, "HOST-KRN-027": true, "HOST-KRN-028": true, "HOST-KRN-029": true, "HOST-KRN-030": true, "HOST-KRN-031": true,
	"HOST-TIME-001": true, "NET-FW-001": true, "NET-FW-002": true,
	"HOST-AUD-001": true, "HOST-AUD-002": true, "HOST-AUD-003": true, "HOST-AUD-004": true, "HOST-AUD-005": true,
	"HOST-AUD-006": true, "HOST-AUD-007": true, "HOST-AUD-008": true, "HOST-AUD-009": true,
}

// HostOnly reports whether check id cannot apply inside a container.
func HostOnly(id string) bool { return hostOnly[id] }

// ContainerSkipMessage is the Skip evidence for a host-only check.
func ContainerSkipMessage(c Container) string {
	return "running inside a container (" + c.Type + "): this setting belongs to the host"
}
