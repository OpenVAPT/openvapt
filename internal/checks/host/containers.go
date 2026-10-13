package host

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

var (
	refDockerSec  = check.Ref{Title: "Docker documentation, Docker Engine security", URL: "https://docs.docker.com/engine/security/"}
	refDockerSock = check.Ref{Title: "Docker documentation, Protect the Docker daemon socket", URL: "https://docs.docker.com/engine/security/protect-access/"}
	refOWASPDock  = check.Ref{Title: "OWASP Docker Security Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"}
	refKubelet    = check.Ref{Title: "Kubernetes documentation, Kubelet authentication and authorization", URL: "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/"}
	refK8sSec     = check.Ref{Title: "Kubernetes documentation, Securing a cluster", URL: "https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/"}
	refNIST190    = check.Ref{Title: "NIST SP 800-190, Application Container Security Guide", URL: "https://csrc.nist.gov/pubs/sp/800/190/final"}
)

// dockerDaemon is the subset of /etc/docker/daemon.json these checks read.
type dockerDaemon struct {
	Hosts           []string `json:"hosts"`
	TLSVerify       bool     `json:"tlsverify"`
	NoNewPrivileges bool     `json:"no-new-privileges"`
	ICC             *bool    `json:"icc"`
	UsernsRemap     string   `json:"userns-remap"`
	LiveRestore     bool     `json:"live-restore"`
}

// hostConfig is the subset of a container's hostconfig.json these checks read.
type hostConfig struct {
	Privileged  bool     `json:"Privileged"`
	PidMode     string   `json:"PidMode"`
	NetworkMode string   `json:"NetworkMode"`
	IpcMode     string   `json:"IpcMode"`
	CapAdd      []string `json:"CapAdd"`
	Binds       []string `json:"Binds"`
}

// containerConfigs reads every container's hostconfig.json (needs root). The
// container id is shortened to 12 characters in evidence, like docker ps.
func containerConfigs(ctx context.Context, s sys.System) (map[string]hostConfig, bool) {
	paths, _ := s.Glob("/var/lib/docker/containers/*/hostconfig.json")
	out := map[string]hostConfig{}
	complete := true
	for _, p := range paths {
		r, err := s.ReadFile(ctx, p)
		if err != nil {
			complete = false
			continue
		}
		var hc hostConfig
		if json.Unmarshal(r.Data, &hc) != nil || !r.Complete {
			complete = false
			continue
		}
		id := filepath.Base(filepath.Dir(p))
		if len(id) > 12 {
			id = id[:12]
		}
		out[id] = hc
	}
	return out, complete
}

func init() {
	check.Register(&check.Check{
		ID: "HOST-CTR-001", Title: "Docker API Exposed Over TCP Without TLS", Domain: check.DomainHost,
		Severity: check.Critical, Category: check.CatNetwork, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Checks whether the Docker daemon is configured to listen on a TCP socket without TLS client verification.",
		Rationale: "The Docker API is equivalent to root on the host. Exposed over TCP without mutual TLS, anyone who can reach the port can start a privileged container and take over the machine; this is a common cause of cryptomining infections.",
		Detection: "Reads /etc/docker/daemon.json (hosts and tlsverify) and Docker systemd unit files and drop-ins for -H tcp:// flags.",
		Fix:       "Remove tcp:// listeners and use the local Unix socket or SSH (docker context with ssh://). If remote access is unavoidable, enable tlsverify with client certificates and restrict the port in the firewall.",
		Verify:    "ss -tlnp | grep -E ':(2375|2376)'  and  grep -r 'tcp://' /etc/docker /etc/systemd/system/docker.service.d",
		Refs:      []check.Ref{refDockerSock, refOWASPDock},
		Standards: check.Standards{CWE: []string{"CWE-306", "CWE-319"}, OWASP: []string{"A05:2021", "A07:2021"}, NIST: []string{"AC-3", "SC-8"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var tcp []string
			tlsOn := false
			found := false
			if t, _, ok := readText(ctx, s, "/etc/docker/daemon.json"); ok {
				found = true
				var d dockerDaemon
				if json.Unmarshal([]byte(t), &d) == nil {
					tlsOn = d.TLSVerify
					for _, h := range d.Hosts {
						if strings.HasPrefix(h, "tcp://") {
							tcp = append(tcp, "daemon.json hosts: "+h)
						}
					}
				}
			}
			units := []string{"/lib/systemd/system/docker.service", "/usr/lib/systemd/system/docker.service"}
			more, _ := s.Glob("/etc/systemd/system/docker.service.d/*.conf")
			units = append(units, more...)
			for _, u := range units {
				t, _, ok := readText(ctx, s, u)
				if !ok {
					continue
				}
				found = true
				for _, line := range strings.Split(t, "\n") {
					if strings.Contains(line, "tcp://") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
						tcp = append(tcp, u+": "+strings.TrimSpace(line))
						if strings.Contains(line, "--tlsverify") {
							tlsOn = true
						}
					}
				}
			}
			if !found {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			if len(tcp) > 0 && !tlsOn {
				return []check.Result{check.FailR("docker", "Docker API listens on TCP without TLS verification", tcp...)}
			}
			return []check.Result{check.PassR("docker", "Docker API is not exposed over unauthenticated TCP")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-002", Title: "Docker Daemon Not Hardened", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L",
		Summary:   "Checks the Docker daemon defaults: no-new-privileges, inter-container communication, user namespace remapping and live restore.",
		Rationale: "Hardened daemon defaults limit what a compromised container can do: no-new-privileges blocks setuid escalation, disabling icc isolates containers, and user namespaces map container root to an unprivileged host user.",
		Detection: "Reads /etc/docker/daemon.json and lists each hardening setting that is missing: no-new-privileges true, icc false, userns-remap set, live-restore true.",
		Fix:       "Add to /etc/docker/daemon.json:  \"no-new-privileges\": true, \"icc\": false, \"userns-remap\": \"default\", \"live-restore\": true  then restart Docker after testing your containers.",
		Verify:    "cat /etc/docker/daemon.json ; docker info | grep -Ei 'security|userns'",
		Refs:      []check.Ref{refDockerSec, refNIST190},
		Standards: check.Standards{CWE: []string{"CWE-250", "CWE-269"}, NIST: []string{"CM-6", "AC-6"}, CISTopic: "Docker daemon configuration"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			t, complete, ok := readText(ctx, s, "/etc/docker/daemon.json")
			if !ok {
				if _, err := s.Stat("/var/lib/docker"); err != nil {
					return []check.Result{check.SkipR("docker", "Docker is not installed")}
				}
				return []check.Result{check.FailR("/etc/docker/daemon.json", "No daemon.json: all hardening options are at their defaults")}
			}
			var d dockerDaemon
			if json.Unmarshal([]byte(t), &d) != nil || !complete {
				return []check.Result{check.IncompleteR("/etc/docker/daemon.json", "daemon.json could not be parsed")}
			}
			var miss []string
			if !d.NoNewPrivileges {
				miss = append(miss, "no-new-privileges is not true")
			}
			if d.ICC == nil || *d.ICC {
				miss = append(miss, "icc is not false")
			}
			if d.UsernsRemap == "" {
				miss = append(miss, "userns-remap is not set")
			}
			if !d.LiveRestore {
				miss = append(miss, "live-restore is not true")
			}
			if len(miss) > 0 {
				return []check.Result{check.FailR("/etc/docker/daemon.json", "Docker daemon hardening options are missing", miss...)}
			}
			return []check.Result{check.PassR("/etc/docker/daemon.json", "Docker daemon hardening options are set")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-003", Title: "Privileged or Host-Namespace Containers", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Looks for containers running privileged, sharing the host's PID, network or IPC namespace, or with dangerous added capabilities.",
		Rationale: "A privileged container, or one with CAP_SYS_ADMIN or host namespaces, has almost no isolation: a compromise of the application inside is a compromise of the host.",
		Detection: "Reads /var/lib/docker/containers/*/hostconfig.json (needs root) and reports Privileged true, PidMode/NetworkMode/IpcMode host, or CapAdd containing ALL, SYS_ADMIN, SYS_PTRACE, SYS_MODULE or NET_ADMIN.",
		Fix:       "Recreate each container without --privileged, --pid=host, --net=host and --ipc=host; drop all capabilities and add back only the specific ones needed (--cap-drop=ALL --cap-add=...).",
		Verify:    "docker inspect --format '{{.Name}} {{.HostConfig.Privileged}} {{.HostConfig.PidMode}} {{.HostConfig.NetworkMode}} {{.HostConfig.CapAdd}}' $(docker ps -aq)",
		Refs:      []check.Ref{refNIST190, refOWASPDock},
		Standards: check.Standards{CWE: []string{"CWE-250", "CWE-653"}, NIST: []string{"AC-6", "SC-39"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfgs, complete := containerConfigs(ctx, s)
			if len(cfgs) == 0 {
				if !complete {
					return []check.Result{check.IncompleteR("containers", "Container configuration could not be read (run as root)")}
				}
				return []check.Result{check.SkipR("containers", "No Docker containers found")}
			}
			danger := map[string]bool{"ALL": true, "SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "NET_ADMIN": true, "CAP_SYS_ADMIN": true}
			var bad []string
			for id, hc := range cfgs {
				var why []string
				if hc.Privileged {
					why = append(why, "privileged")
				}
				for name, mode := range map[string]string{"pid": hc.PidMode, "network": hc.NetworkMode, "ipc": hc.IpcMode} {
					if mode == "host" {
						why = append(why, name+"=host")
					}
				}
				for _, c := range hc.CapAdd {
					if danger[strings.ToUpper(c)] {
						why = append(why, "cap-add "+c)
					}
				}
				if len(why) > 0 {
					bad = append(bad, id+": "+strings.Join(why, ", "))
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("containers", "Containers with weak isolation", bad...)}
			}
			if !complete {
				return []check.Result{check.IncompleteR("containers", "Some container configurations could not be read")}
			}
			return []check.Result{check.PassR("containers", strconv.Itoa(len(cfgs))+" container(s) checked; none privileged or sharing host namespaces")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-004", Title: "Containers Mount the Docker Socket or Host Root", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Looks for containers that bind-mount the Docker socket, the host root filesystem or sensitive host paths.",
		Rationale: "A container with /var/run/docker.sock can control Docker and therefore the host. Mounting / or /etc gives direct write access to host configuration.",
		Detection: "Reads Binds from /var/lib/docker/containers/*/hostconfig.json (needs root) and reports mounts of /var/run/docker.sock, /run/docker.sock, /, /etc, /root, /proc or /sys from the host.",
		Fix:       "Remove these mounts. If a tool genuinely needs the Docker API, use a restricted socket proxy that allows only the required read-only calls.",
		Verify:    "docker inspect --format '{{.Name}} {{.HostConfig.Binds}}' $(docker ps -aq)",
		Refs:      []check.Ref{refDockerSock, refNIST190},
		Standards: check.Standards{CWE: []string{"CWE-250", "CWE-732"}, NIST: []string{"AC-6", "SC-39"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfgs, complete := containerConfigs(ctx, s)
			if len(cfgs) == 0 {
				if !complete {
					return []check.Result{check.IncompleteR("containers", "Container configuration could not be read (run as root)")}
				}
				return []check.Result{check.SkipR("containers", "No Docker containers found")}
			}
			sensitive := map[string]bool{"/var/run/docker.sock": true, "/run/docker.sock": true, "/": true, "/etc": true, "/root": true, "/proc": true, "/sys": true}
			var bad []string
			for id, hc := range cfgs {
				for _, b := range hc.Binds {
					src := strings.SplitN(b, ":", 2)[0]
					if sensitive[filepath.Clean(src)] {
						bad = append(bad, id+": "+b)
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("containers", "Containers mount the Docker socket or sensitive host paths", bad...)}
			}
			return []check.Result{check.PassR("containers", "No containers mount the Docker socket or host root")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-K8S-001", Title: "Kubelet Allows Anonymous or Unauthorised Access", Domain: check.DomainHost,
		Severity: check.Critical, Category: check.CatIdentity, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Checks the kubelet configuration for anonymous authentication, AlwaysAllow authorisation or the unauthenticated read-only port.",
		Rationale: "The kubelet API can run commands in every pod on the node. With anonymous access or AlwaysAllow, anyone who can reach port 10250 controls the node's workloads; the read-only port 10255 leaks pod and environment details.",
		Detection: "Reads /var/lib/kubelet/config.yaml and looks for authentication.anonymous.enabled: true, authorization.mode: AlwaysAllow, or a non-zero readOnlyPort.",
		Fix:       "Set authentication.anonymous.enabled: false, authorization.mode: Webhook and readOnlyPort: 0 in the kubelet configuration, then restart the kubelet.",
		Verify:    "grep -A2 -E 'anonymous|authorization|readOnlyPort' /var/lib/kubelet/config.yaml",
		Refs:      []check.Ref{refKubelet, refK8sSec},
		Standards: check.Standards{CWE: []string{"CWE-306", "CWE-862"}, OWASP: []string{"A01:2021", "A07:2021"}, NIST: []string{"AC-3", "IA-2"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			t, _, ok := readText(ctx, s, "/var/lib/kubelet/config.yaml")
			if !ok {
				return []check.Result{check.SkipR("kubelet", "No kubelet configuration found")}
			}
			var bad []string
			if regexp.MustCompile(`(?m)anonymous:\s*\n\s+enabled:\s*true`).MatchString(t) {
				bad = append(bad, "authentication.anonymous.enabled: true")
			}
			if regexp.MustCompile(`(?m)^\s*mode:\s*AlwaysAllow`).MatchString(t) {
				bad = append(bad, "authorization.mode: AlwaysAllow")
			}
			if m := regexp.MustCompile(`(?m)^\s*readOnlyPort:\s*(\d+)`).FindStringSubmatch(t); m != nil && m[1] != "0" {
				bad = append(bad, "readOnlyPort: "+m[1])
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/var/lib/kubelet/config.yaml", "Kubelet allows unauthenticated or unauthorised access", bad...)}
			}
			return []check.Result{check.PassR("/var/lib/kubelet/config.yaml", "Kubelet requires authentication and authorisation")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-K8S-002", Title: "Kubernetes Data Directory Accessible to Others", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
		Summary:   "Checks that the etcd data directory is accessible only by its owner.",
		Rationale: "etcd stores every Kubernetes object, including Secrets, usually unencrypted at rest. Read access to its data directory exposes all cluster credentials.",
		Detection: "Stats /var/lib/etcd and fails if group or others have any permission.",
		Fix:       "chmod 700 /var/lib/etcd && chown etcd:etcd /var/lib/etcd  (or root:root for kubeadm static pods). Enable encryption at rest for Secrets.",
		Verify:    "stat -c '%a %U:%G %n' /var/lib/etcd",
		Refs:      []check.Ref{{Title: "Kubernetes documentation, Operating etcd clusters for Kubernetes", URL: "https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/"}, refK8sSec},
		Standards: check.Standards{CWE: []string{"CWE-732"}, NIST: []string{"AC-3", "SC-28"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			st, err := s.Stat("/var/lib/etcd")
			if err != nil {
				return []check.Result{check.SkipR("/var/lib/etcd", "No etcd data directory found")}
			}
			if st.Mode.Perm()&0o077 != 0 {
				return []check.Result{check.FailR("/var/lib/etcd", "etcd data directory is accessible by group or others", "mode "+perm(st.Mode))}
			}
			return []check.Result{check.PassR("/var/lib/etcd", "etcd data directory is owner-only", "mode "+perm(st.Mode))}
		},
	})

	registerFileMode(fileModeRule{
		id: "HOST-K8S-003", title: "Kubernetes Credential Files Readable by Others", sev: check.High, cat: check.CatIdentity,
		cvss:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
		summary:   "Checks that kubeconfig files and Kubernetes PKI private keys are not readable by other users.",
		rationale: "admin.conf and the cluster CA key grant full control of the cluster; any local user who can read them becomes a cluster administrator.",
		fix:       "chmod 600 /etc/kubernetes/*.conf /etc/kubernetes/pki/*.key /etc/kubernetes/pki/etcd/*.key && chown root:root on each.",
		verify:    "stat -c '%a %n' /etc/kubernetes/*.conf /etc/kubernetes/pki/*.key",
		patterns:  []string{"/etc/kubernetes/admin.conf", "/etc/kubernetes/super-admin.conf", "/etc/kubernetes/kubelet.conf", "/etc/kubernetes/controller-manager.conf", "/etc/kubernetes/scheduler.conf", "/etc/kubernetes/pki/*.key", "/etc/kubernetes/pki/etcd/*.key"},
		bad:       0o044 | 0o022, why: "readable or writable by group or others", cwe: "CWE-732",
		refs: []check.Ref{refK8sSec},
	})
}
