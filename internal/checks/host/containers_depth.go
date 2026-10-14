package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// Deeper Docker, containerd and Podman checks (HOST-CTR-005 and later). They
// read /etc/docker/daemon.json, each container's hostconfig.json and
// config.v2.json under /var/lib/docker (root only), the Docker socket's
// metadata, /etc/group and the containerd and Podman configuration files. No
// container command is run: docker, podman and ctr are not on the read-only
// allow-list, so everything here comes from files. CIS Docker Benchmark
// recommendations are referred to by number only and paraphrased.

var (
	refDockerLogging  = check.Ref{Title: "Docker documentation, Configure logging drivers", URL: "https://docs.docker.com/engine/logging/configure/"}
	refDockerdRef     = check.Ref{Title: "Docker documentation, dockerd daemon reference", URL: "https://docs.docker.com/reference/cli/dockerd/"}
	refDockerRootless = check.Ref{Title: "Docker documentation, Rootless mode", URL: "https://docs.docker.com/engine/security/rootless/"}
	refDockerSeccomp  = check.Ref{Title: "Docker documentation, Seccomp security profiles", URL: "https://docs.docker.com/engine/security/seccomp/"}
	refDockerLimits   = check.Ref{Title: "Docker documentation, Resource constraints", URL: "https://docs.docker.com/engine/containers/resource_constraints/"}
	refDockerTrust    = check.Ref{Title: "Docker documentation, Content trust in Docker", URL: "https://docs.docker.com/engine/security/trust/"}
	refContainerdOps  = check.Ref{Title: "containerd documentation, Operations (configuration)", URL: "https://github.com/containerd/containerd/blob/main/docs/ops.md"}
	refPodmanConf     = check.Ref{Title: "containers.conf(5), Podman configuration", URL: "https://github.com/containers/common/blob/main/docs/containers.conf.5.md"}
	refOWASPDockerCS  = check.Ref{Title: "OWASP Docker Security Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"}
	refCISDockerBench = check.Ref{Title: "CIS Docker Benchmark (referenced by recommendation number)", URL: "https://www.cisecurity.org/benchmark/docker"}
)

// dockerDaemonMore is the second subset of daemon.json these checks read.
type dockerDaemonMore struct {
	LogDriver      string                 `json:"log-driver"`
	LogOpts        map[string]string      `json:"log-opts"`
	UserlandProxy  *bool                  `json:"userland-proxy"`
	DefaultUlimits map[string]interface{} `json:"default-ulimits"`
	InsecureRegs   []string               `json:"insecure-registries"`
	Debug          bool                   `json:"debug"`
	Experimental   bool                   `json:"experimental"`
	SeccompProfile string                 `json:"seccomp-profile"`
	SelinuxEnabled bool                   `json:"selinux-enabled"`
}

// readDaemonMore returns the parsed daemon.json, whether Docker seems to be
// installed at all, and whether the file was readable and valid.
func readDaemonMore(ctx context.Context, s sys.System) (d dockerDaemonMore, installed, ok bool) {
	t, complete, found := readText(ctx, s, "/etc/docker/daemon.json")
	if !found {
		_, err := s.Stat("/var/lib/docker")
		return d, err == nil, false
	}
	if !complete || json.Unmarshal([]byte(t), &d) != nil {
		return d, true, false
	}
	return d, true, true
}

// hostConfigMore is the second subset of hostconfig.json these checks read.
type hostConfigMore struct {
	SecurityOpt    []string `json:"SecurityOpt"`
	ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
	Memory         int64    `json:"Memory"`
	PidsLimit      *int64   `json:"PidsLimit"`
	LogConfig      struct {
		Type   string            `json:"Type"`
		Config map[string]string `json:"Config"`
	} `json:"LogConfig"`
}

// containerUser is the subset of config.v2.json these checks read.
type containerUser struct {
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
}

type containerInfo struct {
	id   string
	host hostConfigMore
	user string
	// userKnown is false when config.v2.json could not be read.
	userKnown bool
}

// containersMore reads hostconfig.json and config.v2.json for every
// container (needs root). Container ids are shortened to 12 characters.
func containersMore(ctx context.Context, s sys.System) ([]containerInfo, bool) {
	paths, _ := s.Glob("/var/lib/docker/containers/*/hostconfig.json")
	sort.Strings(paths)
	var out []containerInfo
	complete := true
	for _, p := range paths {
		r, err := s.ReadFile(ctx, p)
		if err != nil {
			complete = false
			continue
		}
		var hc hostConfigMore
		if json.Unmarshal(r.Data, &hc) != nil || !r.Complete {
			complete = false
			continue
		}
		dir := filepath.Dir(p)
		id := filepath.Base(dir)
		if len(id) > 12 {
			id = id[:12]
		}
		ci := containerInfo{id: id, host: hc}
		if cr, err := s.ReadFile(ctx, dir+"/config.v2.json"); err == nil && cr.Complete {
			var cu containerUser
			if json.Unmarshal(cr.Data, &cu) == nil {
				ci.user = cu.Config.User
				ci.userKnown = true
			}
		}
		out = append(out, ci)
	}
	return out, complete
}

// containerCheck wraps the "no containers / unreadable" handling shared by
// the per-container checks.
func containerCheck(ctx context.Context, s sys.System, judge func(containerInfo) []string, failMsg, passMsg string) []check.Result {
	cs, complete := containersMore(ctx, s)
	if len(cs) == 0 {
		if !complete {
			return []check.Result{check.IncompleteR("containers", "Container configuration could not be read (run as root)")}
		}
		return []check.Result{check.SkipR("containers", "No Docker containers found")}
	}
	var bad []string
	for _, c := range cs {
		if why := judge(c); len(why) > 0 {
			bad = append(bad, c.id+": "+strings.Join(why, ", "))
		}
	}
	if len(bad) > 0 {
		return []check.Result{check.FailR("containers", failMsg, bad...)}
	}
	if !complete {
		return []check.Result{check.IncompleteR("containers", "Some container configurations could not be read")}
	}
	return []check.Result{check.PassR("containers", fmt.Sprintf("%d container(s) checked; %s", len(cs), passMsg))}
}

// groupMembers returns the members of a group from /etc/group, by name:
// the explicit member list plus any /etc/passwd account whose primary group
// is that group.
func groupMembers(ctx context.Context, s sys.System, group string) ([]string, bool) {
	gt, _, ok := readText(ctx, s, "/etc/group")
	if !ok {
		return nil, false
	}
	gid := ""
	set := map[string]bool{}
	for _, line := range strings.Split(gt, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && f[0] == group {
			gid = f[2]
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					set[m] = true
				}
			}
		}
	}
	if gid == "" {
		return nil, true
	}
	if pt, _, ok := readText(ctx, s, "/etc/passwd"); ok {
		for _, line := range strings.Split(pt, "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 4 && f[3] == gid && f[0] != "root" {
				set[f[0]] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, true
}

var tomlKV = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.+?)\s*$`)

// tomlValues returns a flat key to value map for a simple TOML file,
// prefixing keys with their [section]. Comments and quotes are stripped. It
// is a small scanner for flat configuration, not a full parser.
func tomlValues(text string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.Trim(t, "[]") + "."
			continue
		}
		if m := tomlKV.FindStringSubmatch(t); m != nil {
			v := m[2]
			if i := strings.Index(v, " #"); i >= 0 {
				v = v[:i]
			}
			out[section+m[1]] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return out
}

func init() {
	check.Register(&check.Check{
		ID: "HOST-CTR-005", Title: "Docker Container Logs Have No Size Limit", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
		Summary:   "Checks whether the Docker daemon's default log driver caps log file size and rotation.",
		Rationale: "With the default json-file driver and no max-size, a chatty or attacked container can fill the disk with its own logs and take the host and every other container down. Bounded, rotated logs also keep evidence manageable for investigations.",
		Detection: "Reads /etc/docker/daemon.json. Fails when log-driver is json-file or unset and log-opts lacks max-size, or when a container's LogConfig uses json-file without max-size. Drivers that ship logs elsewhere (journald, syslog, fluentd, awslogs) pass.",
		Fix:       "Add to /etc/docker/daemon.json:  \"log-driver\": \"json-file\", \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}  (or use journald) and restart Docker; recreate containers that set their own LogConfig.",
		Verify:    "docker info --format '{{.LoggingDriver}}' ; grep -A3 log-opts /etc/docker/daemon.json",
		Refs:      []check.Ref{refDockerLogging, refNIST190, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-779", "CWE-770"}, NIST: []string{"AU-4", "SC-5", "CM-6"}, CISTopic: "CIS Docker Benchmark 2.12 (centralised and bounded container logging)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			d, installed, ok := readDaemonMore(ctx, s)
			if !installed {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			if !ok {
				if _, err := s.Stat("/etc/docker/daemon.json"); err != nil {
					return []check.Result{check.FailR("/etc/docker/daemon.json", "No daemon.json: json-file logging with no size limit is the default")}
				}
				return []check.Result{check.IncompleteR("/etc/docker/daemon.json", "daemon.json could not be parsed")}
			}
			var bad []string
			drv := strings.ToLower(d.LogDriver)
			if (drv == "" || drv == "json-file" || drv == "local") && d.LogOpts["max-size"] == "" {
				bad = append(bad, "daemon log-driver "+orElse(drv, "json-file (default)")+" has no max-size")
			}
			cs, _ := containersMore(ctx, s)
			for _, c := range cs {
				lt := strings.ToLower(c.host.LogConfig.Type)
				if lt == "json-file" && c.host.LogConfig.Config["max-size"] == "" && d.LogOpts["max-size"] == "" {
					bad = append(bad, c.id+": json-file logging without max-size")
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("/etc/docker/daemon.json", "Container logs are unbounded", bad...)}
			}
			return []check.Result{check.PassR("/etc/docker/daemon.json", "Container logging is bounded or shipped to a log service", "log-driver "+orElse(drv, "json-file")+", max-size "+orElse(d.LogOpts["max-size"], "n/a"))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-006", Title: "Docker Userland Proxy Enabled", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",
		Summary:   "Checks whether the Docker daemon still uses the docker-proxy userland process for published ports.",
		Rationale: "The userland proxy is a root process per published port that exists only for an old loopback edge case. Hairpin NAT does the same job in the kernel with less code running as root and fewer processes to crash or exploit.",
		Detection: "Reads /etc/docker/daemon.json and fails unless userland-proxy is false.",
		Fix:       "Add  \"userland-proxy\": false  to /etc/docker/daemon.json and restart Docker; test that published ports still answer from the host itself.",
		Verify:    "ps -C docker-proxy  should list nothing after containers are recreated.",
		Refs:      []check.Ref{refDockerdRef, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-1188"}, NIST: []string{"CM-7", "CM-6"}, CISTopic: "CIS Docker Benchmark 2.14 (disable the userland proxy)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			d, installed, ok := readDaemonMore(ctx, s)
			if !installed {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			if !ok {
				if _, err := s.Stat("/etc/docker/daemon.json"); err != nil {
					return []check.Result{check.FailR("/etc/docker/daemon.json", "No daemon.json: the userland proxy is on by default")}
				}
				return []check.Result{check.IncompleteR("/etc/docker/daemon.json", "daemon.json could not be parsed")}
			}
			if d.UserlandProxy == nil || *d.UserlandProxy {
				return []check.Result{check.FailR("/etc/docker/daemon.json", "userland-proxy is not false")}
			}
			return []check.Result{check.PassR("/etc/docker/daemon.json", "userland-proxy is false")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-007", Title: "Docker Default Ulimits Not Set", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
		Summary:   "Checks whether the Docker daemon sets default ulimits (open files and processes) for containers.",
		Rationale: "Without default limits a container inherits the daemon's generous limits and can exhaust file descriptors or spawn processes until the host starves. Daemon-wide defaults protect every container that forgets to set its own.",
		Detection: "Reads /etc/docker/daemon.json and fails unless default-ulimits contains at least nofile and nproc.",
		Fix:       "Add to /etc/docker/daemon.json:  \"default-ulimits\": {\"nofile\": {\"Name\": \"nofile\", \"Hard\": 65536, \"Soft\": 32768}, \"nproc\": {\"Name\": \"nproc\", \"Hard\": 4096, \"Soft\": 2048}}  and restart Docker; tune the numbers to your workloads.",
		Verify:    "docker info | grep -A3 -i ulimit  or  docker run --rm alpine sh -c 'ulimit -n; ulimit -u'  (your own test container)",
		Refs:      []check.Ref{refDockerdRef, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-770"}, NIST: []string{"SC-6", "CM-6"}, CISTopic: "CIS Docker Benchmark 2.7 (default ulimit)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			d, installed, ok := readDaemonMore(ctx, s)
			if !installed {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			if !ok {
				if _, err := s.Stat("/etc/docker/daemon.json"); err != nil {
					return []check.Result{check.FailR("/etc/docker/daemon.json", "No daemon.json: no default ulimits are set")}
				}
				return []check.Result{check.IncompleteR("/etc/docker/daemon.json", "daemon.json could not be parsed")}
			}
			var miss []string
			for _, k := range []string{"nofile", "nproc"} {
				if _, ok := d.DefaultUlimits[k]; !ok {
					miss = append(miss, "default-ulimits has no "+k)
				}
			}
			if len(miss) > 0 {
				return []check.Result{check.FailR("/etc/docker/daemon.json", "Default ulimits are not set", miss...)}
			}
			return []check.Result{check.PassR("/etc/docker/daemon.json", "default-ulimits sets nofile and nproc")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-008", Title: "Docker Socket Accessible to Non-Administrators", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Checks the Docker socket's permissions and who belongs to the docker group.",
		Rationale: "Whoever can write to /var/run/docker.sock is root: one command starts a privileged container with the host's disk mounted. Members of the docker group have that power without sudo, logging or a password prompt, so the group should be empty or hold only administrators.",
		Detection: "Stats /var/run/docker.sock (or /run/docker.sock) and fails when others can read or write it, or when it is not owned by root. Reads /etc/group and /etc/passwd and lists every member of the docker group as evidence; a non-empty group fails.",
		Fix:       "chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock  (the daemon recreates it with these defaults). Remove users from the docker group (gpasswd -d <user> docker) and give administrators sudo docker, or move to rootless Docker.",
		Verify:    "stat -c '%a %U:%G %n' /var/run/docker.sock ; getent group docker",
		Refs:      []check.Ref{refDockerSock, refOWASPDockerCS, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-732", "CWE-250"}, NIST: []string{"AC-3", "AC-6", "CM-6"}, CISTopic: "CIS Docker Benchmark 1.2.2 and 3.15 (only trusted users control the daemon; socket ownership and permissions)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var sock sys.FileInfo
			found := false
			for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
				if st, err := s.Stat(p); err == nil {
					sock, found = st, true
					break
				}
			}
			if !found {
				if _, err := s.Stat("/var/lib/docker"); err != nil {
					return []check.Result{check.SkipR("docker", "Docker is not installed")}
				}
				return []check.Result{check.IncompleteR("/var/run/docker.sock", "Docker socket not found (daemon stopped or rootless)")}
			}
			var bad []string
			if sock.Mode.Perm()&0o006 != 0 {
				bad = append(bad, fmt.Sprintf("%s mode %s is accessible to all users", sock.Path, perm(sock.Mode)))
			}
			if sock.UID > 0 {
				bad = append(bad, fmt.Sprintf("%s is owned by uid %d, not root", sock.Path, sock.UID))
			}
			members, ok := groupMembers(ctx, s, "docker")
			if !ok {
				return []check.Result{check.IncompleteR(sock.Path, "/etc/group could not be read")}
			}
			if len(members) > 0 {
				bad = append(bad, "docker group members (root-equivalent): "+strings.Join(members, ", "))
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR(sock.Path, "Docker socket is reachable by non-administrators", bad...)}
			}
			return []check.Result{check.PassR(sock.Path, "Docker socket is root-owned, mode "+perm(sock.Mode)+", and the docker group is empty")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-009", Title: "Docker Not Running in Rootless Mode", Domain: check.DomainHost,
		Severity: check.Info, Category: check.CatConfig, Effort: check.EffortHigh,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
		Summary:   "Reports whether the Docker daemon runs as root or in rootless mode. Informational.",
		Rationale: "In rootless mode the daemon and every container run inside a user namespace as an ordinary account, so a container breakout lands in that account rather than in root. It is not possible for every workload (some networking and storage features differ), so this is information for a design decision, not a failure.",
		Detection: "Looks for a rootless indicator: a per-user socket at /run/user/*/docker.sock, a per-user daemon configuration at /home/*/.config/docker/daemon.json, or a user systemd unit for docker. Reports root mode when only the system daemon is present.",
		Fix:       "Where the workloads allow it, install rootless Docker (dockerd-rootless-setuptool.sh install) for the service account and disable the system daemon; otherwise keep userns-remap (HOST-CTR-002) as the fallback.",
		Verify:    "docker info --format '{{.SecurityOptions}}'  lists name=rootless.",
		Refs:      []check.Ref{refDockerRootless, refNIST190},
		Standards: check.Standards{CWE: []string{"CWE-250"}, NIST: []string{"AC-6", "SC-39"}, CISTopic: "CIS Docker Benchmark 2.18 (run the daemon in rootless mode)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			_, installed, _ := readDaemonMore(ctx, s)
			var hints []string
			for _, pat := range []string{"/run/user/*/docker.sock", "/home/*/.config/docker/daemon.json", "/home/*/.config/systemd/user/docker.service", "/root/.config/docker/daemon.json"} {
				m, _ := s.Glob(pat)
				hints = append(hints, m...)
			}
			for _, p := range []string{"/run/user/1000/docker.sock", "/usr/bin/dockerd-rootless.sh"} {
				if _, err := s.Stat(p); err == nil {
					hints = append(hints, p)
				}
			}
			sort.Strings(hints)
			if len(hints) > 0 {
				return []check.Result{check.PassR("docker", "A rootless Docker installation is present", hints...)}
			}
			if !installed {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			return []check.Result{check.FailR("docker", "Docker runs as the root daemon only; rootless mode is not in use")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-010", Title: "Docker Daemon Allows Insecure Registries or Debug Features", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
		Summary:   "Checks daemon.json for insecure-registries, debug mode and experimental features.",
		Rationale: "An insecure registry is pulled over plain HTTP or with an unverified certificate, so anyone on the path can swap the image for a malicious one. Debug logging and experimental features widen the daemon's attack surface and leak internal detail into logs.",
		Detection: "Reads /etc/docker/daemon.json and the ExecStart lines of docker.service and its drop-ins (docker.service.d/*.conf under /etc/systemd/system, /run/systemd/system, /usr/lib/systemd/system and /lib/systemd/system). Fails when insecure-registries is non-empty, debug or experimental is true, or the dockerd command line carries --insecure-registry, --debug (-D) or --experimental. Incomplete when daemon.json exists but cannot be read or parsed, or a unit file cannot be read.",
		Fix:       "Remove insecure-registries (serve the registry over TLS with a trusted certificate, or add its CA to /etc/docker/certs.d/<registry>/ca.crt), set \"debug\": false and \"experimental\": false in daemon.json, and remove any --insecure-registry, --debug (-D) or --experimental flag from the dockerd ExecStart in docker.service drop-ins (then systemctl daemon-reload). Restart Docker in a maintenance window: running containers stop unless live-restore is on.",
		Verify:    "docker info | grep -Ei 'insecure|debug|experimental'",
		Refs:      []check.Ref{refDockerdRef, refNIST190, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-494", "CWE-1188"}, NIST: []string{"SI-7", "CM-7"}, CISTopic: "CIS Docker Benchmark 2.4 and 2.10 (no insecure registries; no experimental features)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			d, installed, ok := readDaemonMore(ctx, s)
			if !installed {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			bad, unitIncomplete := dockerdUnitFlags(ctx, s)
			jsonNote := ""
			if ok {
				for _, r := range d.InsecureRegs {
					bad = append(bad, "daemon.json insecure-registries: "+r)
				}
				if d.Debug {
					bad = append(bad, "daemon.json debug is true")
				}
				if d.Experimental {
					bad = append(bad, "daemon.json experimental is true")
				}
			} else if _, err := s.Stat("/etc/docker/daemon.json"); errors.Is(err, fs.ErrNotExist) {
				jsonNote = "none"
			} else {
				jsonNote = "daemon.json exists but could not be read or parsed"
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("docker daemon", "Docker daemon allows insecure registries or debug features", bad...)}
			}
			if jsonNote != "" && jsonNote != "none" {
				return []check.Result{check.IncompleteR("/etc/docker/daemon.json", "The daemon settings could not be confirmed: "+jsonNote)}
			}
			if len(unitIncomplete) > 0 {
				return []check.Result{check.IncompleteR("docker.service", "A docker.service unit or drop-in could not be read, so dockerd command-line flags could not be confirmed", unitIncomplete...)}
			}
			msg := "No insecure registries, debug or experimental settings in daemon.json or on the dockerd command line"
			if jsonNote == "none" {
				msg = "No daemon.json, and no insecure registries, debug or experimental flags on the dockerd command line"
			}
			return []check.Result{check.PassR("docker daemon", msg)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-011", Title: "Seccomp or AppArmor Disabled for Containers", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Looks for the daemon or individual containers turning off the default seccomp profile, AppArmor or SELinux labelling.",
		Rationale: "Docker's default seccomp profile blocks around 40 dangerous system calls and AppArmor or SELinux confines what a container's root can touch on the host. Running unconfined removes the main barriers between a compromised container and the kernel.",
		Detection: "Reads /etc/docker/daemon.json (seccomp-profile unconfined) and each container's hostconfig.json SecurityOpt (needs root) for seccomp=unconfined, seccomp:unconfined, apparmor=unconfined or label=disable.",
		Fix:       "Remove --security-opt seccomp=unconfined and apparmor=unconfined from the container definitions and recreate them; if an application needs one extra system call, write a custom seccomp profile that adds only that call. Delete seccomp-profile from daemon.json.",
		Verify:    "docker inspect --format '{{.Name}} {{.HostConfig.SecurityOpt}}' $(docker ps -aq)",
		Refs:      []check.Ref{refDockerSeccomp, {Title: "Docker documentation, AppArmor security profiles", URL: "https://docs.docker.com/engine/security/apparmor/"}, refNIST190},
		Standards: check.Standards{CWE: []string{"CWE-653", "CWE-250"}, NIST: []string{"AC-6", "SC-39", "CM-7"}, CISTopic: "CIS Docker Benchmark 5.1 and 5.22 (AppArmor profile; seccomp not unconfined)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			d, installed, _ := readDaemonMore(ctx, s)
			if !installed {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			var daemonBad []string
			if strings.EqualFold(strings.TrimSpace(d.SeccompProfile), "unconfined") {
				daemonBad = append(daemonBad, "daemon.json seccomp-profile is unconfined")
			}
			unconfined := regexp.MustCompile(`(?i)^(seccomp[=:]unconfined|apparmor[=:]unconfined|label[=:]disable|label[=:]type:spc_t)$`)
			res := containerCheck(ctx, s, func(c containerInfo) []string {
				var why []string
				for _, o := range c.host.SecurityOpt {
					if unconfined.MatchString(strings.TrimSpace(o)) {
						why = append(why, o)
					}
				}
				return why
			}, "Containers run without seccomp, AppArmor or SELinux confinement", "all keep the default confinement")
			if len(daemonBad) > 0 {
				if res[0].Status == check.Fail {
					res[0].Evidence = append(daemonBad, res[0].Evidence...)
					return res
				}
				return []check.Result{check.FailR("/etc/docker/daemon.json", "Docker daemon disables the default seccomp profile", daemonBad...)}
			}
			return res
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-012", Title: "Containers Run Without Memory or Process Limits", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
		Summary:   "Looks for containers with no memory limit and no PID limit.",
		Rationale: "A container with no limits can use all the host's memory or fork until the kernel runs out of process slots, taking the host and every neighbour down (a fork bomb or a memory leak is enough). Limits turn that into a problem for one container.",
		Detection: "Reads Memory and PidsLimit from each container's hostconfig.json (needs root) and fails when both are zero or unset.",
		Fix:       "Recreate each container with --memory (for example 512m) and --pids-limit (for example 256), or set them in the compose file under deploy.resources.limits / pids_limit.",
		Verify:    "docker inspect --format '{{.Name}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}}' $(docker ps -aq)",
		Refs:      []check.Ref{refDockerLimits, refNIST190, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-770"}, NIST: []string{"SC-6", "SC-5"}, CISTopic: "CIS Docker Benchmark 5.11 and 5.29 (memory limit; PIDs cgroup limit)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return containerCheck(ctx, s, func(c containerInfo) []string {
				var why []string
				if c.host.Memory <= 0 {
					why = append(why, "no memory limit")
				}
				if c.host.PidsLimit == nil || *c.host.PidsLimit <= 0 {
					why = append(why, "no PID limit")
				}
				if len(why) == 2 {
					return why
				}
				return nil
			}, "Containers have neither a memory nor a PID limit", "each has a memory or PID limit")
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-013", Title: "Containers Run as Root With a Writable Root Filesystem", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Looks for containers whose process runs as root and whose root filesystem is writable.",
		Rationale: "Root inside the container is the first half of most container escapes, and a writable root filesystem lets an attacker install tools and persist. A non-root user plus --read-only with a few tmpfs mounts removes both at once for most services.",
		Detection: "Reads Config.User from config.v2.json and ReadonlyRootfs from hostconfig.json (needs root) and fails when the user is empty, root or 0 and the root filesystem is writable.",
		Fix:       "Add USER <uid> to the image or run with --user 1000:1000, and start the container with --read-only plus --tmpfs /tmp for scratch space; recreate the container.",
		Verify:    "docker inspect --format '{{.Name}} user={{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}}' $(docker ps -aq)",
		Refs:      []check.Ref{refOWASPDockerCS, refNIST190, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-250", "CWE-732"}, NIST: []string{"AC-6", "CM-7"}, CISTopic: "CIS Docker Benchmark 4.1 and 5.13 (non-root user; read-only root filesystem)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return containerCheck(ctx, s, func(c containerInfo) []string {
				if !c.userKnown {
					return nil
				}
				u := strings.TrimSpace(strings.SplitN(c.user, ":", 2)[0])
				if (u == "" || u == "root" || u == "0") && !c.host.ReadonlyRootfs {
					return []string{"runs as root with a writable root filesystem"}
				}
				return nil
			}, "Containers run as root on a writable root filesystem", "none run as root on a writable root filesystem")
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-014", Title: "containerd Remote API or Podman Unconfined Defaults", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks the containerd and Podman configuration files for a TCP API without TLS and for unconfined seccomp or disabled labelling defaults.",
		Rationale: "containerd's gRPC API is root on the host, like the Docker API; a tcp_address without TLS exposes it to the network. Podman's containers.conf sets the defaults every container inherits: an unconfined seccomp profile or disabled SELinux labelling removes the isolation for all of them.",
		Detection: "Reads /etc/containerd/config.toml ([grpc] tcp_address set without tcp_tls_cert) and /etc/containers/containers.conf plus /usr/share/containers/containers.conf (seccomp_profile unconfined, label false, or apparmor_profile unconfined in [containers]).",
		Fix:       "containerd: remove tcp_address or set tcp_tls_cert and tcp_tls_key, then restart containerd. Podman: delete seccomp_profile = \"unconfined\", set label = true and apparmor_profile = \"container-default\" in containers.conf.",
		Verify:    "grep -E 'tcp_address|tcp_tls' /etc/containerd/config.toml ; grep -E 'seccomp_profile|^label|apparmor_profile' /etc/containers/containers.conf",
		Refs:      []check.Ref{refContainerdOps, refPodmanConf, refNIST190},
		Standards: check.Standards{CWE: []string{"CWE-306", "CWE-1188"}, NIST: []string{"AC-3", "SC-8", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var out []check.Result
			if t, _, ok := readText(ctx, s, "/etc/containerd/config.toml"); ok {
				v := tomlValues(t)
				addr := v["grpc.tcp_address"]
				if addr != "" && v["grpc.tcp_tls_cert"] == "" {
					out = append(out, check.FailR("/etc/containerd/config.toml", "containerd listens on TCP without TLS", "grpc tcp_address = "+addr))
				} else {
					out = append(out, check.PassR("/etc/containerd/config.toml", "containerd has no unauthenticated TCP API"))
				}
			}
			for _, p := range []string{"/etc/containers/containers.conf", "/usr/share/containers/containers.conf"} {
				t, _, ok := readText(ctx, s, p)
				if !ok {
					continue
				}
				v := tomlValues(t)
				var bad []string
				if strings.EqualFold(v["containers.seccomp_profile"], "unconfined") {
					bad = append(bad, "seccomp_profile = unconfined")
				}
				if strings.EqualFold(v["containers.label"], "false") {
					bad = append(bad, "label = false")
				}
				if strings.EqualFold(v["containers.apparmor_profile"], "unconfined") {
					bad = append(bad, "apparmor_profile = unconfined")
				}
				if len(bad) > 0 {
					out = append(out, check.FailR(p, "Podman defaults disable container confinement", bad...))
				} else {
					out = append(out, check.PassR(p, "Podman defaults keep seccomp, AppArmor and labelling on"))
				}
				break
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("containerd/podman", "No containerd or Podman configuration found")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "HOST-CTR-015", Title: "Docker Content Trust Not Enabled", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
		Summary:   "Checks whether DOCKER_CONTENT_TRUST=1 is set system-wide so that only signed images are pulled.",
		Rationale: "Without content trust, docker pull accepts whatever the registry or a tampering proxy returns for a tag. Signature verification makes a substituted image fail to pull instead of running as root on your host.",
		Detection: "Reads /etc/environment, /etc/profile, /etc/profile.d/*.sh and the Docker service drop-ins for DOCKER_CONTENT_TRUST=1. Fails when Docker is installed and the variable is not set anywhere system-wide.",
		Fix:       "Add  DOCKER_CONTENT_TRUST=1  to /etc/environment (or a file in /etc/profile.d) and sign your own images with docker trust sign; images without signatures then need an explicit --disable-content-trust for a deliberate exception.",
		Verify:    "grep -r DOCKER_CONTENT_TRUST /etc/environment /etc/profile.d",
		Refs:      []check.Ref{refDockerTrust, refCISDockerBench},
		Standards: check.Standards{CWE: []string{"CWE-494", "CWE-347"}, NIST: []string{"SI-7", "CM-14"}, CISTopic: "CIS Docker Benchmark 4.5 (enable content trust)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			_, installed, _ := readDaemonMore(ctx, s)
			if !installed {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			files := []string{"/etc/environment", "/etc/profile"}
			for _, pat := range []string{"/etc/profile.d/*.sh", "/etc/systemd/system/docker.service.d/*.conf"} {
				m, _ := s.Glob(pat)
				files = append(files, m...)
			}
			re := regexp.MustCompile(`(?m)^\s*(export\s+)?(Environment=)?"?DOCKER_CONTENT_TRUST"?=\"?1\"?`)
			for _, p := range files {
				if t, _, ok := readText(ctx, s, p); ok && re.MatchString(t) {
					return []check.Result{check.PassR(p, "DOCKER_CONTENT_TRUST=1 is set system-wide")}
				}
			}
			return []check.Result{check.FailR("/etc/environment", "DOCKER_CONTENT_TRUST is not set system-wide; unsigned images are accepted")}
		},
	})
}

func orElse(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// dockerdUnitFlags reads the effective dockerd ExecStart from docker.service
// and its drop-ins and returns the insecure flags it carries, plus the unit
// files that exist but could not be read. An empty ExecStart= resets the
// list, as systemd does.
func dockerdUnitFlags(ctx context.Context, s sys.System) (bad, unreadable []string) {
	dirs := []string{"/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system", "/etc/systemd/system"}
	var paths []string
	for _, d := range dirs {
		if _, err := s.Stat(d + "/docker.service"); err == nil {
			paths = append(paths, d+"/docker.service")
		}
	}
	for _, d := range dirs {
		g, _ := s.Glob(d + "/docker.service.d/*.conf")
		sort.Strings(g)
		paths = append(paths, g...)
	}
	type line struct{ src, cmd string }
	var exec []line
	for _, p := range paths {
		text, st := readState(ctx, s, p)
		if st != fileRead {
			if st != fileMissing {
				unreadable = append(unreadable, p)
			}
			continue
		}
		for _, l := range strings.Split(text, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
			if !ok || strings.TrimSpace(k) != "ExecStart" {
				continue
			}
			if v = strings.TrimSpace(v); v == "" {
				exec = nil
				continue
			}
			exec = append(exec, line{p, v})
		}
	}
	for _, e := range exec {
		f := strings.Fields(e.cmd)
		for i, a := range f {
			switch {
			case a == "--insecure-registry" && i+1 < len(f):
				bad = append(bad, e.src+": --insecure-registry "+f[i+1])
			case strings.HasPrefix(a, "--insecure-registry="), a == "-D", a == "--debug", a == "--debug=true", a == "--experimental", a == "--experimental=true":
				bad = append(bad, e.src+": "+a)
			}
		}
	}
	return bad, unreadable
}
