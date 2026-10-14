package host

import (
	"io/fs"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

const testCtr = "/var/lib/docker/containers/abcdef123456789/"

// dockerFake returns a fake with Docker installed, daemon.json set to the
// given text and one container with the given hostconfig and config.v2.
func dockerFake(daemon, hostcfg, cfgv2 string) *sys.Fake {
	f := &sys.Fake{Files: map[string]string{}, Infos: map[string]sys.FileInfo{
		"/var/lib/docker": {Path: "/var/lib/docker", Mode: fs.ModeDir | 0o710, IsDir: true},
	}}
	if daemon != "" {
		f.Files["/etc/docker/daemon.json"] = daemon
	}
	if hostcfg != "" {
		f.Files[testCtr+"hostconfig.json"] = hostcfg
	}
	if cfgv2 != "" {
		f.Files[testCtr+"config.v2.json"] = cfgv2
	}
	return f
}

func TestDockerDaemonDepthTable(t *testing.T) {
	for _, tc := range []struct {
		id, daemon string
		want       check.Status
	}{
		// HOST-CTR-005 logging
		{"HOST-CTR-005", "", check.Fail},
		{"HOST-CTR-005", `{"log-driver": "json-file"}`, check.Fail},
		{"HOST-CTR-005", `{"log-driver": "json-file", "log-opts": {"max-size": "10m"}}`, check.Pass},
		{"HOST-CTR-005", `{"log-driver": "journald"}`, check.Pass},
		{"HOST-CTR-005", `{not json`, check.Incomplete},
		// HOST-CTR-006 userland proxy
		{"HOST-CTR-006", "", check.Fail},
		{"HOST-CTR-006", `{"userland-proxy": true}`, check.Fail},
		{"HOST-CTR-006", `{"userland-proxy": false}`, check.Pass},
		// HOST-CTR-007 ulimits
		{"HOST-CTR-007", `{}`, check.Fail},
		{"HOST-CTR-007", `{"default-ulimits": {"nofile": {"Name": "nofile", "Hard": 1, "Soft": 1}}}`, check.Fail},
		{"HOST-CTR-007", `{"default-ulimits": {"nofile": {}, "nproc": {}}}`, check.Pass},
		// HOST-CTR-010 insecure registries, debug, experimental
		{"HOST-CTR-010", "", check.Pass},
		{"HOST-CTR-010", `{"insecure-registries": ["r.example.test:5000"]}`, check.Fail},
		{"HOST-CTR-010", `{"debug": true}`, check.Fail},
		{"HOST-CTR-010", `{"experimental": true}`, check.Fail},
		{"HOST-CTR-010", `{"debug": false, "insecure-registries": []}`, check.Pass},
		// HOST-CTR-015 content trust: nothing set system-wide
		{"HOST-CTR-015", `{}`, check.Fail},
	} {
		got := run(t, tc.id, dockerFake(tc.daemon, "", ""))
		if got.Status != tc.want {
			t.Errorf("%s with daemon.json %q: got %s (%s %v), want %s", tc.id, tc.daemon, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// Without Docker at all every daemon check skips.
	for _, id := range []string{"HOST-CTR-005", "HOST-CTR-006", "HOST-CTR-007", "HOST-CTR-010", "HOST-CTR-011", "HOST-CTR-015"} {
		if got := run(t, id, &sys.Fake{Files: map[string]string{}}); got.Status != check.Skip {
			t.Errorf("%s without Docker: got %s, want skip", id, got.Status)
		}
	}
}

func TestDockerContentTrustSources(t *testing.T) {
	for _, tc := range []struct {
		path, text string
		want       check.Status
	}{
		{"/etc/environment", "DOCKER_CONTENT_TRUST=1\n", check.Pass},
		{"/etc/profile.d/docker.sh", "export DOCKER_CONTENT_TRUST=1\n", check.Pass},
		{"/etc/systemd/system/docker.service.d/trust.conf", "[Service]\nEnvironment=DOCKER_CONTENT_TRUST=1\n", check.Pass},
		{"/etc/environment", "DOCKER_CONTENT_TRUST=0\n", check.Fail},
		{"/etc/environment", "# DOCKER_CONTENT_TRUST=1\n", check.Fail},
	} {
		f := dockerFake(`{}`, "", "")
		f.Files[tc.path] = tc.text
		if got := run(t, "HOST-CTR-015", f); got.Status != tc.want {
			t.Errorf("%s=%q: got %s, want %s", tc.path, tc.text, got.Status, tc.want)
		}
	}
}

func TestDockerSocketAndGroup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  fs.FileMode
		uid   int
		group string
		want  check.Status
	}{
		{"default 660 root:docker, empty group", fs.ModeSocket | 0o660, 0, "docker:x:999:\n", check.Pass},
		{"world writable", fs.ModeSocket | 0o666, 0, "docker:x:999:\n", check.Fail},
		{"world readable", fs.ModeSocket | 0o664, 0, "docker:x:999:\n", check.Fail},
		{"not root owned", fs.ModeSocket | 0o660, 1000, "docker:x:999:\n", check.Fail},
		{"member in group", fs.ModeSocket | 0o660, 0, "docker:x:999:deploy\n", check.Fail},
		{"primary group member", fs.ModeSocket | 0o660, 0, "docker:x:999:\n", check.Fail},
		{"no docker group", fs.ModeSocket | 0o660, 0, "root:x:0:\n", check.Pass},
	} {
		f := dockerFake(`{}`, "", "")
		f.Infos["/var/run/docker.sock"] = sys.FileInfo{Path: "/var/run/docker.sock", Mode: tc.mode, UID: tc.uid}
		f.Files["/etc/group"] = "root:x:0:\n" + tc.group
		f.Files["/etc/passwd"] = "root:x:0:0::/root:/bin/sh\n"
		if tc.name == "primary group member" {
			f.Files["/etc/passwd"] += "ci:x:1001:999::/home/ci:/bin/sh\n"
		}
		if got := run(t, "HOST-CTR-008", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// No socket but Docker installed: incomplete, never pass.
	f := dockerFake(`{}`, "", "")
	if got := run(t, "HOST-CTR-008", f); got.Status != check.Incomplete {
		t.Errorf("missing socket: got %s, want incomplete", got.Status)
	}
	// No /etc/group: incomplete.
	f = dockerFake(`{}`, "", "")
	f.Infos["/var/run/docker.sock"] = sys.FileInfo{Path: "/var/run/docker.sock", Mode: fs.ModeSocket | 0o660}
	if got := run(t, "HOST-CTR-008", f); got.Status != check.Incomplete {
		t.Errorf("missing /etc/group: got %s, want incomplete", got.Status)
	}
}

func TestDockerRootlessIndicator(t *testing.T) {
	f := dockerFake(`{}`, "", "")
	if got := run(t, "HOST-CTR-009", f); got.Status != check.Fail {
		t.Errorf("root daemon only: got %s, want fail", got.Status)
	}
	f.Files["/home/ops/.config/docker/daemon.json"] = "{}"
	if got := run(t, "HOST-CTR-009", f); got.Status != check.Pass {
		t.Errorf("rootless hint: got %s, want pass", got.Status)
	}
	if got := run(t, "HOST-CTR-009", &sys.Fake{Files: map[string]string{}}); got.Status != check.Skip {
		t.Errorf("no docker: got %s, want skip", got.Status)
	}
}

func TestContainerDepthTable(t *testing.T) {
	for _, tc := range []struct {
		id, hostcfg, cfgv2 string
		want               check.Status
	}{
		// HOST-CTR-011 confinement
		{"HOST-CTR-011", `{"SecurityOpt": ["seccomp=unconfined"]}`, "", check.Fail},
		{"HOST-CTR-011", `{"SecurityOpt": ["apparmor=unconfined"]}`, "", check.Fail},
		{"HOST-CTR-011", `{"SecurityOpt": ["label=disable"]}`, "", check.Fail},
		{"HOST-CTR-011", `{"SecurityOpt": ["no-new-privileges", "seccomp=/etc/docker/custom.json"]}`, "", check.Pass},
		{"HOST-CTR-011", `{"SecurityOpt": null}`, "", check.Pass},
		// HOST-CTR-012 limits
		{"HOST-CTR-012", `{"Memory": 0, "PidsLimit": 0}`, "", check.Fail},
		{"HOST-CTR-012", `{"Memory": 0}`, "", check.Fail},
		{"HOST-CTR-012", `{"Memory": 536870912, "PidsLimit": 0}`, "", check.Pass},
		{"HOST-CTR-012", `{"Memory": 0, "PidsLimit": 100}`, "", check.Pass},
		// HOST-CTR-013 root with writable rootfs
		{"HOST-CTR-013", `{"ReadonlyRootfs": false}`, `{"Config": {"User": ""}}`, check.Fail},
		{"HOST-CTR-013", `{"ReadonlyRootfs": false}`, `{"Config": {"User": "root"}}`, check.Fail},
		{"HOST-CTR-013", `{"ReadonlyRootfs": false}`, `{"Config": {"User": "0:0"}}`, check.Fail},
		{"HOST-CTR-013", `{"ReadonlyRootfs": true}`, `{"Config": {"User": ""}}`, check.Pass},
		{"HOST-CTR-013", `{"ReadonlyRootfs": false}`, `{"Config": {"User": "1000:1000"}}`, check.Pass},
		{"HOST-CTR-013", `{"ReadonlyRootfs": false}`, "", check.Pass}, // user unknown: not judged
	} {
		got := run(t, tc.id, dockerFake(`{}`, tc.hostcfg, tc.cfgv2))
		if got.Status != tc.want {
			t.Errorf("%s hostconfig %q config %q: got %s (%s %v), want %s", tc.id, tc.hostcfg, tc.cfgv2, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// Daemon-wide unconfined seccomp fails even with no containers.
	if got := run(t, "HOST-CTR-011", dockerFake(`{"seccomp-profile": "unconfined"}`, "", "")); got.Status != check.Fail {
		t.Errorf("daemon seccomp unconfined: got %s, want fail", got.Status)
	}
	// Unreadable container configuration is incomplete, not pass.
	f := dockerFake(`{}`, `{broken`, "")
	for _, id := range []string{"HOST-CTR-011", "HOST-CTR-012", "HOST-CTR-013"} {
		if got := run(t, id, f); got.Status != check.Incomplete {
			t.Errorf("%s with broken hostconfig: got %s, want incomplete", id, got.Status)
		}
	}
}

func TestContainerdAndPodman(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		want             check.Status
	}{
		{"containerd tcp without tls", "/etc/containerd/config.toml", "[grpc]\n  address = \"/run/containerd/containerd.sock\"\n  tcp_address = \"0.0.0.0:8888\"\n", check.Fail},
		{"containerd tcp with tls", "/etc/containerd/config.toml", "[grpc]\n  tcp_address = \"0.0.0.0:8888\"\n  tcp_tls_cert = \"/etc/containerd/server.crt\"\n", check.Pass},
		{"containerd socket only", "/etc/containerd/config.toml", "[grpc]\n  address = \"/run/containerd/containerd.sock\"\n", check.Pass},
		{"podman unconfined", "/etc/containers/containers.conf", "[containers]\nseccomp_profile = \"unconfined\"\n", check.Fail},
		{"podman label off", "/etc/containers/containers.conf", "[containers]\nlabel = false\n", check.Fail},
		{"podman apparmor unconfined", "/etc/containers/containers.conf", "[containers]\napparmor_profile = \"unconfined\" # dev box\n", check.Fail},
		{"podman defaults", "/usr/share/containers/containers.conf", "[containers]\nlabel = true\n[engine]\nruntime = \"crun\"\n", check.Pass},
	} {
		f := &sys.Fake{Files: map[string]string{tc.path: tc.text}}
		got := runOnHost(t, "HOST-CTR-014", f)
		if len(got) != 1 || got[0].Status != tc.want {
			t.Errorf("%s: got %+v, want %s", tc.name, got, tc.want)
		}
	}
	if got := run(t, "HOST-CTR-014", &sys.Fake{Files: map[string]string{}}); got.Status != check.Skip {
		t.Errorf("no runtime config: got %s, want skip", got.Status)
	}
}

func TestTomlValues(t *testing.T) {
	v := tomlValues("# comment\nversion = 2\n[grpc]\n  address = \"/run/x.sock\" # trailing\n  tcp_address = '0.0.0.0:1'\n[containers]\nlabel = false\n")
	for k, want := range map[string]string{"version": "2", "grpc.address": "/run/x.sock", "grpc.tcp_address": "0.0.0.0:1", "containers.label": "false"} {
		if v[k] != want {
			t.Errorf("%s = %q, want %q", k, v[k], want)
		}
	}
}
