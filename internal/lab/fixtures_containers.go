package lab

import (
	"io/fs"

	"github.com/openvapt/openvapt/internal/sys"
)

// Fixtures for the Docker and Kubernetes host checks.

const ctrID = "3f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f"

func init() {
	Register(func(f *sys.Fake) {
		f.Files["/etc/docker/daemon.json"] = `{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}`
		f.Files["/var/lib/docker/containers/"+ctrID+"/hostconfig.json"] =
			`{"Privileged": true, "PidMode": "host", "NetworkMode": "host", "CapAdd": ["SYS_ADMIN"], "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/:/host"]}`
		f.Files["/var/lib/kubelet/config.yaml"] = "authentication:\n  anonymous:\n    enabled: true\nauthorization:\n  mode: AlwaysAllow\nreadOnlyPort: 10255\n"
		f.Infos["/var/lib/etcd"] = sys.FileInfo{Path: "/var/lib/etcd", Mode: fs.ModeDir | 0o755, IsDir: true}
		file(f, "/etc/kubernetes/admin.conf", "", 0o644)
	}, func(f *sys.Fake) {
		f.Files["/etc/docker/daemon.json"] = `{"hosts": ["unix:///var/run/docker.sock"], "no-new-privileges": true, "icc": false, "userns-remap": "default", "live-restore": true}`
		f.Files["/var/lib/docker/containers/"+ctrID+"/hostconfig.json"] =
			`{"Privileged": false, "PidMode": "", "NetworkMode": "bridge", "CapAdd": null, "Binds": ["/srv/app/data:/data:ro"]}`
		f.Files["/var/lib/kubelet/config.yaml"] = "authentication:\n  anonymous:\n    enabled: false\nauthorization:\n  mode: Webhook\nreadOnlyPort: 0\n"
		f.Infos["/var/lib/etcd"] = sys.FileInfo{Path: "/var/lib/etcd", Mode: fs.ModeDir | 0o700, IsDir: true}
		file(f, "/etc/kubernetes/admin.conf", "", 0o600)
	})
}
