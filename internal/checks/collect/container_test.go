package collect

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/sys"
)

func TestDetectContainer(t *testing.T) {
	cases := []struct {
		files map[string]string
		typ   string
	}{
		{map[string]string{"/.dockerenv": ""}, "docker"},
		{map[string]string{"/run/.containerenv": ""}, "podman"},
		{map[string]string{"/proc/1/environ": "PATH=/bin\x00container=lxc\x00"}, "lxc"},
		{map[string]string{"/proc/1/cgroup": "12:pids:/kubepods/besteffort/pod1/abc\n"}, "kubernetes"},
		{map[string]string{"/proc/self/mountinfo": "1 0 0:1 / / rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/x,upperdir=/var/lib/docker/overlay2/y/diff\n2 1 0:2 /docker/containers/abc/hosts /etc/hosts rw - ext4 /dev/sda1 rw\n"}, "docker"},
		{map[string]string{"/proc/1/cgroup": "0::/init.scope\n", "/proc/self/mountinfo": "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"}, ""},
		// A host that runs containers is not itself a container.
		{map[string]string{"/proc/1/cgroup": "0::/init.scope\n", "/proc/self/mountinfo": "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n90 1 0:50 / /var/lib/docker/overlay2/abc/merged rw - overlay overlay rw\n91 1 0:51 / /run/containerd/io.containerd.runtime.v2.task/k8s.io/x/rootfs rw - overlay overlay rw\n"}, ""},
	}
	for i, c := range cases {
		got := DetectContainer(context.Background(), &sys.Fake{Files: c.files})
		if got.Type != c.typ || got.Inside != (c.typ != "") {
			t.Errorf("case %d: got %+v, want %q", i, got, c.typ)
		}
	}
}
