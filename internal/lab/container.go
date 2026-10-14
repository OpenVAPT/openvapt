package lab

import "github.com/openvapt/openvapt/internal/sys"

// Container returns the given lab server as seen from inside a Docker
// container: the /.dockerenv marker plus a container cgroup path. It is a
// third view used by the container-awareness tests; it does not change the
// vulnerable or hardened labs.
func Container(f *sys.Fake) *sys.Fake {
	f.Files["/.dockerenv"] = ""
	f.Files["/proc/1/cgroup"] = "0::/docker/0123456789abcdef\n"
	return f
}
