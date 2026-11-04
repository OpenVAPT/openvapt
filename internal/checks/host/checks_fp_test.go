package host

import (
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// A2-03: a package removed but not purged keeps its .list file; the dpkg
// status file is the source of truth, so it must not count as installed.
func TestRemovedNotPurgedPackageIsNotInstalled(t *testing.T) {
	files := map[string]string{
		"/var/lib/dpkg/status":            "Package: bash\nStatus: install ok installed\nVersion: 5\n\nPackage: vsftpd\nStatus: deinstall ok config-files\nVersion: 3\n",
		"/var/lib/dpkg/info/bash.list":    "",
		"/var/lib/dpkg/info/vsftpd.list":  "",
		"/var/lib/dpkg/info/telnetd.list": "",
	}
	want(t, "HOST-SVC-005", fake(files, nil, nil), check.Pass, "")
	want(t, "HOST-SVC-002", fake(files, nil, nil), check.Pass, "")
	// Without a readable status file the .list files are the fallback.
	delete(files, "/var/lib/dpkg/status")
	want(t, "HOST-SVC-005", fake(files, nil, nil), check.Fail, "vsftpd")
}

func sysctlFake(vals map[string]string, cmds map[string]string) *sys.Fake {
	f := &sys.Fake{Files: map[string]string{}, Commands: cmds}
	for k, v := range vals {
		f.Files["/proc/sys/"+k] = v
	}
	return f
}

func TestKexecPassesWhenKdumpEnabled(t *testing.T) {
	f := sysctlFake(map[string]string{"kernel/kexec_load_disabled": "0"}, nil)
	want(t, "HOST-KRN-027", f, check.Fail, "")
	f.Commands = map[string]string{"systemctl is-enabled kdump": "enabled\n"}
	want(t, "HOST-KRN-027", f, check.Pass, "kdump")
}

func TestAcceptRAPassesWithRADefaultRoute(t *testing.T) {
	vals := map[string]string{"net/ipv6/conf/all/accept_ra": "1", "net/ipv6/conf/all/forwarding": "0"}
	f := sysctlFake(vals, nil)
	want(t, "HOST-KRN-025", f, check.Fail, "")
	f.Files["/proc/net/ipv6_route"] = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003 eth0\n"
	want(t, "HOST-KRN-025", f, check.Pass, "router advertisement")
	f.Files["/proc/sys/net/ipv6/conf/all/forwarding"] = "1"
	want(t, "HOST-KRN-025", f, check.Fail, "")
	// A static default route (no RA flags) does not excuse accept_ra.
	f.Files["/proc/sys/net/ipv6/conf/all/forwarding"] = "0"
	f.Files["/proc/net/ipv6_route"] = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
	want(t, "HOST-KRN-025", f, check.Fail, "")
}

func TestUserNamespacesAppArmorRestricted(t *testing.T) {
	f := sysctlFake(map[string]string{"kernel/unprivileged_userns_clone": "1"}, nil)
	want(t, "HOST-KRN-022", f, check.Fail, "")
	f.Files["/proc/sys/kernel/apparmor_restrict_unprivileged_userns"] = "1"
	want(t, "HOST-KRN-022", f, check.Pass, "AppArmor")
	f.Files["/proc/sys/kernel/apparmor_restrict_unprivileged_userns"] = "0"
	want(t, "HOST-KRN-022", f, check.Fail, "")
}

// A2-13: HOST-CTR-010 reads dockerd flags from docker.service drop-ins and
// never passes when daemon.json exists but cannot be read.
func TestDockerDaemonFlagsAndUnreadableJSON(t *testing.T) {
	f := dockerFake("", "", "")
	f.Files["/lib/systemd/system/docker.service"] = "[Service]\nExecStart=/usr/bin/dockerd -H fd://\n"
	want(t, "HOST-CTR-010", f, check.Pass, "")
	f.Files["/etc/systemd/system/docker.service.d/override.conf"] = "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd -H fd:// --insecure-registry reg.example.test:5000 -D\n"
	want(t, "HOST-CTR-010", f, check.Fail, "--insecure-registry reg.example.test:5000")
	// An empty ExecStart= in a later drop-in resets the earlier flags.
	f.Files["/etc/systemd/system/docker.service.d/zz.conf"] = "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd -H fd://\n"
	want(t, "HOST-CTR-010", f, check.Pass, "")

	g := dockerFake(`{}`, "", "")
	g.IncompleteFiles = map[string]bool{"/etc/docker/daemon.json": true}
	want(t, "HOST-CTR-010", g, check.Incomplete, "")
}
