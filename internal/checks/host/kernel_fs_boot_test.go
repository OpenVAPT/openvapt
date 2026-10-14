package host

import (
	"context"
	"io/fs"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
)

// Tests for the kernel depth (HOST-KRN-019 onwards), filesystem depth
// (HOST-FS-010 onwards) and boot and integrity (HOST-BOOT) checks. Every
// check is run against the lab pair plus hand-built fakes that exercise
// the Incomplete and Skip paths, so no check passes by default.

var kernelFSBootIDs = []string{
	"HOST-KRN-019", "HOST-KRN-020", "HOST-KRN-021", "HOST-KRN-022", "HOST-KRN-023", "HOST-KRN-024", "HOST-KRN-025",
	"HOST-KRN-026", "HOST-KRN-027", "HOST-KRN-028", "HOST-KRN-029", "HOST-KRN-030", "HOST-KRN-031",
	"HOST-FS-010", "HOST-FS-011", "HOST-FS-012", "HOST-FS-013", "HOST-FS-014", "HOST-FS-015", "HOST-FS-016",
	"HOST-FS-017", "HOST-FS-018", "HOST-FS-019", "HOST-FS-020", "HOST-FS-021", "HOST-FS-022",
	"HOST-BOOT-001", "HOST-BOOT-002", "HOST-BOOT-003", "HOST-BOOT-004", "HOST-BOOT-005", "HOST-BOOT-006", "HOST-BOOT-007", "HOST-BOOT-008",
}

// runAll returns every result of a check (some return one per path).
func runAll(t *testing.T, id string, f *sys.Fake) []check.Result {
	t.Helper()
	c := check.Get(id)
	if c == nil {
		t.Fatalf("%s not registered", id)
	}
	return c.Run(context.Background(), f)
}

func statuses(rs []check.Result) map[check.Status]int {
	m := map[check.Status]int{}
	for _, r := range rs {
		m[r.Status]++
	}
	return m
}

func TestKernelFSBootLabPair(t *testing.T) {
	for _, id := range kernelFSBootIDs {
		v := statuses(runAll(t, id, lab.Vulnerable()))
		if v[check.Fail] == 0 || v[check.Error] > 0 {
			t.Errorf("%s: vulnerable lab should fail, got %v", id, v)
		}
		h := statuses(runAll(t, id, lab.Hardened()))
		if h[check.Fail] > 0 || h[check.Error] > 0 || h[check.Incomplete] > 0 || h[check.Pass] == 0 {
			t.Errorf("%s: hardened lab should pass, got %v", id, h)
		}
	}
}

func empty() *sys.Fake {
	return &sys.Fake{Files: map[string]string{}, Infos: map[string]sys.FileInfo{}, Commands: map[string]string{}, IncompleteFiles: map[string]bool{}, IncompleteWalks: map[string]bool{}}
}

func TestSysctlDepthTable(t *testing.T) {
	cases := []struct {
		id, key, value string
		want           check.Status
	}{
		{"HOST-KRN-019", "kernel/sysrq", "4", check.Pass},
		{"HOST-KRN-019", "kernel/sysrq", "176", check.Fail},
		{"HOST-KRN-020", "fs/protected_fifos", "2", check.Pass},
		{"HOST-KRN-021", "fs/protected_regular", "0", check.Fail},
		{"HOST-KRN-026", "net/ipv4/icmp_ignore_bogus_error_responses", "1", check.Pass},
		{"HOST-KRN-027", "kernel/kexec_load_disabled", "0", check.Fail},
		{"HOST-KRN-028", "vm/unprivileged_userfaultfd", "0", check.Pass},
		{"HOST-KRN-029", "dev/tty/ldisc_autoload", "1", check.Fail},
		{"HOST-KRN-030", "net/core/bpf_jit_harden", "1", check.Pass},
		{"HOST-KRN-031", "kernel/io_uring_disabled", "1", check.Pass},
		{"HOST-KRN-031", "kernel/io_uring_disabled", "0", check.Fail},
	}
	for _, c := range cases {
		f := empty()
		f.Files["/proc/sys/"+c.key] = c.value + "\n"
		if r := run(t, c.id, f); r.Status != c.want {
			t.Errorf("%s with %s=%s: want %s, got %s %q", c.id, c.key, c.value, c.want, r.Status, r.Message)
		}
	}
	// Missing parameter: skipped, never a pass.
	if r := run(t, "HOST-KRN-031", empty()); r.Status != check.Skip {
		t.Errorf("missing io_uring_disabled: want Skip, got %s", r.Status)
	}
	// Per-interface rules fail when any interface differs from all.
	f := empty()
	f.Files["/proc/sys/net/ipv6/conf/all/accept_ra"] = "0"
	f.Files["/proc/sys/net/ipv6/conf/eth0/accept_ra"] = "1"
	if r := run(t, "HOST-KRN-025", f); r.Status != check.Fail {
		t.Errorf("accept_ra on eth0: want Fail, got %s", r.Status)
	}
	f.Files["/proc/sys/net/ipv6/conf/eth0/accept_ra"] = "0"
	if r := run(t, "HOST-KRN-025", f); r.Status != check.Pass {
		t.Errorf("accept_ra off everywhere: want Pass, got %s", r.Status)
	}
}

func TestUserNamespaces(t *testing.T) {
	f := empty()
	if r := run(t, "HOST-KRN-022", f); r.Status != check.Skip {
		t.Errorf("no parameter: want Skip, got %s", r.Status)
	}
	f.Files["/proc/sys/user/max_user_namespaces"] = "0\n"
	if r := run(t, "HOST-KRN-022", f); r.Status != check.Pass {
		t.Errorf("max_user_namespaces 0: want Pass, got %s", r.Status)
	}
	f.Files["/proc/sys/user/max_user_namespaces"] = "28633\n"
	if r := run(t, "HOST-KRN-022", f); r.Status != check.Fail {
		t.Errorf("max_user_namespaces set: want Fail, got %s", r.Status)
	}
	f.Files["/proc/sys/kernel/unprivileged_userns_clone"] = "0\n"
	if r := run(t, "HOST-KRN-022", f); r.Status != check.Pass {
		t.Errorf("userns_clone 0 wins: want Pass, got %s", r.Status)
	}
	f.IncompleteFiles["/proc/sys/kernel/unprivileged_userns_clone"] = true
	if r := run(t, "HOST-KRN-022", f); r.Status != check.Incomplete {
		t.Errorf("truncated read: want Incomplete, got %s", r.Status)
	}
}

func TestMountChecksIncompleteWithoutMountTable(t *testing.T) {
	for _, id := range []string{"HOST-FS-010", "HOST-FS-011", "HOST-FS-012", "HOST-FS-013"} {
		if r := run(t, id, empty()); r.Status != check.Incomplete {
			t.Errorf("%s without /proc/mounts: want Incomplete, got %s", id, r.Status)
		}
		f := empty()
		f.Files["/proc/mounts"] = "tmpfs /tmp tmpfs rw 0 0\n"
		f.IncompleteFiles["/proc/mounts"] = true
		if r := run(t, id, f); r.Status != check.Incomplete {
			t.Errorf("%s with partial /proc/mounts: want Incomplete, got %s", id, r.Status)
		}
	}
	f := empty()
	f.Files["/proc/mounts"] = "/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /var/tmp ext4 rw,nosuid 0 0\n/dev/sda3 /var ext4 rw 0 0\n"
	if r := run(t, "HOST-FS-010", f); r.Status != check.Fail || len(r.Evidence) == 0 {
		t.Errorf("/var/tmp without nodev,noexec: want Fail with evidence, got %s %v", r.Status, r.Evidence)
	}
	if r := run(t, "HOST-FS-012", f); r.Status != check.Pass {
		t.Errorf("/var as a separate mount satisfies the log rule: want Pass, got %s", r.Status)
	}
	if r := run(t, "HOST-FS-013", f); r.Status != check.Fail {
		t.Errorf("/var/tmp without noexec: want Fail, got %s", r.Status)
	}
	g := empty()
	g.Files["/proc/mounts"] = "/dev/sda1 / ext4 rw 0 0\n"
	if r := run(t, "HOST-FS-013", g); r.Status != check.Skip {
		t.Errorf("no temporary mounts: want Skip, got %s", r.Status)
	}
}

func TestWalkChecksIncompleteOnPartialWalk(t *testing.T) {
	f := empty()
	f.Files["/etc/passwd"] = "root:x:0:0:root:/root:/bin/bash\n"
	f.Files["/etc/group"] = "root:x:0:\n"
	f.Infos["/opt/app/bin"] = sys.FileInfo{Path: "/opt/app/bin", Mode: 0o755}
	f.Infos["/usr/bin/sudo"] = sys.FileInfo{Path: "/usr/bin/sudo", Mode: fs.ModeSetuid | 0o755}
	for _, id := range []string{"HOST-FS-014", "HOST-FS-015", "HOST-FS-016"} {
		if r := run(t, id, f); r.Status != check.Pass {
			t.Errorf("%s clean tree: want Pass, got %s %q", id, r.Status, r.Message)
		}
	}
	f.IncompleteWalks["/opt"] = true
	f.IncompleteWalks["/usr/bin"] = true
	for _, id := range []string{"HOST-FS-014", "HOST-FS-015", "HOST-FS-016"} {
		if r := run(t, id, f); r.Status != check.Incomplete {
			t.Errorf("%s partial walk: want Incomplete, got %s %q", id, r.Status, r.Message)
		}
	}
	// Unreadable account database: incomplete, not pass.
	g := empty()
	g.Infos["/opt/app/bin"] = sys.FileInfo{Path: "/opt/app/bin", Mode: 0o755}
	if r := run(t, "HOST-FS-015", g); r.Status != check.Incomplete {
		t.Errorf("no passwd: want Incomplete, got %s", r.Status)
	}
	// A stock RHEL 9 / Alma 9 server: sssd helpers and the other RHEL
	// family defaults are on the baseline (V-04), an extra helper is not.
	rhel := empty()
	rhel.Files["/etc/passwd"] = "root:x:0:0:root:/root:/bin/bash\n"
	rhel.Files["/etc/group"] = "root:x:0:\n"
	for _, p := range []string{"/usr/libexec/sssd/krb5_child", "/usr/libexec/sssd/ldap_child", "/usr/libexec/sssd/proxy_child", "/usr/libexec/sssd/selinux_child",
		"/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache", "/usr/libexec/qemu-bridge-helper", "/usr/bin/staprun", "/usr/sbin/netreport",
		"/usr/libexec/openssh/ssh-keysign", "/usr/libexec/dbus-1/dbus-daemon-launch-helper", "/usr/libexec/utempter/utempter", "/usr/libexec/cockpit-session",
		"/usr/sbin/grub2-set-bootflag", "/usr/sbin/pam_timestamp_check", "/usr/sbin/unix_chkpwd", "/usr/sbin/userhelper", "/usr/bin/sudo", "/usr/bin/fusermount3"} {
		rhel.Infos[p] = sys.FileInfo{Path: p, Mode: fs.ModeSetuid | 0o755}
	}
	if r := run(t, "HOST-FS-016", rhel); r.Status != check.Pass {
		t.Errorf("RHEL 9 default SUID set: want Pass, got %s %v", r.Status, r.Evidence)
	}
	rhel.Infos["/usr/libexec/sssd/custom_child"] = sys.FileInfo{Path: "/usr/libexec/sssd/custom_child", Mode: fs.ModeSetuid | 0o755}
	if r := run(t, "HOST-FS-016", rhel); r.Status != check.Fail {
		t.Errorf("unknown helper beside the sssd ones: want Fail, got %s", r.Status)
	}
	// Empty SUID inventory is incomplete, never a pass.
	if r := run(t, "HOST-FS-016", empty()); r.Status != check.Incomplete {
		t.Errorf("no SUID programs seen: want Incomplete, got %s", r.Status)
	}
	// Nothing to list for the sticky bit check is incomplete.
	if r := run(t, "HOST-FS-017", empty()); r.Status != check.Incomplete {
		t.Errorf("no directories: want Incomplete, got %s", r.Status)
	}
}

func TestBootFilesCronUmaskAccounts(t *testing.T) {
	if r := run(t, "HOST-FS-018", empty()); r.Status != check.Skip {
		t.Errorf("no boot files: want Skip, got %s", r.Status)
	}
	f := empty()
	f.Files["/boot/initrd.img-6.8.0"] = ""
	f.Infos["/boot/initrd.img-6.8.0"] = sys.FileInfo{Path: "/boot/initrd.img-6.8.0", Mode: 0o644}
	if r := run(t, "HOST-FS-018", f); r.Status != check.Fail {
		t.Errorf("world-readable initrd: want Fail, got %s", r.Status)
	}

	// cron and at absent: skipped. cron present without allow: fail.
	if r := run(t, "HOST-FS-019", empty()); r.Status != check.Skip {
		t.Errorf("no scheduler: want Skip, got %s", r.Status)
	}
	g := empty()
	g.Files["/etc/crontab"] = ""
	g.Files["/etc/cron.allow"] = "root\n"
	g.Infos["/etc/cron.allow"] = sys.FileInfo{Path: "/etc/cron.allow", Mode: 0o644}
	rs := runAll(t, "HOST-FS-019", g)
	if len(rs) != 1 || rs[0].Status != check.Fail {
		t.Errorf("group-readable cron.allow: want one Fail, got %+v", rs)
	}
	g.Infos["/etc/cron.allow"] = sys.FileInfo{Path: "/etc/cron.allow", Mode: 0o600, UID: 1000}
	if rs := runAll(t, "HOST-FS-019", g); rs[0].Status != check.Fail {
		t.Errorf("non-root cron.allow: want Fail, got %+v", rs)
	}

	h := empty()
	h.Files["/etc/crontab"] = ""
	h.Infos["/etc/crontab"] = sys.FileInfo{Path: "/etc/crontab", Mode: 0o644}
	if r := run(t, "HOST-FS-020", h); r.Status != check.Fail {
		t.Errorf("crontab 644: want Fail, got %s", r.Status)
	}
	if r := run(t, "HOST-FS-020", empty()); r.Status != check.Skip {
		t.Errorf("no cron: want Skip, got %s", r.Status)
	}

	// umask: none set is skipped; a partial read is incomplete; 0022 fails.
	if r := run(t, "HOST-FS-021", empty()); r.Status != check.Skip {
		t.Errorf("no umask lines: want Skip, got %s", r.Status)
	}
	u := empty()
	u.Files["/etc/profile.d/umask.sh"] = "# set umask\n  umask 0022  # readable\n"
	if r := run(t, "HOST-FS-021", u); r.Status != check.Fail {
		t.Errorf("umask 0022 in profile.d: want Fail, got %s %v", r.Status, r.Evidence)
	}
	u.Files["/etc/profile.d/umask.sh"] = "umask 077\n"
	u.Files["/etc/bash.bashrc"] = "umask 027\n"
	u.IncompleteFiles["/etc/bash.bashrc"] = true
	if r := run(t, "HOST-FS-021", u); r.Status != check.Incomplete {
		t.Errorf("partial bashrc: want Incomplete, got %s", r.Status)
	}

	// Account files: none visible is incomplete; non-root owner fails.
	if r := run(t, "HOST-FS-022", empty()); r.Status != check.Incomplete {
		t.Errorf("no account files: want Incomplete, got %s", r.Status)
	}
	a := empty()
	a.Infos["/etc/passwd"] = sys.FileInfo{Path: "/etc/passwd", Mode: 0o644, UID: 1000}
	if r := run(t, "HOST-FS-022", a); r.Status != check.Fail {
		t.Errorf("passwd owned by uid 1000: want Fail, got %s", r.Status)
	}
	a.Infos["/etc/passwd"] = sys.FileInfo{Path: "/etc/passwd", Mode: 0o644}
	a.Infos["/etc/gshadow-"] = sys.FileInfo{Path: "/etc/gshadow-", Mode: 0o640}
	if r := run(t, "HOST-FS-022", a); r.Status != check.Pass {
		t.Errorf("safe account files: want Pass, got %s %v", r.Status, r.Evidence)
	}
}

func TestBootLoaderAndSecureBoot(t *testing.T) {
	if r := run(t, "HOST-BOOT-001", empty()); r.Status != check.Skip {
		t.Errorf("no grub: want Skip, got %s", r.Status)
	}
	f := empty()
	f.Files["/boot/grub2/grub.cfg"] = "set superusers=\"root\"\n"
	if r := run(t, "HOST-BOOT-001", f); r.Status != check.Fail {
		t.Errorf("superuser without password: want Fail, got %s", r.Status)
	}
	f.Files["/boot/grub2/user.cfg"] = "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.X\n"
	if r := run(t, "HOST-BOOT-001", f); r.Status != check.Fail {
		t.Errorf("RHEL user.cfg without password directive in grub.cfg: want Fail, got %s", r.Status)
	}
	f.Files["/boot/grub2/grub.cfg"] += "password_pbkdf2 root grub.pbkdf2.sha512.10000.X\n"
	r := run(t, "HOST-BOOT-001", f)
	if r.Status != check.Pass {
		t.Errorf("superuser and password: want Pass, got %s", r.Status)
	}
	for _, e := range r.Evidence {
		if contains(e, "pbkdf2.sha512") {
			t.Errorf("evidence leaks the hash: %q", e)
		}
	}
	f.IncompleteFiles["/boot/grub2/grub.cfg"] = true
	f.Files["/boot/grub2/grub.cfg"] = "menuentry 'Linux' {\n"
	if r := run(t, "HOST-BOOT-001", f); r.Status != check.Incomplete {
		t.Errorf("partial grub.cfg: want Incomplete, got %s", r.Status)
	}

	if r := run(t, "HOST-BOOT-002", empty()); r.Status != check.Skip {
		t.Errorf("BIOS machine: want Skip, got %s", r.Status)
	}
	g := empty()
	g.Infos["/sys/firmware/efi"] = sys.FileInfo{Path: "/sys/firmware/efi", IsDir: true, Mode: fs.ModeDir | 0o755}
	if r := run(t, "HOST-BOOT-002", g); r.Status != check.Skip {
		t.Errorf("UEFI without the variable: want Skip, got %s", r.Status)
	}
	g.Files["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = "\x06\x00"
	if r := run(t, "HOST-BOOT-002", g); r.Status != check.Incomplete {
		t.Errorf("short variable: want Incomplete, got %s", r.Status)
	}
	g.Files["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = "\x06\x00\x00\x00\x01"
	if r := run(t, "HOST-BOOT-002", g); r.Status != check.Pass {
		t.Errorf("Secure Boot on: want Pass, got %s", r.Status)
	}
}

func TestModulesIntegrityPrelinkCoreDumps(t *testing.T) {
	f := empty()
	f.Files["/etc/modprobe.d/blacklist.conf"] = "blacklist cramfs\nblacklist freevxfs\nblacklist jffs2\nblacklist hfs\nblacklist hfsplus\nblacklist udf\n"
	f.Infos["/snap"] = sys.FileInfo{Path: "/snap", IsDir: true, Mode: fs.ModeDir | 0o755}
	if r := run(t, "HOST-BOOT-003", f); r.Status != check.Pass {
		t.Errorf("snap host with the six others blacklisted: want Pass, got %s %q", r.Status, r.Message)
	}
	delete(f.Infos, "/snap")
	if r := run(t, "HOST-BOOT-003", f); r.Status != check.Fail || !contains(r.Message, "squashfs") {
		t.Errorf("squashfs not disabled without snap: want Fail naming squashfs, got %s %q", r.Status, r.Message)
	}
	f.IncompleteFiles["/etc/modprobe.d/blacklist.conf"] = true
	if r := run(t, "HOST-BOOT-003", f); r.Status != check.Incomplete {
		t.Errorf("partial modprobe.d: want Incomplete, got %s", r.Status)
	}
	if r := run(t, "HOST-BOOT-004", f); r.Status != check.Incomplete {
		t.Errorf("usb-storage with partial modprobe.d: want Incomplete, got %s", r.Status)
	}
	g := empty()
	g.Files["/usr/lib/modprobe.d/usb.conf"] = "install usb_storage /usr/bin/false\n"
	if r := run(t, "HOST-BOOT-004", g); r.Status != check.Pass {
		t.Errorf("underscore spelling in /usr/lib: want Pass, got %s", r.Status)
	}

	if r := run(t, "HOST-BOOT-005", empty()); r.Status != check.Skip {
		t.Errorf("no module support: want Skip, got %s", r.Status)
	}
	m := empty()
	m.Files["/proc/sys/kernel/modules_disabled"] = "1\n"
	if r := run(t, "HOST-BOOT-005", m); r.Status != check.Pass {
		t.Errorf("modules_disabled 1: want Pass, got %s", r.Status)
	}
	m.Files["/proc/sys/kernel/modules_disabled"] = "0\n"
	m.Files["/sys/kernel/security/lockdown"] = "none [integrity] confidentiality\n"
	if r := run(t, "HOST-BOOT-005", m); r.Status != check.Pass {
		t.Errorf("lockdown integrity: want Pass, got %s", r.Status)
	}
	m.Files["/sys/kernel/security/lockdown"] = "[none] integrity confidentiality\n"
	if r := run(t, "HOST-BOOT-005", m); r.Status != check.Fail {
		t.Errorf("lockdown none: want Fail, got %s", r.Status)
	}
	m.IncompleteFiles["/sys/kernel/security/lockdown"] = true
	if r := run(t, "HOST-BOOT-005", m); r.Status != check.Incomplete {
		t.Errorf("partial lockdown read: want Incomplete, got %s", r.Status)
	}

	i := empty()
	i.Files["/usr/sbin/tripwire"] = ""
	if r := run(t, "HOST-BOOT-006", i); r.Status != check.Fail {
		t.Errorf("tripwire without schedule: want Fail, got %s", r.Status)
	}
	i.Files["/etc/systemd/system/tripwire-check.timer"] = "[Timer]\nOnCalendar=daily\n"
	if r := run(t, "HOST-BOOT-006", i); r.Status != check.Pass {
		t.Errorf("tripwire with timer: want Pass, got %s", r.Status)
	}
	j := empty()
	j.Files["/usr/bin/aide"] = ""
	j.Files["/etc/crontab"] = "0 5 * * * root /usr/bin/aide --check\n"
	if r := run(t, "HOST-BOOT-006", j); r.Status != check.Pass {
		t.Errorf("aide in /etc/crontab: want Pass, got %s", r.Status)
	}

	p := empty()
	p.Files["/usr/sbin/prelink"] = ""
	p.Files["/etc/sysconfig/prelink"] = "PRELINKING=no\n"
	if r := run(t, "HOST-BOOT-007", p); r.Status != check.Pass {
		t.Errorf("prelink disabled: want Pass, got %s", r.Status)
	}
	p.IncompleteFiles["/etc/sysconfig/prelink"] = true
	if r := run(t, "HOST-BOOT-007", p); r.Status != check.Incomplete {
		t.Errorf("partial prelink config: want Incomplete, got %s", r.Status)
	}

	c := empty()
	if r := run(t, "HOST-BOOT-008", c); r.Status != check.Fail {
		t.Errorf("no limits at all: want Fail, got %s", r.Status)
	}
	c.Files["/etc/security/limits.d/90-core.conf"] = "*   -   core   0\n"
	if r := run(t, "HOST-BOOT-008", c); r.Status != check.Pass {
		t.Errorf("limits.d dash form: want Pass, got %s", r.Status)
	}
	d := empty()
	d.Files["/proc/sys/kernel/core_pattern"] = "|/lib/systemd/systemd-coredump %P\n"
	d.Files["/etc/systemd/coredump.conf"] = "[Coredump]\n#Storage=external\n"
	d.Files["/etc/systemd/coredump.conf.d/no.conf"] = "[Coredump]\nStorage=none\n"
	if r := run(t, "HOST-BOOT-008", d); r.Status != check.Pass {
		t.Errorf("coredump.conf.d Storage=none: want Pass, got %s", r.Status)
	}
	d.IncompleteFiles["/etc/systemd/coredump.conf.d/no.conf"] = true
	if r := run(t, "HOST-BOOT-008", d); r.Status != check.Incomplete {
		t.Errorf("partial coredump drop-in: want Incomplete, got %s", r.Status)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
