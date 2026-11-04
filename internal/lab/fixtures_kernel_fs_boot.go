package lab

import (
	"io/fs"

	"github.com/openvapt/openvapt/internal/sys"
)

// Fixtures for the kernel parameter depth (HOST-KRN-019 onwards), filesystem
// depth (HOST-FS-010 onwards) and boot and integrity (HOST-BOOT) checks.
// Each weakness in the vulnerable lab has its fix in the hardened lab.

func dir(f *sys.Fake, path string, mode fs.FileMode) {
	f.Files[path] = ""
	f.Infos[path] = sys.FileInfo{Path: path, Mode: fs.ModeDir | mode, IsDir: true}
}

func owned(f *sys.Fake, path string, mode fs.FileMode, uid, gid int) {
	f.Files[path] = ""
	f.Infos[path] = sys.FileInfo{Path: path, Mode: mode, UID: uid, GID: gid}
}

func init() {
	Register(func(f *sys.Fake) {
		// Kernel parameters left at their permissive defaults.
		for k, v := range map[string]string{
			"kernel/sysrq": "1", "fs/protected_fifos": "0", "fs/protected_regular": "0",
			"kernel/unprivileged_userns_clone": "1", "net/ipv6/conf/all/accept_source_route": "1",
			"net/ipv4/conf/all/secure_redirects": "1", "net/ipv6/conf/all/accept_ra": "1",
			"net/ipv4/icmp_ignore_bogus_error_responses": "0", "kernel/kexec_load_disabled": "0",
			"vm/unprivileged_userfaultfd": "1", "dev/tty/ldisc_autoload": "1", "net/core/bpf_jit_harden": "0",
			"kernel/io_uring_disabled": "0", "kernel/modules_disabled": "0", "kernel/core_pattern": "core",
		} {
			f.Files["/proc/sys/"+k] = v
		}
		// Everything on one root filesystem; /tmp without noexec (see
		// fixtures_host.go for the mount table).
		owned(f, "/srv/app/upload.sh", 0o666, 0, 0)
		owned(f, "/opt/legacy/app.bin", 0o755, 1003, 1003)
		owned(f, "/usr/bin/nmap", fs.ModeSetuid|0o755, 0, 0)
		owned(f, "/usr/bin/sudo", fs.ModeSetuid|0o755, 0, 0)
		dir(f, "/var/www", 0o755)
		dir(f, "/var/www/uploads", 0o777)
		file(f, "/boot/System.map-4.15.0-20-generic", "", 0o644)
		file(f, "/etc/cron.deny", "", 0o644)
		file(f, "/etc/at.deny", "", 0o644)
		file(f, "/etc/profile", "umask 022\n", 0o644)
		f.Infos["/etc/shadow-"] = sys.FileInfo{Path: "/etc/shadow-", Mode: 0o644}
		// Boot and integrity.
		f.Files["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = "\x06\x00\x00\x00\x00"
		file(f, "/usr/sbin/prelink", "", 0o755)
		file(f, "/etc/prelink.conf", "-l /usr/bin\n", 0o644)
		file(f, "/etc/security/limits.conf", "# /etc/security/limits.conf\n#* soft core 0\n", 0o644)
	}, func(f *sys.Fake) {
		for k, v := range map[string]string{
			"kernel/sysrq": "0", "fs/protected_fifos": "1", "fs/protected_regular": "2",
			"kernel/unprivileged_userns_clone": "0", "net/ipv6/conf/all/accept_source_route": "0",
			"net/ipv4/conf/all/secure_redirects": "0", "net/ipv6/conf/all/accept_ra": "0",
			"net/ipv4/icmp_ignore_bogus_error_responses": "1", "kernel/kexec_load_disabled": "1",
			"vm/unprivileged_userfaultfd": "0", "dev/tty/ldisc_autoload": "0", "net/core/bpf_jit_harden": "2",
			"kernel/io_uring_disabled": "2", "kernel/modules_disabled": "0",
			"kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h",
		} {
			f.Files["/proc/sys/"+k] = v
		}
		f.Files["/proc/mounts"] += "tmpfs /var/tmp tmpfs rw,nosuid,nodev,noexec 0 0\n" +
			"/dev/sda3 /home ext4 rw,nosuid,nodev 0 0\n" +
			"/dev/sda4 /var/log ext4 rw,nosuid,nodev,noexec 0 0\n"
		owned(f, "/srv/app/run.sh", 0o755, 0, 0)
		owned(f, "/usr/bin/sudo", fs.ModeSetuid|0o755, 0, 0)
		owned(f, "/usr/bin/passwd", fs.ModeSetuid|0o755, 0, 0)
		dir(f, "/var/www", 0o755)
		dir(f, "/var/www/html", 0o755)
		file(f, "/boot/System.map-6.8.0-45-generic", "", 0o600)
		file(f, "/etc/cron.allow", "root\n", 0o600)
		file(f, "/etc/at.allow", "root\n", 0o600)
		file(f, "/etc/profile", "umask 027\n", 0o644)
		f.Infos["/etc/shadow-"] = sys.FileInfo{Path: "/etc/shadow-", Mode: 0o640}
		f.Infos["/etc/passwd-"] = sys.FileInfo{Path: "/etc/passwd-", Mode: 0o644}
		// Boot and integrity.
		f.Files["/etc/grub.d/40_custom"] = "#!/bin/sh\nexec tail -n +3 $0\nset superusers=\"admin\"\npassword_pbkdf2 admin grub.pbkdf2.sha512.10000.REDACTED\n"
		f.Files["/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"] = "\x06\x00\x00\x00\x01"
		f.Files["/etc/modprobe.d/openvapt-filesystems.conf"] = "install cramfs /bin/false\nblacklist cramfs\ninstall freevxfs /bin/false\nblacklist freevxfs\n" +
			"install jffs2 /bin/false\nblacklist jffs2\ninstall hfs /bin/false\nblacklist hfs\ninstall hfsplus /bin/false\nblacklist hfsplus\n" +
			"install udf /bin/false\nblacklist udf\ninstall squashfs /bin/false\nblacklist squashfs\n"
		f.Files["/etc/modprobe.d/openvapt-usb.conf"] = "install usb-storage /bin/false\nblacklist usb-storage\n"
		f.Files["/sys/module/module/parameters/sig_enforce"] = "Y\n"
		file(f, "/usr/bin/aide", "", 0o755)
		file(f, "/etc/aide/aide.conf", "database_in=file:/var/lib/aide/aide.db\n", 0o600)
		file(f, "/etc/cron.daily/aide", "#!/bin/sh\n/usr/bin/aide --check\n", 0o700)
		file(f, "/etc/security/limits.conf", "* hard core 0\n", 0o644)
		file(f, "/etc/systemd/coredump.conf", "[Coredump]\nStorage=none\nProcessSizeMax=0\n", 0o644)
	})
}
