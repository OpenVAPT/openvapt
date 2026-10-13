package lab

import (
	"io/fs"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// Fixtures for the account, password, file, service and kernel hardening
// checks. Each weakness in the vulnerable lab has its fix in the hardened lab.

func file(f *sys.Fake, path, content string, mode fs.FileMode) {
	f.Files[path] = content
	f.Infos[path] = sys.FileInfo{Path: path, Mode: mode, Size: int64(len(content))}
}

func appendSSHD(f *sys.Fake, extra string) {
	for k, v := range f.Commands {
		if strings.HasPrefix(k, "sshd -T") {
			f.Commands[k] = v + extra
		}
	}
}

func init() {
	Register(func(f *sys.Fake) {
		f.Files["/etc/login.defs"] = "ENCRYPT_METHOD MD5\nPASS_MAX_DAYS 90\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 3\nUMASK 022\n"
		f.Files["/etc/passwd"] += "daemon:x:1:1:daemon:/usr/sbin:/bin/bash\n+::::::\n"
		f.Files["/etc/shadow"] += "olduser:$1$saltsalt$abcdefghijklmnopqrstuv:19000:0:99999:7:::\n"
		f.Files["/etc/group"] = "root:x:0:\ndocker:x:999:deploy\n"
		f.Files["/etc/security/pwquality.conf"] = "minlen = 8\n"
		f.Files["/etc/pam.d/common-auth"] = "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\n"
		f.Infos["/home/deploy/.netrc"] = sys.FileInfo{Path: "/home/deploy/.netrc", Mode: 0o644}
		file(f, "/etc/ssh/ssh_host_ed25519_key", "", 0o644)
		file(f, "/etc/ssh/sshd_config", "", 0o666)
		file(f, "/boot/grub/grub.cfg", "", 0o644)
		file(f, "/etc/ssl/private/shop.key", "", 0o644)
		file(f, "/var/log/auth.log", "", 0o644)
		f.Files["/proc/mounts"] = "tmpfs /tmp tmpfs rw,relatime 0 0\ntmpfs /dev/shm tmpfs rw 0 0\n"
		f.Files["/etc/debian_version"] = "10.13\n"
		file(f, "/var/run/reboot-required", "*** System restart required ***\n", 0o644)
		f.Files["/var/run/reboot-required.pkgs"] = "linux-image-generic\nlibc6\n"
		f.Commands["systemctl is-active avahi-daemon"] = "active"
		f.Commands["systemctl is-active rpcbind"] = "active"
		f.Infos["/var/run/docker.sock"] = sys.FileInfo{Path: "/var/run/docker.sock", Mode: fs.ModeSocket | 0o666}
		appendSSHD(f, "hostbasedauthentication yes\nignorerhosts no\npermituserenvironment yes\nloglevel quiet\n")
		for k, v := range map[string]string{
			"kernel/yama/ptrace_scope": "0", "fs/protected_symlinks": "0", "fs/protected_hardlinks": "0",
			"net/ipv4/conf/all/rp_filter": "0", "net/ipv4/conf/all/log_martians": "0", "net/ipv4/conf/all/send_redirects": "1",
			"net/ipv4/icmp_echo_ignore_broadcasts": "0", "net/ipv6/conf/all/accept_redirects": "1", "kernel/perf_event_paranoid": "1",
		} {
			f.Files["/proc/sys/"+k] = v
		}
	}, func(f *sys.Fake) {
		f.Files["/etc/login.defs"] = "ENCRYPT_METHOD YESCRYPT\nPASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nUMASK 027\n"
		f.Files["/etc/group"] = "root:x:0:\ndocker:x:999:\n"
		// Docker is installed (see the container fixtures) with an empty
		// docker group and the socket at its default 660 root:docker.
		f.Infos["/var/run/docker.sock"] = sys.FileInfo{Path: "/var/run/docker.sock", Mode: fs.ModeSocket | 0o660}
		f.Files["/etc/security/pwquality.conf"] = "minlen = 14\n"
		f.Files["/etc/pam.d/common-auth"] = "auth required pam_faillock.so preauth\nauth [success=1 default=ignore] pam_unix.so\nauth [default=die] pam_faillock.so authfail\n"
		file(f, "/etc/ssh/ssh_host_ed25519_key", "", 0o600)
		file(f, "/etc/ssh/sshd_config", "", 0o600)
		file(f, "/boot/grub/grub.cfg", "", 0o600)
		file(f, "/etc/ssl/private/shop.key", "", 0o600)
		file(f, "/var/log/auth.log", "", 0o640)
		f.Files["/proc/mounts"] = "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n"
		f.Files["/etc/debian_version"] = "12.7\n"
		f.Files["/sys/module/apparmor/parameters/enabled"] = "Y\n"
		f.Files["/etc/apt/apt.conf.d/20auto-upgrades"] = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
		f.Files["/etc/sudoers"] += "Defaults use_pty\nDefaults logfile=\"/var/log/sudo.log\"\n"
		f.Commands["systemctl is-active fail2ban"] = "active"
		file(f, "/etc/logrotate.conf", "weekly\nrotate 4\n", 0o644)
		appendSSHD(f, "hostbasedauthentication no\nignorerhosts yes\npermituserenvironment no\nloglevel verbose\n")
		for k, v := range map[string]string{
			"kernel/yama/ptrace_scope": "1", "fs/protected_symlinks": "1", "fs/protected_hardlinks": "1",
			"net/ipv4/conf/all/rp_filter": "1", "net/ipv4/conf/all/log_martians": "1", "net/ipv4/conf/all/send_redirects": "0",
			"net/ipv4/icmp_echo_ignore_broadcasts": "1", "net/ipv6/conf/all/accept_redirects": "0", "kernel/perf_event_paranoid": "3",
		} {
			f.Files["/proc/sys/"+k] = v
		}
	})
}
