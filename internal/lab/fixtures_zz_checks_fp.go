package lab

import "github.com/openvapt/openvapt/internal/sys"

// Fixtures for the false-positive fixes of 2026-10-14. The file name sorts
// last so these fixtures run after fixtures_host.go and may replace its files. The vulnerable
// server runs MySQL 5.7 (Ubuntu 18.04), whose defaults allow symbolic links
// and leave secure_file_priv unrestricted; the hardened server runs MySQL
// 8.0 and also sets both options explicitly.
func init() {
	Register(func(f *sys.Fake) {
		// A lockout that is present but weak: 100 failures, released after
		// one minute. HOST-PWD-004 fails on deny, HOST-PAM-002 on unlock_time.
		f.Files["/etc/pam.d/common-auth"] = "auth required pam_faillock.so preauth deny=100 unlock_time=60\nauth [success=1 default=ignore] pam_unix.so nullok\nauth [default=die] pam_faillock.so authfail deny=100 unlock_time=60\nauth requisite pam_deny.so\n"
		f.Files["/var/lib/dpkg/status"] += "\n\nPackage: mysql-server-5.7\nStatus: install ok installed\nVersion: 5.7.42-0ubuntu0.18.04.1\n"
	}, func(f *sys.Fake) {
		// auditd is running, so its rule files are loaded (HOST-AUD-002..007).
		f.Commands["systemctl is-active auditd"] = "active"
		f.Files["/var/lib/dpkg/status"] += "\n\nPackage: mysql-server-8.0\nStatus: install ok installed\nVersion: 8.0.39-0ubuntu0.24.04.2\n"
	})
}
