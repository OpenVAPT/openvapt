package host

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// fake builds a Fake with files, directory markers and command output.
func fake(files map[string]string, dirs []string, cmds map[string]string) *sys.Fake {
	f := &sys.Fake{Files: map[string]string{}, Infos: map[string]sys.FileInfo{}, Commands: map[string]string{}}
	for k, v := range files {
		f.Files[k] = v
	}
	for _, d := range dirs {
		f.Infos[d] = sys.FileInfo{Path: d, Mode: fs.ModeDir | 0o755, IsDir: true}
	}
	for k, v := range cmds {
		f.Commands[k] = v
	}
	return f
}

func want(t *testing.T, id string, f *sys.Fake, status check.Status, contains string) {
	t.Helper()
	r := run(t, id, f)
	if r.Status != status {
		t.Errorf("%s: got %s (%s %v), want %s", id, r.Status, r.Message, r.Evidence, status)
	}
	if contains != "" && !strings.Contains(r.Message+" "+strings.Join(r.Evidence, " "), contains) {
		t.Errorf("%s: output %q %v does not mention %q", id, r.Message, r.Evidence, contains)
	}
}

func TestAuditEnabledAtBoot(t *testing.T) {
	for _, tc := range []struct {
		out    string
		audit  bool
		status check.Status
	}{
		{"enabled\n", true, check.Pass},
		{"static", true, check.Pass},
		{"disabled", true, check.Fail},
		{"masked", true, check.Fail},
		{"enabled-runtime", true, check.Fail},
		{"", false, check.Skip},
		{"", true, check.Incomplete},
	} {
		cmds := map[string]string{}
		if tc.out != "" {
			cmds["systemctl is-enabled auditd"] = tc.out
		}
		var dirs []string
		if tc.audit {
			dirs = []string{"/etc/audit"}
		}
		want(t, "HOST-AUD-001", fake(nil, dirs, cmds), tc.status, "")
	}
}

func TestAuditRulesStates(t *testing.T) {
	// Not installed: skip. Installed with unreadable rules: incomplete.
	for _, id := range []string{"HOST-AUD-002", "HOST-AUD-003", "HOST-AUD-004", "HOST-AUD-005", "HOST-AUD-006", "HOST-AUD-007"} {
		want(t, id, fake(nil, nil, nil), check.Skip, "")
		f := fake(map[string]string{"/etc/audit/audit.rules": "-w /etc/passwd -p wa\n"}, []string{"/etc/audit"}, nil)
		f.IncompleteFiles = map[string]bool{"/etc/audit/audit.rules": true}
		want(t, id, f, check.Incomplete, "")
		// Installed with an empty rule set: fail.
		want(t, id, fake(map[string]string{"/etc/audit/audit.rules": "-D\n-b 8192\n"}, []string{"/etc/audit"}, nil), check.Fail, "")
	}
}

func TestAuditRuleMatching(t *testing.T) {
	full := "-w /etc/passwd -p wa -k id\n-w /etc/group -p wa -k id\n-w /etc/shadow -p wa -k id\n-w /etc/gshadow -p wa -k id\n-w /etc/sudoers -p wa -k id\n-w /etc/sudoers.d/ -p wa -k id\n" +
		"-w /var/log/lastlog -p wa\n-w /var/log/faillog -p wa\n-w /var/log/wtmp -p wa\n-w /var/log/btmp -p wa\n" +
		"-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time\n-w /etc/localtime -p wa\n" +
		"-a always,exit -F arch=b64 -S init_module,delete_module -k mod\n" +
		"-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k priv\n-e 2\n"
	for _, tc := range []struct {
		id     string
		rules  string
		status check.Status
		ev     string
	}{
		{"HOST-AUD-002", full, check.Pass, ""},
		{"HOST-AUD-002", strings.Replace(full, "-w /etc/shadow -p wa -k id\n", "", 1), check.Fail, "/etc/shadow"},
		{"HOST-AUD-002", "-a always,exit -F path=/etc/passwd -F perm=wa\n-w /etc/ -p wa\n-e 2\n", check.Pass, ""}, // directory watch covers children
		{"HOST-AUD-003", full, check.Pass, ""},
		{"HOST-AUD-003", strings.Replace(full, "-w /var/log/faillog -p wa\n", "", 1), check.Fail, "failed-login"},
		{"HOST-AUD-004", full, check.Pass, ""},
		{"HOST-AUD-004", strings.Replace(full, " -S clock_settime", "", 1), check.Fail, "clock_settime"},
		{"HOST-AUD-005", full, check.Pass, ""},
		{"HOST-AUD-005", strings.Replace(full, "-S init_module,delete_module", "-S init_module", 1), check.Fail, "delete_module"},
		{"HOST-AUD-005", "-w /usr/bin/kmod -p x -k modules\n-e 2\n", check.Pass, ""},
		{"HOST-AUD-006", full, check.Pass, ""},
		{"HOST-AUD-006", strings.Replace(full, " -F perm=x", "", 1), check.Fail, "perm=x"},
		{"HOST-AUD-007", full, check.Pass, ""},
		{"HOST-AUD-007", strings.Replace(full, "-e 2\n", "-e 1\n", 1), check.Fail, "-e 1"},
		{"HOST-AUD-007", "-e 2\n-w /etc/passwd -p wa\n", check.Fail, "not -e 2"},
	} {
		f := fake(map[string]string{"/etc/audit/rules.d/50-x.rules": tc.rules}, []string{"/etc/audit"}, nil)
		want(t, tc.id, f, tc.status, tc.ev)
	}
}

func TestAuditLogPermissions(t *testing.T) {
	mk := func(dirMode, fileMode fs.FileMode, uid int) *sys.Fake {
		f := fake(map[string]string{"/var/log/audit/audit.log": ""}, []string{"/etc/audit"}, nil)
		f.Infos["/var/log/audit"] = sys.FileInfo{Path: "/var/log/audit", Mode: fs.ModeDir | dirMode, IsDir: true}
		f.Infos["/var/log/audit/audit.log"] = sys.FileInfo{Path: "/var/log/audit/audit.log", Mode: fileMode, UID: uid}
		return f
	}
	want(t, "HOST-AUD-008", mk(0o750, 0o600, 0), check.Pass, "")
	want(t, "HOST-AUD-008", mk(0o750, 0o640, 0), check.Pass, "")
	want(t, "HOST-AUD-008", mk(0o755, 0o600, 0), check.Fail, "directory")
	want(t, "HOST-AUD-008", mk(0o750, 0o644, 0), check.Fail, "audit.log")
	want(t, "HOST-AUD-008", mk(0o750, 0o600, 1000), check.Fail, "uid 1000")
	want(t, "HOST-AUD-008", fake(nil, nil, nil), check.Skip, "")
	want(t, "HOST-AUD-008", fake(nil, []string{"/etc/audit"}, nil), check.Incomplete, "")
}

func TestAuditdConfFullDisk(t *testing.T) {
	good := "max_log_file_action = keep_logs\nspace_left_action = email\nadmin_space_left_action = halt\n"
	for _, tc := range []struct {
		conf   string
		status check.Status
		ev     string
	}{
		{good, check.Pass, ""},
		{"max_log_file_action = ROTATE\nspace_left_action = SYSLOG\nadmin_space_left_action = single\n", check.Pass, ""},
		{strings.Replace(good, "keep_logs", "ignore", 1), check.Fail, "max_log_file_action = ignore"},
		{strings.Replace(good, "email", "suspend", 1), check.Fail, "space_left_action = suspend"},
		{"max_log_file_action = keep_logs\n", check.Fail, "space_left_action is not set"},
	} {
		want(t, "HOST-AUD-009", fake(map[string]string{"/etc/audit/auditd.conf": tc.conf}, []string{"/etc/audit"}, nil), tc.status, tc.ev)
	}
	want(t, "HOST-AUD-009", fake(nil, nil, nil), check.Skip, "")
	want(t, "HOST-AUD-009", fake(nil, []string{"/etc/audit"}, nil), check.Incomplete, "")
	f := fake(map[string]string{"/etc/audit/auditd.conf": good}, []string{"/etc/audit"}, nil)
	f.IncompleteFiles = map[string]bool{"/etc/audit/auditd.conf": true}
	want(t, "HOST-AUD-009", f, check.Incomplete, "")
}

func TestJournaldStorage(t *testing.T) {
	for _, tc := range []struct {
		conf   string
		dir    bool
		status check.Status
		ev     string
	}{
		{"[Journal]\nStorage=persistent\n", false, check.Pass, ""},
		{"[Journal]\nStorage=auto\n", true, check.Pass, ""},
		{"[Journal]\n#Storage=auto\n", false, check.Fail, "no /var/log/journal"},
		{"[Journal]\nStorage=volatile\n", true, check.Fail, "volatile"},
		{"[Journal]\nStorage=persistent\nCompress=no\n", false, check.Fail, "Compress=no"},
		{"[Journal]\nStorage=persistent\nCompress=1M\n", false, check.Pass, ""},
	} {
		dirs := []string{"/etc/systemd"}
		if tc.dir {
			dirs = append(dirs, "/var/log/journal")
		}
		want(t, "HOST-AUD-010", fake(map[string]string{"/etc/systemd/journald.conf": tc.conf}, dirs, nil), tc.status, tc.ev)
	}
	// A drop-in overrides the main file.
	f := fake(map[string]string{"/etc/systemd/journald.conf": "[Journal]\nStorage=volatile\n", "/etc/systemd/journald.conf.d/10-p.conf": "[Journal]\nStorage=persistent\n"}, []string{"/etc/systemd"}, nil)
	want(t, "HOST-AUD-010", f, check.Pass, "")
	want(t, "HOST-AUD-010", fake(nil, nil, nil), check.Skip, "")
	want(t, "HOST-AUD-010", fake(nil, []string{"/etc/systemd"}, nil), check.Incomplete, "")
}

func TestRemoteLogForwarding(t *testing.T) {
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
	}{
		{map[string]string{"/etc/rsyslog.conf": "*.* /var/log/syslog\n"}, check.Fail},
		{map[string]string{"/etc/rsyslog.conf": "*.* /var/log/syslog\n#*.* @@logs:514\n"}, check.Fail},
		{map[string]string{"/etc/rsyslog.conf": "*.* @@logs.example.test:514\n"}, check.Pass},
		{map[string]string{"/etc/rsyslog.conf": "auth.* @10.0.0.1\n"}, check.Pass},
		{map[string]string{"/etc/rsyslog.d/90-r.conf": "*.* action(type=\"omfwd\" target=\"logs\" port=\"6514\")\n"}, check.Pass},
		{map[string]string{"/etc/syslog-ng/syslog-ng.conf": "destination d_net { network(\"logs\" port(514)); };\n"}, check.Pass},
		{map[string]string{"/etc/systemd/journal-upload.conf": "[Upload]\nURL=https://logs.example.test:19532\n"}, check.Pass},
		{map[string]string{"/etc/systemd/journal-upload.conf": "[Upload]\n# URL=\n"}, check.Fail},
		{nil, check.Fail},
	} {
		want(t, "HOST-AUD-011", fake(tc.files, nil, nil), tc.status, "")
	}
	f := fake(map[string]string{"/etc/rsyslog.conf": "*.* /var/log/syslog\n"}, nil, nil)
	f.IncompleteFiles = map[string]bool{"/etc/rsyslog.conf": true}
	want(t, "HOST-AUD-011", f, check.Incomplete, "")
	// The remote address never reaches the report.
	r := run(t, "HOST-AUD-011", fake(map[string]string{"/etc/rsyslog.conf": "*.* @@logs.example.test:514\n"}, nil, nil))
	if strings.Contains(r.Message+strings.Join(r.Evidence, ""), "logs.example.test") {
		t.Error("remote host leaked into the result")
	}
}

func TestPasswordQualityModule(t *testing.T) {
	stack := "/etc/pam.d/common-password"
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
		ev     string
	}{
		{map[string]string{stack: "password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so\n"}, check.Pass, ""},
		{map[string]string{stack: "password [success=1 default=ignore] pam_unix.so obscure\n"}, check.Fail, "no pam_pwquality"},
		{map[string]string{stack: "# password requisite pam_pwquality.so\npassword required pam_unix.so\n"}, check.Fail, "no pam_pwquality"},
		{map[string]string{stack: "password requisite pam_pwquality.so retry=3\n", "/etc/security/pwquality.conf": "dictcheck = 0\n"}, check.Fail, "dictcheck = 0"},
		{map[string]string{stack: "password requisite pam_pwquality.so retry=3 enforcing=0\n"}, check.Fail, "enforcing = 0"},
		{map[string]string{stack: "password requisite pam_pwquality.so retry=3\n", "/etc/security/pwquality.conf": "dictcheck = 1\nusercheck = 1\n"}, check.Pass, ""},
		{map[string]string{"/etc/pam.d/system-auth": "password requisite pam_pwquality.so\n"}, check.Pass, ""},
		{nil, check.Skip, ""},
	} {
		want(t, "HOST-PAM-001", fake(tc.files, nil, nil), tc.status, tc.ev)
	}
	f := fake(map[string]string{stack: "x"}, nil, nil)
	f.IncompleteFiles = map[string]bool{stack: true}
	want(t, "HOST-PAM-001", f, check.Incomplete, "")
}

func TestLockoutUnlockTime(t *testing.T) {
	auth := "/etc/pam.d/common-auth"
	withFaillock := "auth required pam_faillock.so preauth\nauth [success=1 default=ignore] pam_unix.so\nauth [default=die] pam_faillock.so authfail\n"
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
		ev     string
	}{
		{map[string]string{auth: withFaillock}, check.Fail, "unlock_time=600"}, // module default
		{map[string]string{auth: strings.Replace(withFaillock, "preauth", "preauth unlock_time=900", 1)}, check.Pass, "900"},
		{map[string]string{auth: strings.Replace(withFaillock, "preauth", "preauth unlock_time=0", 1)}, check.Pass, "0"},
		{map[string]string{auth: strings.Replace(withFaillock, "preauth", "preauth unlock_time=300", 1)}, check.Fail, "300"},
		{map[string]string{auth: withFaillock, "/etc/security/faillock.conf": "deny = 5\nunlock_time = 1800\n"}, check.Pass, "1800"},
		{map[string]string{auth: "auth required pam_unix.so\n"}, check.Fail, "No pam_faillock"},
		{nil, check.Skip, ""},
	} {
		want(t, "HOST-PAM-002", fake(tc.files, nil, nil), tc.status, tc.ev)
	}
}

func TestSuRestricted(t *testing.T) {
	for _, tc := range []struct {
		su     string
		status check.Status
	}{
		{"auth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid\n", check.Pass},
		{"auth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid group=sudo\n", check.Pass},
		{"auth sufficient pam_rootok.so\n# auth required pam_wheel.so\n", check.Fail},
		{"account required pam_wheel.so\n", check.Fail}, // wrong stack
	} {
		want(t, "HOST-PAM-003", fake(map[string]string{"/etc/pam.d/su": tc.su}, nil, nil), tc.status, "")
	}
	want(t, "HOST-PAM-003", fake(nil, nil, nil), check.Skip, "")
	f := fake(map[string]string{"/etc/pam.d/su": "x"}, nil, nil)
	f.IncompleteFiles = map[string]bool{"/etc/pam.d/su": true}
	want(t, "HOST-PAM-003", f, check.Incomplete, "")
}

func TestPasswordHistory(t *testing.T) {
	stack := "/etc/pam.d/common-password"
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
		ev     string
	}{
		{map[string]string{stack: "password required pam_pwhistory.so remember=5 use_authtok\npassword required pam_unix.so\n"}, check.Pass, "remember=5"},
		{map[string]string{stack: "password required pam_unix.so remember=10 yescrypt\n"}, check.Pass, "remember=10"},
		{map[string]string{stack: "password required pam_pwhistory.so remember=3\n"}, check.Fail, "remember=3"},
		{map[string]string{stack: "password required pam_unix.so yescrypt\n"}, check.Fail, "No remember"},
		{map[string]string{stack: "password required pam_pwhistory.so\n", "/etc/security/pwhistory.conf": "remember = 6\n"}, check.Pass, "remember=6"},
		{nil, check.Skip, ""},
	} {
		want(t, "HOST-PAM-004", fake(tc.files, nil, nil), tc.status, tc.ev)
	}
}

func TestLoginDefsAges(t *testing.T) {
	for _, tc := range []struct {
		id, defs string
		status   check.Status
	}{
		{"HOST-PAM-005", "PASS_MIN_DAYS 1\n", check.Pass},
		{"HOST-PAM-005", "PASS_MIN_DAYS 0\n", check.Fail},
		{"HOST-PAM-005", "UMASK 027\n", check.Fail},
		{"HOST-PAM-006", "PASS_WARN_AGE 7\n", check.Pass},
		{"HOST-PAM-006", "PASS_WARN_AGE 14\n", check.Pass},
		{"HOST-PAM-006", "PASS_WARN_AGE 3\n", check.Fail},
		{"HOST-PAM-006", "", check.Fail},
	} {
		want(t, tc.id, fake(map[string]string{"/etc/login.defs": tc.defs}, nil, nil), tc.status, "")
	}
	want(t, "HOST-PAM-005", fake(nil, nil, nil), check.Skip, "")
	f := fake(map[string]string{"/etc/login.defs": "PASS_MIN_DAYS 1\n"}, nil, nil)
	f.IncompleteFiles = map[string]bool{"/etc/login.defs": true}
	want(t, "HOST-PAM-005", f, check.Incomplete, "")
}

func TestInactiveDefault(t *testing.T) {
	for _, tc := range []struct {
		conf   string
		status check.Status
	}{
		{"INACTIVE=30\n", check.Pass},
		{"INACTIVE=0\n", check.Pass},
		{"INACTIVE=-1\n", check.Fail},
		{"INACTIVE=45\n", check.Fail},
		{"SHELL=/bin/bash\n", check.Fail},
		{"INACTIVE=abc\n", check.Incomplete},
	} {
		want(t, "HOST-PAM-007", fake(map[string]string{"/etc/default/useradd": tc.conf}, nil, nil), tc.status, "")
	}
	want(t, "HOST-PAM-007", fake(nil, nil, nil), check.Fail, "File not found")
	f := fake(map[string]string{"/etc/default/useradd": "INACTIVE=30\n"}, nil, nil)
	f.IncompleteFiles = map[string]bool{"/etc/default/useradd": true}
	want(t, "HOST-PAM-007", f, check.Incomplete, "")
}

func TestRootPath(t *testing.T) {
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
		ev     string
	}{
		{map[string]string{"/etc/environment": "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"}, check.Pass, ""},
		{map[string]string{"/root/.bashrc": "export PATH=.:/usr/bin\n"}, check.Fail, "entry ."},
		{map[string]string{"/root/.bashrc": "PATH=/usr/bin:\n"}, check.Fail, "trailing colon"},
		{map[string]string{"/root/.bashrc": "PATH=:/usr/bin\n"}, check.Fail, "leading colon"},
		{map[string]string{"/root/.bashrc": "PATH=/usr/bin::/bin\n"}, check.Fail, "doubled colon"},
		{map[string]string{"/root/.bashrc": "PATH=bin:/usr/bin\n"}, check.Fail, "relative entry bin"},
		{map[string]string{"/root/.bash_profile": "PATH=$PATH:$HOME/bin\nexport PATH\n"}, check.Pass, ""},
		{map[string]string{"/etc/profile": "umask 022\n"}, check.Incomplete, "No PATH"},
		{nil, check.Incomplete, ""},
	} {
		want(t, "HOST-PAM-008", fake(tc.files, nil, nil), tc.status, tc.ev)
	}
	f := fake(map[string]string{"/etc/environment": "PATH=/opt/tools/bin:/usr/bin\n"}, nil, nil)
	f.Infos["/opt/tools/bin"] = sys.FileInfo{Path: "/opt/tools/bin", Mode: fs.ModeDir | 0o777, IsDir: true}
	want(t, "HOST-PAM-008", f, check.Fail, "world-writable")
	f.Infos["/opt/tools/bin"] = sys.FileInfo{Path: "/opt/tools/bin", Mode: fs.ModeDir | 0o755, IsDir: true, UID: 1000}
	want(t, "HOST-PAM-008", f, check.Fail, "uid 1000")
}

func TestShellTimeout(t *testing.T) {
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
	}{
		{map[string]string{"/etc/profile.d/99-tmout.sh": "TMOUT=900\nreadonly TMOUT\nexport TMOUT\n"}, check.Pass},
		{map[string]string{"/etc/profile": "readonly TMOUT=600\n"}, check.Pass},
		{map[string]string{"/etc/bashrc": "export TMOUT=300\n"}, check.Pass},
		{map[string]string{"/etc/profile": "TMOUT=3600\n"}, check.Fail},
		{map[string]string{"/etc/profile": "TMOUT=0\n"}, check.Fail},
		{map[string]string{"/etc/profile": "# TMOUT=900\n"}, check.Fail},
		{map[string]string{"/etc/profile": "umask 022\n"}, check.Fail},
		{nil, check.Incomplete},
	} {
		want(t, "HOST-PAM-009", fake(tc.files, nil, nil), tc.status, "")
	}
}

func TestRepoSignatureChecks(t *testing.T) {
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
		ev     string
	}{
		{map[string]string{"/etc/apt/sources.list": "deb http://archive.ubuntu.com/ubuntu noble main\n"}, check.Pass, ""},
		{map[string]string{"/etc/apt/sources.list.d/x.list": "deb [arch=amd64 trusted=yes] http://repo.example.net/deb stable main\n"}, check.Fail, "repo.example.net"},
		{map[string]string{"/etc/apt/sources.list.d/x.sources": "Types: deb\nURIs: http://repo.example.net/deb\nSuites: stable\nTrusted: yes\n"}, check.Fail, "Trusted: yes"},
		{map[string]string{"/etc/apt/sources.list": "deb http://archive.ubuntu.com/ubuntu noble main\n", "/etc/apt/apt.conf.d/99x": "APT::Get::AllowUnauthenticated \"true\";\n"}, check.Fail, "AllowUnauthenticated"},
		{map[string]string{"/etc/apt/sources.list": "deb http://archive.ubuntu.com/ubuntu noble main\n", "/etc/apt/apt.conf.d/99x": "// APT::Get::AllowUnauthenticated \"true\";\n"}, check.Pass, ""},
		{map[string]string{"/etc/yum.repos.d/x.repo": "[x]\nname=x\nbaseurl=http://repo.example.net/el9\ngpgcheck=0\n"}, check.Fail, "x.gpgcheck=0"},
		{map[string]string{"/etc/yum.repos.d/x.repo": "[x]\nname=x\ngpgcheck=1\n[y]\ngpgcheck=1\n"}, check.Pass, ""},
		{map[string]string{"/etc/dnf/dnf.conf": "[main]\ngpgcheck=0\n"}, check.Fail, "main.gpgcheck=0"},
		{nil, check.Skip, ""},
	} {
		want(t, "HOST-PKG-002", fake(tc.files, nil, nil), tc.status, tc.ev)
	}
	f := fake(map[string]string{"/etc/apt/sources.list": "deb http://archive.ubuntu.com/ubuntu noble main\n"}, nil, nil)
	f.IncompleteFiles = map[string]bool{"/etc/apt/sources.list": true}
	want(t, "HOST-PKG-002", f, check.Incomplete, "")
}

func TestThirdPartyRepos(t *testing.T) {
	for _, tc := range []struct {
		files  map[string]string
		status check.Status
		ev     string
	}{
		{map[string]string{"/etc/apt/sources.list": "deb http://my.archive.ubuntu.com/ubuntu noble main\ndeb http://security.ubuntu.com/ubuntu noble-security main\n"}, check.Pass, ""},
		{map[string]string{"/etc/apt/sources.list.d/ppa.list": "deb http://ppa.launchpadcontent.net/x/ppa/ubuntu noble main\n"}, check.Fail, "ppa.launchpadcontent.net"},
		{map[string]string{"/etc/apt/sources.list.d/d.sources": "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: noble\n"}, check.Fail, "download.docker.com"},
		{map[string]string{"/etc/apt/sources.list": "deb cdrom:[Debian]/ bookworm main\n"}, check.Pass, ""},
		{map[string]string{"/etc/yum.repos.d/epel.repo": "[epel]\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=epel-9\n[x]\nbaseurl=https://pkgs.example.org/el9\n"}, check.Fail, "pkgs.example.org"},
		{nil, check.Skip, ""},
	} {
		want(t, "HOST-PKG-003", fake(tc.files, nil, nil), tc.status, tc.ev)
	}
}

func TestKernelChecks(t *testing.T) {
	status := func(names ...string) string {
		var b strings.Builder
		for _, n := range names {
			b.WriteString("Package: " + n + "\nStatus: install ok installed\nVersion: 1\n\n")
		}
		return b.String()
	}
	// Four kernels via dpkg status: too many; running one is old.
	f := fake(map[string]string{"/var/lib/dpkg/status": status("linux-image-6.8.0-40-generic", "linux-image-6.8.0-45-generic", "linux-image-6.8.0-9-generic", "linux-image-6.8.0-100-generic", "linux-image-generic")}, nil, map[string]string{"uname -r": "6.8.0-45-generic"})
	want(t, "HOST-PKG-004", f, check.Fail, "4 kernel")
	want(t, "HOST-PKG-005", f, check.Fail, "6.8.0-100-generic")
	// Two kernels via dpkg info lists; running the newest.
	f = fake(map[string]string{"/var/lib/dpkg/info/linux-image-6.8.0-40-generic.list": "", "/var/lib/dpkg/info/linux-image-6.8.0-45-generic.list": "", "/var/lib/dpkg/info/libc6:amd64.list": ""}, nil, map[string]string{"uname -r": "6.8.0-45-generic"})
	want(t, "HOST-PKG-004", f, check.Pass, "2 kernel")
	want(t, "HOST-PKG-005", f, check.Pass, "")
	// RHEL: rpm output, uname carries the architecture.
	rpm := "kernel-core\t0:5.14.0-427.13.1.el9_4\nkernel-core\t0:5.14.0-427.20.1.el9_4\nbash\t0:5.1.8-9.el9\n"
	f = fake(map[string]string{"/etc/os-release": "ID=rocky\n"}, nil, map[string]string{"rpm -qa --qf %{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n": rpm, "uname -r": "5.14.0-427.13.1.el9_4.x86_64"})
	want(t, "HOST-PKG-004", f, check.Pass, "")
	want(t, "HOST-PKG-005", f, check.Fail, "427.20.1")
	f.Commands["uname -r"] = "5.14.0-427.20.1.el9_4.x86_64"
	want(t, "HOST-PKG-005", f, check.Pass, "")
	// No package database: incomplete. No kernel packages: skip.
	f = fake(nil, nil, map[string]string{"uname -r": "6.8.0-45-generic"})
	want(t, "HOST-PKG-004", f, check.Incomplete, "")
	want(t, "HOST-PKG-005", f, check.Incomplete, "")
	f = fake(map[string]string{"/var/lib/dpkg/status": status("bash")}, nil, map[string]string{"uname -r": "6.8.0-45-generic"})
	want(t, "HOST-PKG-004", f, check.Skip, "")
	want(t, "HOST-PKG-005", f, check.Skip, "")
	f = fake(map[string]string{"/var/lib/dpkg/status": status("linux-image-6.8.0-45-generic")}, nil, nil)
	want(t, "HOST-PKG-005", f, check.Incomplete, "uname")
	if !kernelLess("6.8.0-9-generic", "6.8.0-45-generic") || kernelLess("6.8.0-45-generic", "6.8.0-9-generic") || !kernelLess("5.14.0-427.el9", "5.14.0-428.el9") {
		t.Error("kernelLess orders numerically")
	}
}

func TestPackageListRefresh(t *testing.T) {
	for _, tc := range []struct {
		files  map[string]string
		dirs   []string
		cmds   map[string]string
		status check.Status
	}{
		{map[string]string{"/etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Update-Package-Lists \"1\";\n"}, []string{"/etc/apt"}, nil, check.Pass},
		{map[string]string{"/etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Update-Package-Lists \"0\";\n"}, []string{"/etc/apt"}, nil, check.Fail},
		{nil, []string{"/etc/apt"}, map[string]string{"systemctl is-enabled apt-daily.timer": "enabled"}, check.Pass},
		{map[string]string{"/etc/systemd/system/timers.target.wants/apt-daily.timer": ""}, []string{"/etc/apt"}, nil, check.Pass},
		{nil, []string{"/etc/apt"}, map[string]string{"systemctl is-enabled apt-daily.timer": "disabled"}, check.Fail},
		{nil, []string{"/etc/yum.repos.d"}, map[string]string{"systemctl is-enabled dnf-makecache.timer": "enabled"}, check.Pass},
		{nil, []string{"/etc/yum.repos.d"}, nil, check.Fail},
		{nil, nil, nil, check.Skip},
	} {
		want(t, "HOST-PKG-006", fake(tc.files, tc.dirs, tc.cmds), tc.status, "")
	}
}

func TestLegacyServices(t *testing.T) {
	dpkg := func(names ...string) map[string]string {
		m := map[string]string{}
		for _, n := range names {
			m["/var/lib/dpkg/info/"+n+".list"] = ""
		}
		return m
	}
	// Installed package fails; enabled unit fails; clean system passes.
	want(t, "HOST-SVC-002", fake(dpkg("telnetd", "bash"), nil, nil), check.Fail, "package telnetd")
	want(t, "HOST-SVC-002", fake(mergeMaps(dpkg("bash"), map[string]string{"/etc/systemd/system/sockets.target.wants/telnet.socket": ""}), nil, nil), check.Fail, "unit telnet.socket")
	want(t, "HOST-SVC-002", fake(dpkg("bash"), nil, map[string]string{"systemctl is-enabled telnet.socket": "enabled"}), check.Fail, "telnet.socket")
	want(t, "HOST-SVC-002", fake(dpkg("bash"), nil, nil), check.Pass, "")
	for _, tc := range []struct{ id, pkg string }{
		{"HOST-SVC-003", "rsh-server"}, {"HOST-SVC-004", "tftpd-hpa"}, {"HOST-SVC-005", "vsftpd"}, {"HOST-SVC-006", "ypserv"},
		{"HOST-SVC-007", "cups"}, {"HOST-SVC-008", "rpcbind"}, {"HOST-SVC-009", "bind9"}, {"HOST-SVC-010", "samba"},
		{"HOST-SVC-011", "snmpd"}, {"HOST-SVC-012", "xinetd"},
	} {
		want(t, tc.id, fake(dpkg(tc.pkg), nil, nil), check.Fail, tc.pkg)
		want(t, tc.id, fake(dpkg("bash"), nil, nil), check.Pass, "")
	}
	// rpm database as the only source.
	want(t, "HOST-SVC-010", fake(nil, nil, map[string]string{"rpm -qa --qf %{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n": "samba\t0:4.19-1\n"}), check.Fail, "samba")
	// Nothing readable at all: incomplete. Units visible but no package data: incomplete, not pass.
	want(t, "HOST-SVC-002", fake(nil, nil, nil), check.Incomplete, "")
	want(t, "HOST-SVC-002", fake(nil, []string{"/etc/systemd/system"}, nil), check.Incomplete, "")
}

func mergeMaps(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
