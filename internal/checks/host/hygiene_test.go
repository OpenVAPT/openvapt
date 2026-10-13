package host

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// runOnHost runs a check and returns every result (for checks that report
// one result per file).
func runOnHost(t *testing.T, id string, f sys.System) []check.Result {
	t.Helper()
	c := check.Get(id)
	if c == nil {
		t.Fatalf("%s not registered", id)
	}
	return c.Run(context.Background(), f)
}

func hygieneFake() *sys.Fake {
	return &sys.Fake{Files: map[string]string{}, Infos: map[string]sys.FileInfo{}}
}

func TestSecretsInWorldReadableFiles(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		mode             fs.FileMode
		want             check.Status
	}{
		{"password in world-readable conf", "/etc/app/db.conf", "password=hunter2secret\n", 0o644, check.Fail},
		{"private key", "/etc/backup/key.pem", "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n", 0o644, check.Fail},
		{"aws key", "/etc/app/.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", 0o644, check.Fail},
		{"token in yaml", "/etc/app/config.yml", "api_key: 0123456789abcdef\n", 0o644, check.Fail},
		{"same file but mode 640", "/etc/app/db.conf", "password=hunter2secret\n", 0o640, check.Pass},
		{"placeholder value is skipped", "/etc/app/db.conf", "password=${DB_PASSWORD}\n", 0o644, check.Pass},
		{"non-config name is not read", "/etc/app/notes.txt", "password=hunter2secret\n", 0o644, check.Pass},
		{"empty password is skipped", "/etc/app/db.conf", "password=\n", 0o644, check.Pass},
	} {
		f := hygieneFake()
		f.Files[tc.path] = tc.text
		f.Infos[tc.path] = sys.FileInfo{Path: tc.path, Mode: tc.mode, Size: int64(len(tc.text))}
		got := run(t, "HOST-SEC-001", f)
		if got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
		for _, e := range got.Evidence {
			if strings.Contains(e, "hunter2") || strings.Contains(e, "AKIA") {
				t.Errorf("%s: evidence leaks the value: %q", tc.name, e)
			}
		}
	}
	// Partial walk without findings is incomplete, never pass.
	f := hygieneFake()
	f.IncompleteWalks = map[string]bool{"/etc": true}
	if got := run(t, "HOST-SEC-001", f); got.Status != check.Incomplete {
		t.Errorf("partial walk: got %s, want incomplete", got.Status)
	}
}

func TestAuthorizedKeysHygiene(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		mode       fs.FileMode
		want       check.Status
	}{
		{"unrestricted root key", "ssh-ed25519 AAAAC3 root@laptop\n", 0o600, check.Fail},
		{"from= restriction", "from=\"203.0.113.0/24\" ssh-ed25519 AAAAC3 admin\n", 0o600, check.Pass},
		{"command= restriction", "command=\"/usr/local/bin/backup\",restrict ssh-ed25519 AAAAC3 backup\n", 0o600, check.Pass},
		{"restricted but world readable", "from=\"203.0.113.0/24\" ssh-ed25519 AAAAC3 admin\n", 0o644, check.Fail},
		{"restricted but group writable", "from=\"203.0.113.0/24\" ssh-ed25519 AAAAC3 admin\n", 0o620, check.Fail},
		{"comments and blanks only", "# no keys yet\n\n", 0o600, check.Pass},
	} {
		f := hygieneFake()
		f.Files["/root/.ssh/authorized_keys"] = tc.text
		f.Infos["/root/.ssh/authorized_keys"] = sys.FileInfo{Path: "/root/.ssh/authorized_keys", Mode: tc.mode}
		if got := run(t, "HOST-SSH-013", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// A user's writable authorized_keys fails even with no root file.
	f := hygieneFake()
	f.Files["/home/dev/.ssh/authorized_keys"] = "ssh-ed25519 AAAAC3 dev\n"
	f.Infos["/home/dev/.ssh/authorized_keys"] = sys.FileInfo{Path: "/home/dev/.ssh/authorized_keys", Mode: 0o666}
	if got := run(t, "HOST-SSH-013", f); got.Status != check.Fail {
		t.Errorf("user writable file: got %s, want fail", got.Status)
	}
	f.Infos["/home/dev/.ssh/authorized_keys"] = sys.FileInfo{Path: "/home/dev/.ssh/authorized_keys", Mode: 0o600}
	if got := run(t, "HOST-SSH-013", f); got.Status != check.Pass {
		t.Errorf("user key without options is fine: got %s, want pass", got.Status)
	}
	if got := run(t, "HOST-SSH-013", hygieneFake()); got.Status != check.Skip {
		t.Errorf("no files: got %s, want skip", got.Status)
	}
}

func TestCronCommandsParser(t *testing.T) {
	cmds, path := cronCommands("# comment\nPATH=/usr/bin:/bin\nSHELL=/bin/sh\n* * * * * root /usr/local/bin/a.sh --flag\n@reboot root /opt/b start\n0 1 * * * root\n", true)
	if path != "/usr/bin:/bin" {
		t.Errorf("PATH = %q", path)
	}
	if len(cmds) != 2 || cmds[0] != "/usr/local/bin/a.sh --flag" || cmds[1] != "/opt/b start" {
		t.Errorf("commands = %q", cmds)
	}
	cmds, _ = cronCommands("*/5 * * * * /home/me/job.sh\n", false)
	if len(cmds) != 1 || cmds[0] != "/home/me/job.sh" {
		t.Errorf("user crontab commands = %q", cmds)
	}
}

func TestCronWorldWritablePrograms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fileMode fs.FileMode
		dirMode  fs.FileMode
		want     check.Status
	}{
		{"root-owned 755 in 755 folder", 0o755, fs.ModeDir | 0o755, check.Pass},
		{"world-writable script", 0o777, fs.ModeDir | 0o755, check.Fail},
		{"script in world-writable folder", 0o755, fs.ModeDir | 0o777, check.Fail},
		{"script in sticky world-writable folder", 0o755, fs.ModeDir | fs.ModeSticky | 0o777, check.Pass},
	} {
		f := hygieneFake()
		f.Files["/etc/crontab"] = "0 3 * * * root /opt/jobs/backup.sh\n"
		f.Infos["/opt/jobs/backup.sh"] = sys.FileInfo{Path: "/opt/jobs/backup.sh", Mode: tc.fileMode}
		f.Infos["/opt/jobs"] = sys.FileInfo{Path: "/opt/jobs", Mode: tc.dirMode, IsDir: true}
		if got := run(t, "HOST-CRON-001", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// Scripts in cron.daily are checked too; a job with no absolute path skips.
	f := hygieneFake()
	f.Files["/etc/cron.daily/logrotate"] = "#!/bin/sh\n"
	f.Infos["/etc/cron.daily/logrotate"] = sys.FileInfo{Path: "/etc/cron.daily/logrotate", Mode: 0o777}
	if got := run(t, "HOST-CRON-001", f); got.Status != check.Fail {
		t.Errorf("cron.daily world-writable: got %s, want fail", got.Status)
	}
	f = hygieneFake()
	f.Files["/etc/crontab"] = "0 3 * * * root backup-db\n"
	if got := run(t, "HOST-CRON-001", f); got.Status != check.Skip {
		t.Errorf("no absolute paths: got %s, want skip", got.Status)
	}
}

func TestCronPathHijack(t *testing.T) {
	dirs := func(f *sys.Fake, mode fs.FileMode, paths ...string) {
		for _, p := range paths {
			f.Infos[p] = sys.FileInfo{Path: p, Mode: fs.ModeDir | mode, IsDir: true}
		}
	}
	for _, tc := range []struct {
		name, crontab string
		setup         func(f *sys.Fake)
		want          check.Status
	}{
		{"clean path", "PATH=/usr/bin:/bin\n", func(f *sys.Fake) { dirs(f, 0o755, "/usr/bin", "/bin") }, check.Pass},
		{"world-writable folder", "PATH=/opt/scripts:/usr/bin\n", func(f *sys.Fake) { dirs(f, 0o755, "/usr/bin"); dirs(f, 0o777, "/opt/scripts") }, check.Fail},
		{"sticky folder is fine", "PATH=/opt/scripts:/usr/bin\n", func(f *sys.Fake) { dirs(f, 0o755, "/usr/bin"); dirs(f, fs.ModeSticky|0o777, "/opt/scripts") }, check.Pass},
		{"relative entry", "PATH=.:/usr/bin\n", func(f *sys.Fake) { dirs(f, 0o755, "/usr/bin") }, check.Fail},
		{"empty entry", "PATH=/usr/bin::/bin\n", func(f *sys.Fake) { dirs(f, 0o755, "/usr/bin", "/bin") }, check.Fail},
		{"default path when unset", "", func(f *sys.Fake) { dirs(f, 0o755, "/usr/bin", "/bin") }, check.Pass},
		{"folder cannot be checked", "PATH=/usr/bin:/bin\n", func(f *sys.Fake) { dirs(f, 0o755, "/usr/bin") }, check.Incomplete},
		{"environment path", "PATH=/usr/bin\n", func(f *sys.Fake) {
			dirs(f, 0o755, "/usr/bin")
			dirs(f, 0o777, "/srv/tools")
			f.Files["/etc/environment"] = "PATH=\"/srv/tools:/usr/bin\"\n"
		}, check.Fail},
	} {
		f := hygieneFake()
		f.Files["/etc/crontab"] = tc.crontab + "0 3 * * * root backup-db\n"
		tc.setup(f)
		if got := run(t, "HOST-CRON-002", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	if got := run(t, "HOST-CRON-002", hygieneFake()); got.Status != check.Skip {
		t.Errorf("no crontab: got %s, want skip", got.Status)
	}
}

func TestDuplicateGroupsAndNames(t *testing.T) {
	passwd := "root:x:0:0::/root:/bin/sh\ndeploy:x:1000:1000::/home/deploy:/bin/sh\n"
	for _, tc := range []struct {
		name, group, passwd string
		want                check.Status
	}{
		{"unique", "root:x:0:\ndeploy:x:1000:\n", passwd, check.Pass},
		{"duplicate gid", "root:x:0:\nadm:x:4:\nstaff:x:4:\n", passwd, check.Fail},
		{"duplicate group name", "root:x:0:\nadm:x:4:\nadm:x:5:\n", passwd, check.Fail},
		{"duplicate user name", "root:x:0:\n", passwd + "deploy:x:1001:1001::/home/d2:/bin/sh\n", check.Fail},
		{"nis plus lines ignored", "root:x:0:\n+::::\n+::::\n", passwd, check.Pass},
	} {
		f := hygieneFake()
		f.Files["/etc/group"] = tc.group
		f.Files["/etc/passwd"] = tc.passwd
		if got := run(t, "HOST-USR-008", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	f := hygieneFake()
	f.Files["/etc/passwd"] = passwd
	if got := run(t, "HOST-USR-008", f); got.Status != check.Incomplete {
		t.Errorf("group missing: got %s, want incomplete", got.Status)
	}
}

func TestPasswdShadowConsistency(t *testing.T) {
	for _, tc := range []struct {
		name, passwd, shadow string
		want                 check.Status
	}{
		{"consistent", "root:x:0:0::/root:/bin/sh\ndeploy:x:1000:1000::/home/deploy:/bin/sh\n", "root:!:1::::::\ndeploy:$6$x$y:1::::::\n", check.Pass},
		{"account without shadow entry", "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/root:/bin/sh\n", "root:!:1::::::\n", check.Fail},
		{"hash in passwd", "root:$6$x$y:0:0::/root:/bin/sh\n", "root:!:1::::::\n", check.Fail},
		{"orphan shadow entry", "root:x:0:0::/root:/bin/sh\n", "root:!:1::::::\nolduser:$6$x$y:1::::::\n", check.Fail},
		{"locked markers accepted", "root:x:0:0::/root:/bin/sh\nsvc:*:5:5::/:/bin/false\n", "root:!:1::::::\nsvc:*:1::::::\n", check.Pass},
	} {
		f := hygieneFake()
		f.Files["/etc/passwd"] = tc.passwd
		f.Files["/etc/shadow"] = tc.shadow
		if got := run(t, "HOST-USR-009", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	f := hygieneFake()
	f.Files["/etc/passwd"] = "root:x:0:0::/root:/bin/sh\n"
	if got := run(t, "HOST-USR-009", f); got.Status != check.Incomplete {
		t.Errorf("shadow unreadable: got %s, want incomplete", got.Status)
	}
}

func TestHomeDirectoryPermissions(t *testing.T) {
	passwd := "root:x:0:0::/root:/bin/bash\nsvc:x:999:999::/var/lib/svc:/usr/sbin/nologin\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n"
	for _, tc := range []struct {
		name string
		mode fs.FileMode
		want check.Status
	}{
		{"750", fs.ModeDir | 0o750, check.Pass},
		{"700", fs.ModeDir | 0o700, check.Pass},
		{"755", fs.ModeDir | 0o755, check.Fail},
		{"701", fs.ModeDir | 0o701, check.Fail},
	} {
		f := hygieneFake()
		f.Files["/etc/passwd"] = passwd
		f.Infos["/home/deploy"] = sys.FileInfo{Path: "/home/deploy", Mode: tc.mode, IsDir: true}
		if got := run(t, "HOST-USR-010", f); got.Status != tc.want {
			t.Errorf("%s: got %s (%s %v), want %s", tc.name, got.Status, got.Message, got.Evidence, tc.want)
		}
	}
	// Missing home: incomplete, not pass; UID_MIN from login.defs honoured.
	f := hygieneFake()
	f.Files["/etc/passwd"] = passwd
	if got := run(t, "HOST-USR-010", f); got.Status != check.Incomplete {
		t.Errorf("missing home: got %s, want incomplete", got.Status)
	}
	f.Files["/etc/login.defs"] = "UID_MIN 500\n"
	f.Files["/etc/passwd"] = "app:x:600:600::/opt/app:/bin/bash\n"
	f.Infos["/opt/app"] = sys.FileInfo{Path: "/opt/app", Mode: fs.ModeDir | 0o755, IsDir: true}
	if got := run(t, "HOST-USR-010", f); got.Status != check.Fail {
		t.Errorf("UID_MIN 500: got %s, want fail", got.Status)
	}
}
