package sys

import "testing"

func TestValidSSHDContext(t *testing.T) {
	good := []string{
		"user=root,host=localhost,addr=127.0.0.1",
		"user=alice,host=localhost,addr=10.0.0.0",
		"user=_svc-1,host=localhost,addr=2001:db8::",
	}
	for _, c := range good {
		if !ValidSSHDContext(c) || !IsAllowed("sshd", []string{"-T", "-C", c}) {
			t.Errorf("rejected %q", c)
		}
	}
	bad := []string{
		"", "user=root", "user=root,host=localhost",
		"user=root,host=evil.example,addr=127.0.0.1",
		"user=root;id,host=localhost,addr=127.0.0.1",
		"user=$(id),host=localhost,addr=127.0.0.1",
		"user=root`id`,host=localhost,addr=127.0.0.1",
		"user=Root,host=localhost,addr=127.0.0.1",
		"user=-oProxy,host=localhost,addr=127.0.0.1",
		"user=a b,host=localhost,addr=127.0.0.1",
		"user=root\n,host=localhost,addr=127.0.0.1",
		"user=root,host=localhost,addr=127.0.0.1\n",
		"user=abcdefghijklmnopqrstuvwxyz0123456,host=localhost,addr=127.0.0.1",
		"user=root,host=localhost,addr=10.0.0.0/8",
		"user=root,host=localhost,addr=127.0.0.1:22",
		"user=root,host=localhost,addr=fe80::1%eth0",
		"user=root,host=localhost,addr=2001:DB8::",
		"user=root,host=localhost,addr=010.0.0.1",
		"user=root,host=localhost,addr=127.0.0.1,laddr=1.2.3.4",
		"host=localhost,user=root,addr=127.0.0.1",
	}
	for _, c := range bad {
		if ValidSSHDContext(c) || IsAllowed("sshd", []string{"-T", "-C", c}) {
			t.Errorf("accepted %q", c)
		}
	}
	if IsAllowed("sshd", []string{"-T", "-C", "user=root,host=localhost,addr=127.0.0.1", "-f", "/tmp/x"}) {
		t.Error("extra arguments accepted")
	}
}
