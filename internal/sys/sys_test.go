package sys

import "testing"

func TestAllowList(t *testing.T) {
	ok := [][]string{{"sshd", "-T"}, {"apt-get", "-s", "upgrade"}, {"php", "-r", "echo ini_get('expose_php');"}}
	bad := [][]string{
		{"rm", "-rf", "/"}, {"apt-get", "upgrade"}, {"apt-get", "install", "x"},
		{"systemctl", "restart", "sshd"}, {"php", "-r", "system('id');"},
		{"php", "-r", "echo ini_get('x'); system('id');"}, {"sh", "-c", "id"},
	}
	for _, c := range ok {
		if !IsAllowed(c[0], c[1:]) {
			t.Errorf("%v should be allowed", c)
		}
	}
	for _, c := range bad {
		if IsAllowed(c[0], c[1:]) {
			t.Errorf("%v must NOT be allowed", c)
		}
	}
}
