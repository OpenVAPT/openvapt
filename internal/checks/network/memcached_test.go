package network

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// C-08: loopback spellings pass, anything else fails, and the evidence is
// the real values.
func TestMemcachedListenAndUDP(t *testing.T) {
	cases := []struct {
		name, path, conf string
		want             check.Status
		ev               string
	}{
		{"localhost", "/etc/memcached.conf", "-l localhost\n-U 0\n", check.Pass, "-l localhost"},
		{"ipv6 loopback", "/etc/memcached.conf", "-l ::1\n-U 0\n", check.Pass, "-l ::1"},
		{"both loopbacks with port", "/etc/memcached.conf", "-l 127.0.0.1:11211,::1\n", check.Pass, "-l 127.0.0.1:11211,::1"},
		{"all interfaces", "/etc/memcached.conf", "-l 0.0.0.0\n-U 0\n", check.Fail, "-l 0.0.0.0"},
		{"udp on", "/etc/memcached.conf", "-l 127.0.0.1\n-U 11211\n", check.Fail, "-U 11211"},
		{"no listen", "/etc/memcached.conf", "-m 64\n", check.Fail, "no -l listen address"},
		{"sysconfig options", "/etc/sysconfig/memcached", "PORT=\"11211\"\nUSER=\"memcached\"\nOPTIONS=\"-l 127.0.0.1 -U 0\"\n", check.Pass, "options -l 127.0.0.1 -U 0"},
		{"sysconfig udp", "/etc/sysconfig/memcached", "OPTIONS=\"-l 127.0.0.1\"\nUDP_PORT=\"11211\"\n", check.Fail, "UDP_PORT 11211"},
	}
	for _, c := range cases {
		rs := check.Get("NET-DB-006").Run(context.Background(), &sys.Fake{Files: map[string]string{c.path: c.conf}})
		if len(rs) != 1 || rs[0].Status != c.want || !strings.Contains(strings.ToLower(strings.Join(rs[0].Evidence, "\n")), strings.ToLower(c.ev)) {
			t.Errorf("%s: want %s with evidence %q, got %+v", c.name, c.want, c.ev, rs)
		}
	}
}
