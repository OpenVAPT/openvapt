package network

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// procTCP renders /proc/net/tcp with the given little-endian hex addresses.
func procTCP(socks ...[2]string) string {
	s := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for i, k := range socks {
		s += fmt.Sprintf("   %d: %s:%s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1000%d\n", i, k[0], k[1], i)
	}
	return s
}

func fakeSockets(tcp string) *sys.Fake {
	empty := procTCP()
	return &sys.Fake{Files: map[string]string{"/proc/net/tcp": tcp, "/proc/net/tcp6": empty, "/proc/net/udp": empty, "/proc/net/udp6": empty}}
}

// C-03: one socket yields at most one finding per check family, severity
// follows the service identity, and loopback bindings never fire.
func TestPortTiersAndExposure(t *testing.T) {
	const all, loop, private = "00000000", "0100007F", "0A00000A" // 0.0.0.0, 127.0.0.1, 10.0.0.10
	cases := []struct {
		name  string
		tcp   string
		fails map[string]string // check id -> substring expected in evidence
		pass  []string
	}{
		{"snmp is cleartext only", procTCP(), nil, []string{"NET-SVC-002", "NET-SVC-004", "NET-DB-001"}},
		{"docker api critical", procTCP([2]string{all, "0947"}), map[string]string{"NET-SVC-002": "Docker API without TLS, bound to all interfaces"}, []string{"NET-SVC-004", "NET-DB-001", "NET-APP-001", "NET-APP-002"}},
		{"node exporter medium on private address", procTCP([2]string{private, "238C"}), map[string]string{"NET-SVC-004": "Prometheus Node Exporter, bound to private address"}, []string{"NET-SVC-002"}},
		{"inspector high, app port medium, proxy noted", procTCP([2]string{all, "0050"}, [2]string{all, "240D"}, [2]string{all, "0BB8"}), map[string]string{"NET-APP-001": "Node.js inspector", "NET-APP-002": "a web server listens on port 80 or 443"}, []string{"NET-SVC-002", "NET-SVC-004"}},
		{"loopback never fires", procTCP([2]string{loop, "0947"}, [2]string{loop, "238C"}, [2]string{loop, "240D"}, [2]string{loop, "0BB8"}, [2]string{loop, "0CEA"}), nil, []string{"NET-SVC-002", "NET-SVC-004", "NET-APP-001", "NET-APP-002", "NET-DB-001"}},
	}
	for _, c := range cases {
		f := fakeSockets(c.tcp)
		for id, want := range c.fails {
			rs := check.Get(id).Run(context.Background(), f)
			if len(rs) != 1 || rs[0].Status != check.Fail || !strings.Contains(strings.Join(rs[0].Evidence, "\n"), want) {
				t.Errorf("%s: %s should fail with %q, got %+v", c.name, id, want, rs)
			}
		}
		for _, id := range c.pass {
			rs := check.Get(id).Run(context.Background(), f)
			if len(rs) != 1 || rs[0].Status != check.Pass {
				t.Errorf("%s: %s should pass, got %+v", c.name, id, rs)
			}
		}
	}
	// Severity is derived from identity: the tiers never overlap.
	for p := range controlPorts {
		if _, dup := managementPorts[p]; dup {
			t.Errorf("port %d is in both control and management tiers", p)
		}
		if _, dup := dataPorts[p]; dup {
			t.Errorf("port %d is in both control and data tiers", p)
		}
	}
	for p := range codePorts {
		if _, dup := appPorts[p]; dup {
			t.Errorf("port %d is in both code and app tiers", p)
		}
	}
	if _, snmp := controlPorts[161]; snmp {
		t.Error("SNMP must be rated once, by NET-SVC-001")
	}
	if check.Get("NET-SVC-004").Severity != check.Medium || check.Get("NET-APP-002").Severity != check.Medium {
		t.Error("management and app tiers must be Medium")
	}
	// Unreadable socket tables are Incomplete, never Pass.
	for _, id := range []string{"NET-SVC-002", "NET-SVC-004", "NET-APP-001", "NET-APP-002"} {
		rs := check.Get(id).Run(context.Background(), &sys.Fake{})
		if len(rs) != 1 || rs[0].Status != check.Incomplete {
			t.Errorf("%s without /proc/net: want Incomplete, got %+v", id, rs)
		}
	}
}
