package host

import (
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/lab"
	"github.com/openvapt/openvapt/internal/sys"
)

func TestIPForwardContainerContext(t *testing.T) {
	if r := run(t, "HOST-KRN-005", lab.Vulnerable()); r.Status != check.Fail {
		t.Errorf("vulnerable lab: want Fail, got %v %q", r.Status, r.Message)
	}
	if r := run(t, "HOST-KRN-005", lab.Hardened()); r.Status != check.Pass {
		t.Errorf("hardened lab: want Pass, got %v %q", r.Status, r.Message)
	}
	r := run(t, "HOST-KRN-005", lab.ContainerHost())
	if r.Status != check.Pass || !strings.Contains(strings.Join(r.Evidence, " "), "container runtime detected") {
		t.Errorf("container host: want Pass with context, got %v %q %v", r.Status, r.Message, r.Evidence)
	}

	base := func() *sys.Fake {
		return &sys.Fake{Files: map[string]string{"/proc/sys/net/ipv4/ip_forward": "1"}, Infos: map[string]sys.FileInfo{}, Commands: map[string]string{}}
	}
	// Forwarding with no container runtime still fails.
	if r := run(t, "HOST-KRN-005", base()); r.Status != check.Fail {
		t.Errorf("no runtime: want Fail, got %v", r.Status)
	}
	// Runtime present, forwarded traffic accepted by default: fail.
	f := base()
	f.Infos["/run/containerd/containerd.sock"] = sys.FileInfo{Path: "/run/containerd/containerd.sock"}
	f.Commands["iptables -S"] = "-P INPUT DROP\n-P FORWARD ACCEPT\n"
	if r := run(t, "HOST-KRN-005", f); r.Status != check.Fail {
		t.Errorf("open forward: want Fail, got %v", r.Status)
	}
	// DOCKER-USER filtering counts as a filtered forward path.
	f.Commands["iptables -S"] += "-A DOCKER-USER -i eth0 -j DROP\n"
	if r := run(t, "HOST-KRN-005", f); r.Status != check.Pass {
		t.Errorf("docker-user: want Pass, got %v", r.Status)
	}
	// Docker's trailing "-j RETURN" after an inserted deny is still filtered.
	f.Commands["iptables -S"] = "-P INPUT DROP\n-P FORWARD ACCEPT\n-A DOCKER-USER -i eth0 -j DROP\n-A DOCKER-USER -j RETURN\n"
	if r := run(t, "HOST-KRN-005", f); r.Status != check.Pass {
		t.Errorf("docker-user with trailing RETURN: want Pass, got %v", r.Status)
	}
	// Only Docker's default RETURN: forwarded traffic is not filtered.
	f.Commands["iptables -S"] = "-P INPUT DROP\n-P FORWARD ACCEPT\n-A DOCKER-USER -j RETURN\n"
	if r := run(t, "HOST-KRN-005", f); r.Status != check.Fail {
		t.Errorf("docker-user RETURN only: want Fail, got %v", r.Status)
	}
	// nftables forward chain with policy drop.
	f = base()
	f.Files["/etc/kubernetes/kubelet.conf"] = ""
	f.Infos["/etc/kubernetes"] = sys.FileInfo{Path: "/etc/kubernetes", IsDir: true}
	f.Commands["nft list ruleset"] = "table inet filter {\n chain forward {\n  type filter hook forward priority 0; policy drop;\n }\n}\n"
	if r := run(t, "HOST-KRN-005", f); r.Status != check.Pass {
		t.Errorf("nft drop: want Pass, got %v", r.Status)
	}
	// Policy unreadable: incomplete, never a silent pass.
	delete(f.Commands, "nft list ruleset")
	if r := run(t, "HOST-KRN-005", f); r.Status != check.Incomplete {
		t.Errorf("unknown policy: want Incomplete, got %v", r.Status)
	}
}

func TestDockerUserDefaultDeny(t *testing.T) {
	for rule, want := range map[string]bool{
		"-A DOCKER-USER -j DROP":                                       true,
		"-A DOCKER-USER -j REJECT":                                     true,
		"-A DOCKER-USER -j REJECT --reject-with icmp-port-unreachable": true,
		"-A DOCKER-USER -s 203.0.113.9/32 -j DROP":                     false,
		"-A DOCKER-USER -i eth0 -j DROP":                               true,
		"-A DOCKER-USER -i eth0 -s 10.0.0.1 -j DROP":                   false,
		"-A DOCKER-USER -i ! eth0 -j DROP":                             false,
		"-A DOCKER-USER -j RETURN":                                     false,
		"":                                                             false,
	} {
		if got := dockerUserDefaultDeny(rule); got != want {
			t.Errorf("dockerUserDefaultDeny(%q) = %v, want %v", rule, got, want)
		}
	}
}
