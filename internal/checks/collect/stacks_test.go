package collect

import (
	"context"
	"io/fs"
	"reflect"
	"testing"

	"github.com/openvapt/openvapt/internal/sys"
)

func TestParseUFW(t *testing.T) {
	out := "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n" +
		"To                         Action      From\n--                         ------      ----\n" +
		"22/tcp                     LIMIT IN    Anywhere\n3306                       ALLOW IN    10.0.0.0/8\n" +
		"8000:8100/tcp              ALLOW IN    Anywhere\nApache Full                ALLOW IN    Anywhere\n" +
		"25/tcp                     DENY IN     Anywhere\n53                         ALLOW OUT   Anywhere\n443/tcp (v6)               ALLOW IN    Anywhere (v6)\n"
	got := parseUFW(out)
	want := []FWRule{
		{Engine: "ufw", Proto: "tcp", From: 22, To: 22, Source: "anywhere"},
		{Engine: "ufw", From: 3306, To: 3306, Source: "10.0.0.0/8"},
		{Engine: "ufw", Proto: "tcp", From: 8000, To: 8100, Source: "anywhere"},
		{Engine: "ufw", Proto: "tcp", From: 443, To: 443, Source: "anywhere"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		got[i].Raw = ""
		if got[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if !got[2].Covers("tcp6", 8050) || got[2].Covers("udp", 8050) || !got[1].Covers("udp", 3306) {
		t.Error("Covers does not honour protocol and range")
	}
}

func TestParseNFT(t *testing.T) {
	out := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		tcp dport { 22, 80, 443 } accept
		ip saddr 10.0.0.0/8 tcp dport 5432 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		tcp dport 8080 accept
	}
}`
	deny, rules := parseNFT(out)
	if !deny {
		t.Error("policy drop not detected")
	}
	var ports []int
	for _, r := range rules {
		ports = append(ports, r.From)
	}
	if !reflect.DeepEqual(ports, []int{22, 80, 443, 5432}) {
		t.Errorf("ports = %v (forward chain must be ignored)", ports)
	}
	if rules[3].Any() || rules[0].Source != "anywhere" {
		t.Errorf("sources wrong: %+v", rules)
	}
}

func TestParseIPTables(t *testing.T) {
	out := "-P INPUT DROP\n-A INPUT -i lo -p tcp --dport 6379 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443,8000:8010 -j ACCEPT\n" +
		"-A INPUT -s 192.0.2.10/32 -p tcp -m tcp --dport 3306 -j ACCEPT\n-A FORWARD -p tcp --dport 25 -j ACCEPT\n" +
		"-A ufw-user-input -p udp -m udp --dport 51820 -j ACCEPT\n-A INPUT -p tcp --dport 23 -j DROP\n"
	got := parseIPTables(out)
	if len(got) != 5 {
		t.Fatalf("got %d rules: %+v", len(got), got)
	}
	if got[2].To != 8010 || got[3].Source != "192.0.2.10/32" || got[4].Proto != "udp" {
		t.Errorf("unexpected rules: %+v", got)
	}
}

func TestPortRanges(t *testing.T) {
	if got := portRanges("22,80-81,x,70000,9000:8000"); !reflect.DeepEqual(got, [][2]int{{22, 22}, {80, 81}}) {
		t.Errorf("portRanges = %v", got)
	}
}

func TestUnitsMergeDropInsAndPrecedence(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/lib/systemd/system/app.service":                "[Service]\nExecStart=/usr/bin/app\nEnvironment=A=1\n",
		"/etc/systemd/system/app.service":                "[Service]\nExecStart=/usr/local/bin/app \\\n  --flag\nEnvironment=\"B=two words\" C=3\nUser=app\n",
		"/etc/systemd/system/app.service.d/10-env.conf":  "[Service]\nEnvironment=\nEnvironment=TOKEN=x\n",
		"/etc/systemd/system/masked.service":             "",
		"/usr/lib/systemd/system/oneshot.service":        "[Service]\nType=oneshot\nExecStart=/bin/true\n",
		"/etc/systemd/system/app.service.d/20-user.conf": "[Service]\nUser=\n",
	}, Infos: map[string]sys.FileInfo{"/etc/systemd/system/masked.service": {Mode: fs.ModeSymlink | 0o777}}}
	us := Units(context.Background(), f)
	if len(us) != 2 {
		t.Fatalf("got %d units: %+v", len(us), us)
	}
	app := us[0]
	if app.Path != "/etc/systemd/system/app.service" || !app.Custom || len(app.DropIns) != 2 {
		t.Errorf("precedence or drop-ins wrong: %+v", app)
	}
	if app.Program() != "/usr/local/bin/app" || app.Get("service.execstart") != "/usr/local/bin/app    --flag" {
		t.Errorf("ExecStart = %q", app.Get("service.execstart"))
	}
	if env := app.Env(); !reflect.DeepEqual(env, map[string]string{"TOKEN": "x"}) {
		t.Errorf("empty Environment= must reset the list, got %v", env)
	}
	if !app.RunsAsRoot() {
		t.Error("User= reset by a drop-in means root")
	}
	if us[1].LongRunning() {
		t.Error("oneshot units are not long-running")
	}
	if got := splitEnv(`"B=two words" C=3 'D=x y'`); !reflect.DeepEqual(got, []string{"B=two words", "C=3", "D=x y"}) {
		t.Errorf("splitEnv = %q", got)
	}
}

func TestXMLElementsIgnoresComments(t *testing.T) {
	doc := `<Server port="-1"><!-- <Connector port="8009" protocol="AJP/1.3"/> -->
<Connector port='8080' address="127.0.0.1"
  protocol="HTTP/1.1"/></Server>`
	cs := XMLElements(doc, "Connector")
	if len(cs) != 1 || cs[0]["port"] != "8080" || cs[0]["address"] != "127.0.0.1" || cs[0]["protocol"] != "HTTP/1.1" {
		t.Errorf("XMLElements = %+v", cs)
	}
}

// Negated sources admit everyone else; negated ports, loopback-only rules and
// trailing comments must be read the way the kernel applies them.
func TestFirewallNegationAndComments(t *testing.T) {
	ipt := parseIPTables("-A INPUT ! -s 10.0.0.0/8 -p tcp --dport 3306 -j ACCEPT\n-A INPUT -p tcp ! --dport 22 -j ACCEPT\n-A INPUT ! -i lo -p tcp --dport 80 -j ACCEPT\n")
	if len(ipt) != 2 || !ipt[0].Any() || ipt[1].From != 80 {
		t.Errorf("iptables negation: %+v", ipt)
	}
	_, nft := parseNFT("chain input {\n type filter hook input priority 0; policy drop;\n ip saddr != 10.0.0.0/8 tcp dport 3306 accept\n tcp dport 22 accept comment \"ssh\"\n iifname \"lo\" tcp dport 8080 accept\n}")
	if len(nft) != 2 || !nft[0].Any() || nft[1].From != 22 {
		t.Errorf("nftables negation, comments and loopback: %+v", nft)
	}
	ufw := parseUFW("Status: active\n\nTo                         Action      From\n--                         ------      ----\n8080/tcp on lo             ALLOW IN    Anywhere\n80/tcp on eth0             ALLOW IN    Anywhere\n")
	if len(ufw) != 1 || ufw[0].From != 80 {
		t.Errorf("ufw interface rules: %+v", ufw)
	}
}

func TestDropInsSortAcrossDirectories(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/lib/systemd/system/x.service":                    "[Service]\nExecStart=/usr/bin/x\n",
		"/etc/systemd/system/x.service.d/05-user.conf":     "[Service]\nUser=app\n",
		"/usr/lib/systemd/system/x.service.d/10-root.conf": "[Service]\nUser=root\n",
		"/usr/lib/systemd/system/x.service.d/05-user.conf": "[Service]\nUser=ignored\n",
	}}
	u := Units(context.Background(), f)[0]
	if !u.RunsAsRoot() || len(u.DropIns) != 2 {
		t.Errorf("drop-ins must apply by file name across directories: %v user=%q", u.DropIns, u.Get("service.user"))
	}
}

func TestPortlessAcceptOnInterfaceOrSetIsRestricted(t *testing.T) {
	ipt := parseIPTables("-A INPUT -i wg0 -j ACCEPT\n-A INPUT -m set --match-set trusted src -j ACCEPT\n-A INPUT -m set ! --match-set blocked src -j ACCEPT\n-A INPUT ! -i eth0 -j ACCEPT\n")
	want := []string{"interface wg0", "ipset trusted", "anywhere", "anywhere"}
	if len(ipt) != len(want) {
		t.Fatalf("iptables rules: %+v", ipt)
	}
	for i, w := range want {
		if ipt[i].Source != w || ipt[i].From != 1 || ipt[i].To != 65535 {
			t.Errorf("iptables rule %d: want source %q, got %+v", i, w, ipt[i])
		}
	}
	_, nft := parseNFT("chain input {\n type filter hook input priority 0; policy drop;\n iifname \"docker0\" accept\n ip saddr @allowed accept\n iifname != \"eth0\" accept\n meta l4proto tcp accept\n}")
	wantN := []string{"interface docker0", "set @allowed", "anywhere"}
	if len(nft) != len(wantN) {
		t.Fatalf("nft rules: %+v", nft)
	}
	for i, w := range wantN {
		if nft[i].Source != w {
			t.Errorf("nft rule %d: want source %q, got %+v", i, w, nft[i])
		}
	}
}
