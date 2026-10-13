package host

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func run(t *testing.T, id string, f *sys.Fake) check.Result {
	t.Helper()
	c := check.Get(id)
	if c == nil {
		t.Fatalf("%s not registered", id)
	}
	r := c.Run(context.Background(), f)
	if len(r) != 1 {
		t.Fatalf("%s: want one result, got %+v", id, r)
	}
	return r[0]
}

func TestSSHParserKeyValueMatchAndRelativeInclude(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/etc/ssh/sshd_config": "Include sshd_config.d/*.conf\nPermitRootLogin=no\nPasswordAuthentication no\n" +
			"Match User backup\n  PasswordAuthentication yes\n  PermitRootLogin yes\n",
		"/etc/ssh/sshd_config.d/10-a.conf": "X11Forwarding=yes\nPermitRootLogin yes\n",
	}}
	cfg, ok := collect.SSHD(context.Background(), f)
	if !ok {
		t.Fatal("config not parsed")
	}
	// The relative Include is resolved under /etc/ssh and read first, so its
	// PermitRootLogin wins (sshd uses the first value).
	if cfg["permitrootlogin"] != "yes" || cfg["x11forwarding"] != "yes" {
		t.Errorf("include not applied: %v", cfg)
	}
	if cfg["passwordauthentication"] != "no" {
		t.Errorf("Match block overrode a global value: %v", cfg)
	}
	if cfg["match:passwordauthentication"] != "yes" {
		t.Errorf("Match block value not recorded: %v", cfg)
	}
}

func TestSSHForwardingDefaultsAndValues(t *testing.T) {
	base := "AllowTcpForwarding no\nAllowAgentForwarding no\n"
	for _, tc := range []struct {
		extra string
		fail  bool
	}{
		{"", false}, // GatewayPorts and PermitTunnel default to no
		{"PermitTunnel point-to-point\n", true},
		{"PermitTunnel ethernet\n", true},
		{"GatewayPorts clientspecified\n", true},
		{"GatewayPorts no\nPermitTunnel no\n", false},
	} {
		f := &sys.Fake{Files: map[string]string{"/etc/ssh/sshd_config": base + tc.extra}}
		if got := run(t, "HOST-SSH-007", f).Status == check.Fail; got != tc.fail {
			t.Errorf("%q: fail=%v, want %v", tc.extra, got, tc.fail)
		}
	}
}

func TestSSHAuthenticationSecondFactor(t *testing.T) {
	for _, tc := range []struct {
		cfg  string
		fail bool
	}{
		{"LoginGraceTime 30\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n", false},
		{"LoginGraceTime 30\nPasswordAuthentication yes\n", true},
		{"LoginGraceTime 30\nPasswordAuthentication yes\nAuthenticationMethods publickey,password\n", false},
		{"LoginGraceTime 30\nKbdInteractiveAuthentication yes\nPasswordAuthentication no\nAuthenticationMethods publickey keyboard-interactive\n", true},
		{"LoginGraceTime 120\nPasswordAuthentication no\n", true},
	} {
		f := &sys.Fake{Files: map[string]string{"/etc/ssh/sshd_config": tc.cfg}}
		if got := run(t, "HOST-SSH-008", f).Status == check.Fail; got != tc.fail {
			t.Errorf("%q: fail=%v, want %v", tc.cfg, got, tc.fail)
		}
	}
}

func TestSSHRSASHA1HostKeyAlgorithm(t *testing.T) {
	f := &sys.Fake{Commands: map[string]string{"sshd -T": "permitrootlogin no\nciphers aes128-gcm@openssh.com\nhostkeyalgorithms ssh-ed25519,ssh-rsa\n"}}
	if r := run(t, "HOST-SSH-004", f); r.Status != check.Fail {
		t.Errorf("ssh-rsa host key algorithm should fail: %+v", r)
	}
	f.Commands["sshd -T"] = "permitrootlogin no\nciphers aes128-gcm@openssh.com\nhostkeyalgorithms ssh-ed25519,rsa-sha2-512\n"
	if r := run(t, "HOST-SSH-004", f); r.Status != check.Pass {
		t.Errorf("rsa-sha2-512 should pass: %+v", r)
	}
}

func TestSysctlPerInterface(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/proc/sys/net/ipv4/conf/all/accept_redirects":      "0",
		"/proc/sys/net/ipv4/conf/default/accept_redirects":  "0",
		"/proc/sys/net/ipv4/conf/eth0/accept_redirects":     "0",
		"/proc/sys/net/ipv4/conf/eth0.100/accept_redirects": "1",
	}}
	r := run(t, "HOST-KRN-006", f)
	if r.Status != check.Fail || len(r.Evidence) != 1 || r.Evidence[0] != "net/ipv4/conf/eth0.100/accept_redirects = 1 (all = 0)" {
		t.Errorf("per-interface value missed: %+v", r)
	}
	f.Files["/proc/sys/net/ipv4/conf/eth0.100/accept_redirects"] = "0"
	if r := run(t, "HOST-KRN-006", f); r.Status != check.Pass {
		t.Errorf("all hardened should pass: %+v", r)
	}
	f.Files["/proc/sys/net/ipv4/conf/default/accept_redirects"] = "1"
	if r := run(t, "HOST-KRN-006", f); r.Status != check.Fail {
		t.Errorf("default value missed: %+v", r)
	}
	if r := run(t, "HOST-KRN-017", &sys.Fake{}); r.Status != check.Skip {
		t.Errorf("missing parameter should skip: %+v", r)
	}
}

func TestOSEOLEdges(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		id, ver    string
		bad, known bool
	}{
		{"ubuntu", "14.04", true, true}, // older than the oldest row
		{"debian", "8", true, true},
		{"fedora", "38", true, true},
		{"ubuntu", "24.04", false, true},
		{"ubuntu", "26.04", false, true},
		{"ubuntu", "25.10", true, true}, // ended 2026-07
		{"rhel", "10.1", false, true},
		{"ol", "9.4", false, true},
		{"centos", "9", false, true},
		{"fedora", "42", true, true},
		{"fedora", "43", true, true},  // ends about 2026-12-09: inside the 90-day window
		{"fedora", "44", false, true}, // about 2027-05
		{"centos", "10", false, true}, // CentOS Stream 10, about 2030-01-01
		{"amzn", "2017.09", true, true},
		{"amzn", "2016.09", true, true},
		{"amzn", "2018.03", true, true},
		{"amzn", "2", true, true}, // ended 2026-06-30
		{"amzn", "2023", false, true},
		{"ubuntu", "30.04", false, false}, // newer than the table: unknown
		{"arch", "", false, false},
	} {
		_, bad, known, _ := osEOL(tc.id, tc.ver, now)
		if bad != tc.bad || known != tc.known {
			t.Errorf("%s %s: bad=%v known=%v, want %v %v", tc.id, tc.ver, bad, known, tc.bad, tc.known)
		}
	}
	// Within the 90-day planning window.
	_, bad, _, left := osEOL("debian", "11", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if !bad || left < 0 || left > 90 {
		t.Errorf("debian 11 near end of support: bad=%v left=%d", bad, left)
	}
}

func TestOSEOLOlderReleaseFails(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{"/etc/os-release": "ID=ubuntu\nVERSION_ID=\"14.04\"\nPRETTY_NAME=\"Ubuntu 14.04\"\n"}}
	if r := run(t, "HOST-OS-001", f); r.Status != check.Fail {
		t.Errorf("Ubuntu 14.04 should fail: %+v", r)
	}
}

func TestFirewallPortlessAccept(t *testing.T) {
	ctx := context.Background()
	ipt := &sys.Fake{Commands: map[string]string{"iptables -S": "-P INPUT DROP\n" +
		"-A INPUT -i lo -j ACCEPT\n" +
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		"-A INPUT -p icmp -j ACCEPT\n" +
		"-A INPUT -s 203.0.113.0/24 -j ACCEPT\n"}}
	fw := collect.ReadFirewall(ctx, ipt)
	if len(fw.Rules) != 1 || !fw.Rules[0].Covers("tcp", 3306) || fw.Rules[0].Any() {
		t.Errorf("iptables port-less accept: %+v", fw.Rules)
	}

	nft := &sys.Fake{Commands: map[string]string{"nft list ruleset": "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n" +
		"  ct state established,related accept\n  iif \"lo\" accept\n  meta l4proto icmp accept\n  iifname \"eth1\" accept\n }\n}\n"}}
	fw = collect.ReadFirewall(ctx, nft)
	// An interface match restricts the rule to that interface's traffic; the
	// interface is recorded as the source.
	if len(fw.Rules) != 1 || !fw.Rules[0].Covers("udp", 11211) || fw.Rules[0].Any() || fw.Rules[0].Source != "interface eth1" {
		t.Errorf("nftables port-less accept: %+v", fw.Rules)
	}

	ufw := &sys.Fake{Commands: map[string]string{"ufw status verbose": "Status: active\nDefault: deny (incoming), allow (outgoing)\n\n" +
		"To                         Action      From\n--                         ------      ----\n" +
		"22/tcp                     ALLOW IN    Anywhere\nAnywhere                   ALLOW IN    198.51.100.7\n"}}
	fw = collect.ReadFirewall(ctx, ufw)
	found := false
	for _, r := range fw.Rules {
		if r.Source == "198.51.100.7" && r.Covers("tcp", 6379) {
			found = true
		}
	}
	if !found {
		t.Errorf("ufw Anywhere rule not treated as all ports: %+v", fw.Rules)
	}
}

func TestLockoutRequiresPreauthAuthfailAndDeny(t *testing.T) {
	for _, tc := range []struct {
		stack, conf string
		pass        bool
	}{
		{"auth required pam_faillock.so preauth\nauth required pam_unix.so\nauth [default=die] pam_faillock.so authfail\n", "", true},
		{"auth required pam_faillock.so preauth\nauth required pam_unix.so\n", "", false},
		{"auth required pam_faillock.so preauth\nauth [default=die] pam_faillock.so authfail\n", "deny = 50\n", false},
		{"auth required pam_faillock.so preauth deny=5\nauth [default=die] pam_faillock.so authfail deny=5\n", "deny = 50\n", true},
		{"auth required pam_tally2.so\n", "", false},
	} {
		f := &sys.Fake{Files: map[string]string{"/etc/pam.d/common-auth": tc.stack}}
		if tc.conf != "" {
			f.Files["/etc/security/faillock.conf"] = tc.conf
		}
		if got := run(t, "HOST-PWD-004", f).Status == check.Pass; got != tc.pass {
			t.Errorf("%q / %q: pass=%v, want %v", tc.stack, tc.conf, got, tc.pass)
		}
	}
}

func TestUIDMinFromLoginDefs(t *testing.T) {
	f := &sys.Fake{Files: map[string]string{
		"/etc/login.defs": "UID_MIN 500\n",
		"/etc/passwd":     "root:x:0:0::/root:/bin/bash\nalice:x:600:600::/home/alice:/bin/bash\n",
	}}
	if r := run(t, "HOST-USR-005", f); r.Status != check.Pass {
		t.Errorf("UID 600 is a human account when UID_MIN is 500: %+v", r)
	}
	delete(f.Files, "/etc/login.defs")
	if r := run(t, "HOST-USR-005", f); r.Status != check.Fail {
		t.Errorf("UID 600 is a system account with the default UID_MIN: %+v", r)
	}
}

func TestWorldWritableDirectory(t *testing.T) {
	f := &sys.Fake{
		Files: map[string]string{"/etc/cron.d": "", "/etc/tmpdir": ""},
		Infos: map[string]sys.FileInfo{
			"/etc/cron.d":  {Path: "/etc/cron.d", Mode: 0o777, IsDir: true},
			"/etc/tmpdir":  {Path: "/etc/tmpdir", Mode: 0o777 | fs.ModeSticky, IsDir: true},
			"/etc/hosts":   {Path: "/etc/hosts", Mode: 0o644},
			"/etc/passwd2": {Path: "/etc/passwd2", Mode: 0o644},
		},
	}
	r := run(t, "HOST-FS-003", f)
	if r.Status != check.Fail || len(r.Evidence) != 1 {
		t.Errorf("world-writable directory without sticky bit should be the only finding: %+v", r)
	}
}

func TestPasswordRotationIsInformational(t *testing.T) {
	c := check.Get("HOST-PWD-005")
	if c.Severity != check.Info {
		t.Fatalf("HOST-PWD-005 severity %s, want info", c.Severity)
	}
	for v, want := range map[string]check.Status{"90": check.Fail, "365": check.Pass, "99999": check.Pass} {
		f := &sys.Fake{Files: map[string]string{"/etc/login.defs": "PASS_MAX_DAYS " + v + "\n"}}
		if r := run(t, "HOST-PWD-005", f); r.Status != want {
			t.Errorf("PASS_MAX_DAYS %s: %s, want %s", v, r.Status, want)
		}
	}
}

func TestListenersWithoutIPv6Files(t *testing.T) {
	hdr := "  sl  local_address rem_address   st\n"
	f := &sys.Fake{Files: map[string]string{
		"/proc/net/tcp": hdr + "   0: 00000000:0016 00000000:0000 0A\n",
		"/proc/net/udp": hdr,
	}}
	ls, err := collect.Listeners(f)
	if err != nil || len(ls) != 1 || ls[0].Port != 22 {
		t.Errorf("missing tcp6/udp6 should mean no IPv6 sockets: %v %v", ls, err)
	}
	delete(f.Files, "/proc/net/tcp")
	if _, err := collect.Listeners(f); err == nil {
		t.Error("a missing IPv4 table must still be an error")
	}
}

func TestSSHMatchBlockIsConditionalFail(t *testing.T) {
	conf := "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nX11Forwarding no\n" +
		"AllowTcpForwarding no\nAllowAgentForwarding no\n" +
		"Match Address 10.0.0.0/8\n  PasswordAuthentication yes\n  X11Forwarding yes\n" +
		"Match User deploy\n  PermitRootLogin yes\n  PermitEmptyPasswords yes\n  AllowTcpForwarding yes\n"
	safe := "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nX11Forwarding no\nAllowTcpForwarding no\nAllowAgentForwarding no\nMatch User deploy\n  PasswordAuthentication no\n"
	want := map[string]string{
		"HOST-SSH-001": "match user deploy", "HOST-SSH-002": "match address 10.0.0.0/8", "HOST-SSH-003": "match user deploy",
		"HOST-SSH-005": "match address 10.0.0.0/8", "HOST-SSH-007": "match",
	}
	// sshd -T output (global context only) plus the files: the -T path must
	// still report Match blocks found in the files.
	tOut := "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npermitemptypasswords no\nx11forwarding no\nallowtcpforwarding no\nallowagentforwarding no\n"
	for _, viaT := range []bool{false, true} {
		for id, cond := range want {
			f := &sys.Fake{Files: map[string]string{"/etc/ssh/sshd_config": conf}}
			if viaT {
				f.Commands = map[string]string{"sshd -T": tOut}
			}
			r := run(t, id, f)
			if r.Status != check.Fail || len(r.Evidence) == 0 || !containsFold(r.Evidence[0], cond) {
				t.Errorf("%s (sshd -T %v): want conditional fail naming %q, got %+v", id, viaT, cond, r)
			}
			f = &sys.Fake{Files: map[string]string{"/etc/ssh/sshd_config": safe}}
			if viaT {
				f.Commands = map[string]string{"sshd -T": tOut}
			}
			if r := run(t, id, f); r.Status != check.Pass {
				t.Errorf("%s (sshd -T %v): a safe Match block must pass, got %+v", id, viaT, r)
			}
		}
	}
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func TestSysctlKernelCombination(t *testing.T) {
	conf := func(kv map[string]string) *sys.Fake {
		f := &sys.Fake{Files: map[string]string{}}
		for k, v := range kv {
			f.Files["/proc/sys/net/ipv4/"+k] = v
		}
		return f
	}
	cases := []struct {
		id   string
		kv   map[string]string
		want check.Status
	}{
		// rp_filter: max(all, iface).
		{"HOST-KRN-013", map[string]string{"conf/all/rp_filter": "1", "conf/default/rp_filter": "0", "conf/eth0/rp_filter": "0", "conf/lo/rp_filter": "0"}, check.Pass},
		{"HOST-KRN-013", map[string]string{"conf/all/rp_filter": "0", "conf/default/rp_filter": "2", "conf/eth0/rp_filter": "1"}, check.Pass},
		{"HOST-KRN-013", map[string]string{"conf/all/rp_filter": "0", "conf/default/rp_filter": "1", "conf/eth0/rp_filter": "0"}, check.Fail},
		// log_martians: all OR iface.
		{"HOST-KRN-014", map[string]string{"conf/all/log_martians": "1", "conf/default/log_martians": "0", "conf/eth0/log_martians": "0"}, check.Pass},
		{"HOST-KRN-014", map[string]string{"conf/all/log_martians": "0", "conf/default/log_martians": "1", "conf/eth0/log_martians": "1", "conf/lo/log_martians": "0"}, check.Pass},
		{"HOST-KRN-014", map[string]string{"conf/all/log_martians": "0", "conf/default/log_martians": "1", "conf/eth0/log_martians": "0"}, check.Fail},
		// accept_redirects without forwarding: all OR iface accepts.
		{"HOST-KRN-006", map[string]string{"ip_forward": "0", "conf/all/accept_redirects": "0", "conf/default/accept_redirects": "0", "conf/eth0/accept_redirects": "1"}, check.Fail},
		{"HOST-KRN-006", map[string]string{"ip_forward": "0", "conf/all/accept_redirects": "0", "conf/default/accept_redirects": "0", "conf/eth0/accept_redirects": "0", "conf/lo/accept_redirects": "1"}, check.Pass},
		// with forwarding: accepted only when all AND iface accept.
		{"HOST-KRN-006", map[string]string{"ip_forward": "1", "conf/all/accept_redirects": "0", "conf/default/accept_redirects": "1", "conf/eth0/accept_redirects": "1"}, check.Pass},
		{"HOST-KRN-006", map[string]string{"ip_forward": "0", "conf/all/accept_redirects": "1", "conf/default/accept_redirects": "0", "conf/eth0/forwarding": "1", "conf/eth0/accept_redirects": "0", "conf/default/forwarding": "0"}, check.Fail},
		{"HOST-KRN-006", map[string]string{"ip_forward": "1", "conf/all/accept_redirects": "1", "conf/default/accept_redirects": "1", "conf/eth0/accept_redirects": "0"}, check.Fail},
	}
	for i, c := range cases {
		if r := run(t, c.id, conf(c.kv)); r.Status != c.want {
			t.Errorf("case %d %s: want %s, got %+v", i, c.id, c.want, r)
		}
	}
}
