// Package lab provides two simulated servers for learning and testing:
//
//   - Vulnerable: a deliberately misconfigured Ubuntu web server on which
//     every check should fail.
//   - Hardened: the same server after following each check's fix, on which
//     every check should pass or be skipped.
//
// "openvapt demo" scans these simulations, so anyone can see a full report
// without touching a real machine. The unit tests use them to prove that each
// check detects its weakness AND stays silent once the weakness is fixed.
// Nothing here touches the real system: it is all in memory.
package lab

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/sys"
)

const site = "shop.example.test"

// procTCP renders /proc/net/tcp lines for listening sockets.
// addr is the little-endian hex form the kernel prints, e.g. 00000000 = 0.0.0.0.
func procTCP(socks ...[2]string) string {
	s := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for i, k := range socks {
		s += fmt.Sprintf("   %d: %s:%s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1000%d\n", i, k[0], k[1], i)
	}
	return s
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

// Fixture adds files, metadata, command output or HTTP/TLS responses to a
// simulated server. Fixtures for related checks live in their own files
// (fixtures_*.go) and register themselves, so the labs grow with the checks.
type Fixture func(f *sys.Fake)

var vulnFixtures, hardFixtures []Fixture

// Register adds a pair of fixtures: one that introduces a weakness into the
// vulnerable lab, and one that adds the fixed configuration to the hardened
// lab. Called from init functions.
func Register(vulnerable, hardened Fixture) {
	vulnFixtures = append(vulnFixtures, vulnerable)
	hardFixtures = append(hardFixtures, hardened)
}

func apply(f *sys.Fake, fx []Fixture) *sys.Fake {
	if f.Files == nil {
		f.Files = map[string]string{}
	}
	if f.Infos == nil {
		f.Infos = map[string]sys.FileInfo{}
	}
	if f.Commands == nil {
		f.Commands = map[string]string{}
	}
	if f.HTTPResp == nil {
		f.HTTPResp = map[string]sys.HTTPResponse{}
	}
	if f.TLSResp == nil {
		f.TLSResp = map[string]sys.TLSInfo{}
	}
	if f.TLSCipherResp == nil {
		f.TLSCipherResp = map[string]sys.TLSInfo{}
	}
	for _, x := range fx {
		x(f)
	}
	return f
}

// Vulnerable returns the misconfigured simulation.
func Vulnerable() *sys.Fake { return apply(baseVulnerable(), vulnFixtures) }

// Hardened returns the same server after every fix has been applied.
func Hardened() *sys.Fake { return apply(baseHardened(), hardFixtures) }

func baseVulnerable() *sys.Fake {
	soon := time.Now().Add(9 * 24 * time.Hour)
	return &sys.Fake{
		Files: map[string]string{
			"/etc/os-release":                                 "PRETTY_NAME=\"Ubuntu 18.04.6 LTS\"\nID=ubuntu\nVERSION_ID=\"18.04\"\n",
			"/etc/passwd":                                     "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n",
			"/etc/shadow":                                     "root:$6$abc$hashedvalue:19000:0:99999:7:::\ndeploy::19000:0:99999:7:::\n",
			"/etc/sudoers":                                    "root ALL=(ALL:ALL) ALL\ndeploy ALL=(ALL) NOPASSWD: ALL\n",
			"/proc/sys/kernel/randomize_va_space":             "0",
			"/proc/sys/kernel/kptr_restrict":                  "0",
			"/proc/sys/kernel/dmesg_restrict":                 "0",
			"/proc/sys/fs/suid_dumpable":                      "2",
			"/proc/sys/net/ipv4/ip_forward":                   "1",
			"/proc/sys/net/ipv4/conf/all/accept_redirects":    "1",
			"/proc/sys/net/ipv4/conf/all/accept_source_route": "1",
			"/proc/sys/net/ipv4/tcp_syncookies":               "0",
			"/proc/sys/kernel/unprivileged_bpf_disabled":      "0",
			// 0.0.0.0 on 22, 80, 443, 3306 (MySQL), 6379 (Redis), 21 (FTP)
			"/proc/net/tcp": procTCP([2]string{"00000000", "0016"}, [2]string{"00000000", "0050"}, [2]string{"00000000", "01BB"},
				[2]string{"00000000", "0CEA"}, [2]string{"00000000", "18EB"}, [2]string{"00000000", "0015"}),
			"/proc/net/tcp6": procTCP(), "/proc/net/udp": procTCP(), "/proc/net/udp6": procTCP(),
			"/etc/apache2/sites-enabled/shop.conf": "<VirtualHost *:443>\n  ServerName " + site + "\n</VirtualHost>\n",
			"/etc/crontab":                         "* * * * * root /usr/local/bin/backup.sh\n",
		},
		Infos: map[string]sys.FileInfo{
			"/etc/shadow":            {Path: "/etc/shadow", Mode: 0o644},
			"/etc/passwd":            {Path: "/etc/passwd", Mode: 0o666},
			"/tmp":                   {Path: "/tmp", Mode: fs.ModeDir | 0o777, IsDir: true},
			"/etc/app/db.conf":       {Path: "/etc/app/db.conf", Mode: 0o666},
			"/home/deploy/.cache/sh": {Path: "/home/deploy/.cache/sh", Mode: fs.ModeSetuid | 0o755},
			"/etc/crontab":           {Path: "/etc/crontab", Mode: 0o666, UID: 0},
		},
		Commands: map[string]string{
			"sshd -T": "permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords yes\nx11forwarding yes\nmaxauthtries 10\n" +
				"ciphers aes128-cbc,aes256-ctr\nmacs hmac-md5,hmac-sha2-256\nkexalgorithms diffie-hellman-group1-sha1,curve25519-sha256\nhostkeyalgorithms ssh-rsa\n",
			"apt-get -s upgrade": "Inst openssl [1.1.1-1ubuntu2.1~18.04.20] (1.1.1-1ubuntu2.1~18.04.23 Ubuntu:18.04/bionic-security [amd64])\n" +
				"Inst sudo [1.8.21p2-3ubuntu1.4] (1.8.21p2-3ubuntu1.6 Ubuntu:18.04/bionic-security [amd64])\n",
			"iptables -S":                 "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
			"systemctl is-active rsyslog": "inactive",
			"systemctl is-active auditd":  "inactive",
			"php -v":                      "PHP 7.2.24-0ubuntu0.18.04.17 (cli)",
			"php -r echo ini_get('display_errors'),\"\\n\";":    "1",
			"php -r echo ini_get('expose_php'),\"\\n\";":        "1",
			"php -r echo ini_get('allow_url_include'),\"\\n\";": "1",
		},
		HTTPResp: map[string]sys.HTTPResponse{
			"https://" + site + "/": {Status: 200,
				Header:  hdr("Content-Type", "text/html", "Server", "Apache/2.4.29 (Ubuntu)", "X-Powered-By", "PHP/7.2.24"),
				Body:    `<html><head><meta name="generator" content="WordPress 5.2.1"></head><body>Shop</body></html>`,
				Cookies: []*http.Cookie{{Name: "PHPSESSID", Value: "x"}}},
			"http://" + site + "/":               {Status: 200, Header: hdr("Content-Type", "text/html"), Body: "<html>Shop</html>"},
			"https://" + site + "/.git/HEAD":     {Status: 200, Header: hdr("Content-Type", "text/plain"), Body: "ref: refs/heads/main\n"},
			"https://" + site + "/.env":          {Status: 200, Header: hdr("Content-Type", "text/plain"), Body: "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"},
			"https://" + site + "/phpinfo.php":   {Status: 200, Header: hdr("Content-Type", "text/html"), Body: "<html><title>PHP 7.2.24 - phpinfo()</title></html>"},
			"https://" + site + "/db.sql":        {Status: 200, Header: hdr("Content-Type", "application/sql"), Body: "CREATE TABLE users (id int);"},
			"https://" + site + "/uploads/":      {Status: 200, Header: hdr("Content-Type", "text/html"), Body: "<html><title>Index of /uploads</title></html>"},
			"https://" + site + "/server-status": {Status: 200, Header: hdr("Content-Type", "text/html"), Body: "<h1>Apache Server Status for shop</h1>"},
			"https://" + site + "/readme.html":   {Status: 200, Header: hdr("Content-Type", "text/html"), Body: "<html>WordPress readme</html>"},
			"https://" + site + "/xmlrpc.php":    {Status: 405, Header: hdr("Content-Type", "text/plain"), Body: "XML-RPC server accepts POST requests only."},
		},
		TLSResp: map[string]sys.TLSInfo{
			"443/" + site + "/1.0": {Version: tls.VersionTLS10},
			"443/" + site + "/1.1": {Version: tls.VersionTLS11},
			"443/" + site + "/1.3": {Version: tls.VersionTLS12, NotAfter: soon, Subject: site, DNSNames: []string{site}, SelfSigned: true},
		},
	}
}

func baseHardened() *sys.Fake {
	later := time.Now().Add(80 * 24 * time.Hour)
	secure := hdr("Content-Type", "text/html", "Server", "Apache",
		"Strict-Transport-Security", "max-age=31536000; includeSubDomains",
		"Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
		"X-Frame-Options", "SAMEORIGIN", "X-Content-Type-Options", "nosniff",
		"Referrer-Policy", "strict-origin-when-cross-origin", "Permissions-Policy", "camera=(), microphone=()")
	return &sys.Fake{
		Files: map[string]string{
			"/etc/os-release":                                 "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
			"/etc/passwd":                                     "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n",
			"/etc/shadow":                                     "root:!:19000:0:99999:7:::\ndeploy:$6$abc$hashedvalue:19000:0:99999:7:::\n",
			"/etc/sudoers":                                    "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n",
			"/proc/sys/kernel/randomize_va_space":             "2",
			"/proc/sys/kernel/kptr_restrict":                  "1",
			"/proc/sys/kernel/dmesg_restrict":                 "1",
			"/proc/sys/fs/suid_dumpable":                      "0",
			"/proc/sys/net/ipv4/ip_forward":                   "0",
			"/proc/sys/net/ipv4/conf/all/accept_redirects":    "0",
			"/proc/sys/net/ipv4/conf/all/accept_source_route": "0",
			"/proc/sys/net/ipv4/tcp_syncookies":               "1",
			"/proc/sys/kernel/unprivileged_bpf_disabled":      "2",
			// 22, 80, 443 public; MySQL and Redis on 127.0.0.1 (0100007F)
			"/proc/net/tcp": procTCP([2]string{"00000000", "0016"}, [2]string{"00000000", "0050"}, [2]string{"00000000", "01BB"},
				[2]string{"0100007F", "0CEA"}, [2]string{"0100007F", "18EB"}),
			"/proc/net/tcp6": procTCP(), "/proc/net/udp": procTCP(), "/proc/net/udp6": procTCP(),
			"/etc/apache2/sites-enabled/shop.conf": "<VirtualHost *:443>\n  ServerName " + site + "\n</VirtualHost>\n",
			"/etc/crontab":                         "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
		},
		Infos: map[string]sys.FileInfo{
			"/etc/shadow":      {Path: "/etc/shadow", Mode: 0o640},
			"/etc/passwd":      {Path: "/etc/passwd", Mode: 0o644},
			"/tmp":             {Path: "/tmp", Mode: fs.ModeDir | fs.ModeSticky | 0o777, IsDir: true},
			"/etc/hosts":       {Path: "/etc/hosts", Mode: 0o644},
			"/etc/crontab":     {Path: "/etc/crontab", Mode: 0o600, UID: 0},
			"/var/log/journal": {Path: "/var/log/journal", Mode: fs.ModeDir | 0o755, IsDir: true},
		},
		Commands: map[string]string{
			"sshd -T": "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npermitemptypasswords no\nx11forwarding no\nmaxauthtries 3\n" +
				"allowtcpforwarding no\nallowagentforwarding no\npermittunnel no\ngatewayports no\nlogingracetime 30\nauthenticationmethods publickey\n" +
				"ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nmacs hmac-sha2-512-etm@openssh.com\nkexalgorithms curve25519-sha256\nhostkeyalgorithms ssh-ed25519\n",
			"apt-get -s upgrade":                                "Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
			"ufw status verbose":                                "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
			"systemctl is-active rsyslog":                       "active",
			"systemctl is-active auditd":                        "active",
			"systemctl is-active chronyd":                       "active",
			"php -v":                                            "PHP 8.3.6 (cli)",
			"php -r echo ini_get('display_errors'),\"\\n\";":    "",
			"php -r echo ini_get('expose_php'),\"\\n\";":        "",
			"php -r echo ini_get('allow_url_include'),\"\\n\";": "0",
		},
		HTTPResp: map[string]sys.HTTPResponse{
			"https://" + site + "/": {Status: 200, Header: secure, Body: "<html><body>Shop</body></html>",
				Cookies: []*http.Cookie{{Name: "sid", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}}},
			"http://" + site + "/": {Status: 301, Header: hdr("Location", "https://"+site+"/")},
		},
		TLSResp: map[string]sys.TLSInfo{
			"443/" + site + "/1.3": {Version: tls.VersionTLS13, NotAfter: later, Subject: site, DNSNames: []string{site, "www." + site}, Trusted: true},
		},
	}
}

// ContainerHost returns the hardened server running as a container host:
// Docker's bridge interface exists and IP forwarding is on, as the runtime
// requires, with the forward path filtered by a DROP policy.
func ContainerHost() *sys.Fake {
	f := Hardened()
	f.Files["/proc/sys/net/ipv4/ip_forward"] = "1"
	f.Infos["/sys/class/net/docker0"] = sys.FileInfo{Path: "/sys/class/net/docker0", Mode: fs.ModeDir | fs.ModeSymlink | 0o777, IsDir: true}
	if !strings.Contains(f.Commands["iptables -S"], "-P FORWARD") {
		f.Commands["iptables -S"] = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n" + f.Commands["iptables -S"]
	}
	return f
}
