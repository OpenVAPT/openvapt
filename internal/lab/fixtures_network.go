package lab

import (
	"crypto/tls"
	"fmt"

	"github.com/openvapt/openvapt/internal/sys"
)

func procUDP(socks ...[2]string) string {
	s := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for i, k := range socks {
		s += fmt.Sprintf("   %d: %s:%s 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 %d\n", i, k[0], k[1], 20000+i)
	}
	return s
}

func init() { Register(networkVulnerable, networkHardened) }

func networkVulnerable(f *sys.Fake) {
	f.Files["/etc/redis/redis.conf"] = "bind 0.0.0.0\nprotected-mode no\n"
	f.Files["/etc/mongod.conf"] = "security:\n  authorization: disabled\nnet:\n  bindIp: 0.0.0.0\n"
	f.Files["/etc/postgresql/16/main/postgresql.conf"] = "listen_addresses = '*'\n"
	f.Files["/etc/postgresql/16/main/pg_hba.conf"] = "host all all 0.0.0.0/0 trust\n"
	f.Files["/etc/mysql/mysql.conf.d/mysqld.cnf"] = "[mysqld]\nlocal_infile=ON\nskip-grant-tables\nskip-networking=OFF\nbind-address=0.0.0.0\n"
	f.Files["/etc/memcached.conf"] = "-l 0.0.0.0\n-U 11211\n"
	f.Files["/etc/elasticsearch/elasticsearch.yml"] = "xpack.security.enabled: false\nnetwork.host: 0.0.0.0\n"
	f.Files["/etc/exports"] = "/srv/share *(rw,no_root_squash,insecure)\n"
	f.Files["/etc/samba/smb.conf"] = "[global]\nmap to guest = Bad User\nserver min protocol = NT1\n[public]\nguest ok = yes\n"
	f.Files["/etc/bind/named.conf.options"] = "options { recursion yes; allow-transfer { any; }; };\n"
	f.Files["/etc/postfix/main.cf"] = "mynetworks = 0.0.0.0/0\nsmtpd_relay_restrictions = permit_mynetworks\nsmtpd_tls_auth_only = no\n"
	f.Files["/etc/dovecot/conf.d/10-auth.conf"] = "disable_plaintext_auth = no\n"
	f.Files["/etc/ntp.conf"] = "restrict default kod nomodify notrap nopeer\n"
	f.Files["/proc/net/tcp"] = procTCP([2]string{"00000000", "0016"}, [2]string{"00000000", "0050"}, [2]string{"00000000", "01BB"}, [2]string{"00000000", "0CEA"}, [2]string{"00000000", "18EB"}, [2]string{"00000000", "0015"}, [2]string{"00000000", "0947"}, [2]string{"00000000", "192B"}, [2]string{"00000000", "3D38"})
	f.Files["/proc/net/tcp6"] = procTCP([2]string{"00000000000000000000000000000000", "2710"})
	f.Files["/proc/net/udp"] = procUDP([2]string{"00000000", "007B"}, [2]string{"00000000", "007B"}, [2]string{"00000000", "2BCB"}, [2]string{"00000000", "00A1"})
	f.Files["/proc/net/udp6"] = procUDP()
	f.Commands["ip6tables -S"] = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
	weak := tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
	f.TLSCipherResp["443/"+site+"/"+fmt.Sprint(weak)] = sys.TLSInfo{Version: tls.VersionTLS12, Cipher: weak}
	i := f.TLSResp["443/"+site+"/1.3"]
	i.PublicKeyAlgorithm = "RSA"
	i.PublicKeyBits = 1024
	i.SignatureAlgorithm = "SHA1-RSA"
	f.TLSResp["443/"+site+"/1.3"] = i
}

func networkHardened(f *sys.Fake) {
	f.Files["/etc/redis/redis.conf"] = "bind 127.0.0.1 ::1\nprotected-mode yes\nuser app on >redacted ~* +@all\n"
	f.Files["/etc/mongod.conf"] = "security:\n  authorization: enabled\nnet:\n  bindIp: 127.0.0.1\n"
	f.Files["/etc/postgresql/16/main/postgresql.conf"] = "listen_addresses = '127.0.0.1'\n"
	f.Files["/etc/postgresql/16/main/pg_hba.conf"] = "host all all 127.0.0.1/32 scram-sha-256\n"
	f.Files["/etc/mysql/mysql.conf.d/mysqld.cnf"] = "[mysqld]\nlocal_infile=OFF\nskip-networking=ON\nbind-address=127.0.0.1\n"
	f.Files["/etc/memcached.conf"] = "-l 127.0.0.1\n-U 0\n"
	f.Files["/etc/elasticsearch/elasticsearch.yml"] = "xpack.security.enabled: true\nnetwork.host: 127.0.0.1\n"
	f.Files["/etc/exports"] = "/srv/share 10.0.0.0/24(ro,root_squash,secure)\n"
	f.Files["/etc/samba/smb.conf"] = "[global]\nmap to guest = Never\nserver min protocol = SMB2_02\n[private]\nguest ok = no\n"
	f.Files["/etc/bind/named.conf.options"] = "options { recursion no; allow-transfer { none; }; };\n"
	f.Files["/etc/postfix/main.cf"] = "mynetworks = 127.0.0.0/8\nsmtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination\nsmtpd_tls_auth_only = yes\n"
	f.Files["/etc/dovecot/conf.d/10-auth.conf"] = "disable_plaintext_auth = yes\n"
	// Apache also listens on IPv6 port 443, behind a default-deny ip6tables
	// policy, and ntpd serves time with queries refused (noquery).
	f.Files["/proc/net/tcp6"] = procTCP([2]string{"00000000000000000000000000000000", "01BB"})
	f.Commands["ip6tables -S"] = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n"
	f.Files["/proc/net/udp"] = procUDP([2]string{"00000000", "007B"})
	f.Files["/etc/ntp.conf"] = "restrict default kod limited nomodify notrap nopeer noquery\nrestrict 127.0.0.1\nrestrict ::1\n"
	i := f.TLSResp["443/"+site+"/1.3"]
	i.PublicKeyAlgorithm = "RSA"
	i.PublicKeyBits = 3072
	i.SignatureAlgorithm = "SHA256-RSA"
	f.TLSResp["443/"+site+"/1.3"] = i
}
