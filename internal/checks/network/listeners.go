package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// dataPorts are services that should almost never be reachable from other
// machines. Port numbers per the IANA Service Name and Port Number Registry.
var dataPorts = map[int]string{
	3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "Microsoft SQL Server", 1521: "Oracle DB",
	27017: "MongoDB", 6379: "Redis", 11211: "Memcached", 9200: "Elasticsearch/OpenSearch",
	5984: "CouchDB", 9042: "Cassandra", 5672: "RabbitMQ",
}

// cleartextPorts are legacy services that send credentials unencrypted.
var cleartextPorts = map[int]string{
	21: "FTP", 23: "Telnet", 69: "TFTP", 110: "POP3 (no TLS)", 143: "IMAP (no TLS)",
	512: "rexec", 513: "rlogin", 514: "rsh", 161: "SNMP (v1/v2c community strings)", 389: "LDAP (no TLS)", 873: "rsync daemon",
}

func init() {
	check.Register(&check.Check{
		ID:        "NET-LSN-001",
		Title:     "Inventory of Listening Network Services",
		Domain:    check.DomainNetwork,
		Severity:  check.Info,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		Summary:   "Lists every TCP and UDP port this machine listens on, and whether it is reachable from other machines.",
		Rationale: "Attack surface starts with what is listening. Every exposed port should be known and justified (NIST SP 800-115, discovery phase).",
		Detection: "Parses /proc/net/tcp, tcp6, udp and udp6. Sockets bound to 127.0.0.1 or ::1 are local only; anything else (0.0.0.0, ::, a public address) is reachable from the network unless a firewall blocks it.",
		Fix:       "Stop or uninstall services you do not need (systemctl disable --now <unit>). Bind internal services to 127.0.0.1. Block the rest at the firewall.",
		Verify:    "ss -tulpn  shows the same list with process names.",
		Refs:      []check.Ref{{Title: "NIST SP 800-115, Technical Guide to Information Security Testing and Assessment", URL: "https://csrc.nist.gov/pubs/sp/800/115/final"}, {Title: "proc_net(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/proc_net.5.html"}},
		Standards: check.Standards{CWE: []string{"CWE-1327"}, NIST: []string{"CM-7", "CM-8"}, CISTopic: "Network services inventory"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			ls, err := collect.Listeners(s)
			if err != nil {
				return []check.Result{check.IncompleteR("/proc/net", "One or more socket tables were unreadable or partial")}
			}
			var pub, local []string
			for _, l := range ls {
				if l.Public() {
					pub = append(pub, l.String()+label(l.Port))
				} else {
					local = append(local, l.String()+label(l.Port))
				}
			}
			ev := append([]string{fmt.Sprintf("network-reachable: %d", len(pub))}, pub...)
			ev = append(ev, fmt.Sprintf("local only: %d", len(local)))
			ev = append(ev, local...)
			return []check.Result{check.PassR("sockets", fmt.Sprintf("%d listening sockets, %d reachable from the network", len(ls), len(pub)), ev...)}
		},
	})

	check.Register(&check.Check{
		ID:        "NET-DB-001",
		Title:     "Database or Cache Service Exposed to the Network",
		Domain:    check.DomainNetwork,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether databases, caches, search engines or the Docker API listen on a network-reachable address.",
		Rationale: "Exposed databases and caches (Redis, MongoDB, Elasticsearch, Memcached) are among the most common causes of mass data breaches and ransom wipes, often because they ship without authentication.",
		Detection: "Matches network-reachable listening ports from /proc/net against a list of well-known data service ports (IANA registry).",
		Fix:       "Bind the service to 127.0.0.1 (MySQL: bind-address = 127.0.0.1; Redis: bind 127.0.0.1 ::1 and protected-mode yes; MongoDB: net.bindIp: 127.0.0.1) and restart it. Caution: confirm first that no application on another machine connects to it, or that application loses its database. If remote access is needed, allow only specific source IPs in the firewall and require TLS and authentication.",
		Verify:    "ss -tlnp | grep -E ':(3306|5432|6379|27017|9200|11211)'  should show only 127.0.0.1 or ::1.",
		Refs: []check.Ref{{Title: "OWASP Database Security Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"},
			{Title: "Redis security", URL: "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"}},
		Standards: check.Standards{CWE: []string{"CWE-1327", "CWE-306"}, OWASP: []string{"A05:2021"}, NIST: []string{"SC-7", "CM-7"}, CISTopic: "Network exposure of data services"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			ls, err := collect.Listeners(s)
			if err != nil {
				return []check.Result{check.IncompleteR("/proc/net", "One or more socket tables were unreadable or partial")}
			}
			var bad []string
			for _, l := range ls {
				if name, ok := dataPorts[l.Port]; ok && l.Public() && strings.HasPrefix(l.Proto, "tcp") {
					bad = append(bad, l.String()+" "+name)
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("sockets", "Data services listen on network-reachable addresses", bad...)}
			}
			return []check.Result{check.PassR("sockets", "No database or cache ports are network-reachable")}
		},
	})

	check.Register(&check.Check{
		ID:        "NET-SVC-001",
		Title:     "Cleartext Legacy Services Listening",
		Domain:    check.DomainNetwork,
		Severity:  check.High,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks for Telnet, FTP, rsh/rlogin, TFTP, plain POP3/IMAP/LDAP, SNMP v1/v2c and rsync daemons on network-reachable addresses.",
		Rationale: "These protocols send passwords and data unencrypted, so anyone on the path can read or alter them. Most also have weak or no authentication.",
		Detection: "Matches network-reachable listening ports from /proc/net against well-known cleartext service ports.",
		Fix:       "Replace with encrypted equivalents: SSH/SFTP instead of Telnet/FTP/rsh, IMAPS (993)/POP3S (995), LDAPS (636), SNMPv3. Disable the old service: systemctl disable --now <unit>.",
		Verify:    "ss -tulpn  should not show ports 21, 23, 69, 110, 143, 161, 389, 512-514 or 873 on public addresses.",
		Refs:      []check.Ref{{Title: "NIST SP 800-123, Guide to General Server Security", URL: "https://csrc.nist.gov/pubs/sp/800/123/final"}},
		Standards: check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, NIST: []string{"SC-8", "CM-7"}, CISTopic: "Remove insecure legacy services"},
		Run: func(_ context.Context, s sys.System) []check.Result {
			ls, err := collect.Listeners(s)
			if err != nil {
				return []check.Result{check.IncompleteR("/proc/net", "One or more socket tables were unreadable or partial")}
			}
			var bad []string
			for _, l := range ls {
				if name, ok := cleartextPorts[l.Port]; ok && l.Public() {
					bad = append(bad, l.String()+" "+name)
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("sockets", "Cleartext services are network-reachable", bad...)}
			}
			return []check.Result{check.PassR("sockets", "No cleartext legacy services are network-reachable")}
		},
	})
}

func label(port int) string {
	for _, m := range []map[int]string{dataPorts, cleartextPorts, controlPorts, managementPorts} {
		if n, ok := m[port]; ok {
			return " (" + n + ")"
		}
	}
	switch port {
	case 22:
		return " (SSH)"
	case 25:
		return " (SMTP)"
	case 53:
		return " (DNS)"
	case 80:
		return " (HTTP)"
	case 443:
		return " (HTTPS)"
	case 587:
		return " (SMTP submission)"
	case 993:
		return " (IMAPS)"
	case 995:
		return " (POP3S)"
	}
	return ""
}

// exposure describes how a network-reachable socket is bound, so a reader
// can tell a service on every interface from one on a single address.
func exposure(l collect.Listener) string {
	if l.IP.IsUnspecified() {
		return "all interfaces"
	}
	if l.IP.IsPrivate() || l.IP.IsLinkLocalUnicast() {
		return "private address"
	}
	return "public address"
}
