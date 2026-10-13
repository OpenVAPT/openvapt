package network

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func readAny(ctx context.Context, s sys.System, paths ...string) (string, string, bool, bool) {
	var found []string
	var text strings.Builder
	complete := true
	for _, p := range paths {
		r, err := s.ReadFile(ctx, p)
		if err == nil {
			found = append(found, p)
			text.Write(r.Data)
			text.WriteByte('\n')
			complete = complete && r.Complete
		}
	}
	if len(found) == 0 {
		return "", "", false, false
	}
	return strings.Join(found, ", "), text.String(), complete, true
}
func simpleFileCheck(id, title string, sev check.Severity, cat check.Category, summary, rationale, detection, fix, verify, cvss string, paths []string, ref check.Ref, bad func(string) []string) {
	check.Register(&check.Check{
		ID: id, Title: title, Domain: check.DomainNetwork, Severity: sev, Category: cat, Effort: check.EffortLow, CVSS: cvss, Summary: summary, Rationale: rationale, Detection: detection, Fix: fix, Verify: verify, Refs: []check.Ref{ref}, Standards: check.Standards{CWE: []string{"CWE-16", "CWE-284"}, OWASP: []string{"A05:2021"}, NIST: []string{"AC-3", "CM-6", "SC-7"}}, Run: func(ctx context.Context, s sys.System) []check.Result {
			p, text, complete, ok := readAny(ctx, s, paths...)
			if !ok {
				return []check.Result{check.SkipR(strings.Join(paths, ", "), "Configuration was not found")}
			}
			ev := bad(text)
			if len(ev) > 0 {
				return []check.Result{check.FailR(p, summary, ev...)}
			}
			if !complete {
				return []check.Result{check.IncompleteR(p, "Configuration input was truncated")}
			}
			return []check.Result{check.PassR(p, "No unsafe setting was found")}
		}})
}

func init() {
	simpleFileCheck("NET-DB-008", "Unsafe NFS Export Options", check.High, check.CatData, "NFS exports are world-accessible or use no_root_squash or insecure.", "These export options can grant untrusted clients filesystem access or preserve remote root privileges.", "Reads /etc/exports and active exports.d fragments, ignoring comments, and flags *, no_root_squash, and insecure.", "Restrict every export to explicit client CIDRs, use root_squash, remove insecure, and reload exports.", "Run exportfs -v during approved administration and confirm only intended networks and safe options appear.", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", []string{"/etc/exports"}, check.Ref{Title: "Linux exports(5)", URL: "https://man7.org/linux/man-pages/man5/exports.5.html"}, func(t string) []string { return matchingLines(t, "*", "no_root_squash", "insecure") })
	simpleFileCheck("NET-DB-009", "Unsafe Samba Guest or SMB1 Configuration", check.High, check.CatData, "Samba permits guest access, maps unknown users to guest, or allows SMB1.", "Guest shares weaken accountability, while SMB1 lacks modern protocol protections and has a long history of severe flaws.", "Reads smb.conf and flags guest ok = yes, permissive map to guest modes, or a server min protocol below SMB2.", "Set guest ok = no, map to guest = Never, and server min protocol = SMB2_02 or newer. Review each share ACL.", "Run testparm -s during approved administration and confirm the effective values.", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", []string{"/etc/samba/smb.conf"}, check.Ref{Title: "Samba smb.conf Manual", URL: "https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html"}, func(t string) []string {
		l := strings.ToLower(t)
		var e []string
		if strings.Contains(l, "guest ok = yes") || strings.Contains(l, "guest ok=yes") {
			e = append(e, "guest ok enabled")
		}
		if strings.Contains(l, "map to guest = bad") || strings.Contains(l, "map to guest=bad") {
			e = append(e, "unknown users map to guest")
		}
		if strings.Contains(l, "server min protocol = nt1") || strings.Contains(l, "server min protocol=nt1") {
			e = append(e, "SMB1 NT1 enabled")
		}
		return e
	})
	simpleFileCheck("NET-DB-010", "BIND Open Recursion", check.High, check.CatData, "BIND enables recursion without restricting recursive clients.", "An open recursive resolver can be abused for reflection attacks and permits outsiders to consume resolver resources.", "Reads named.conf and flags recursion yes when neither allow-recursion nor allow-query-cache restricts clients.", "Disable recursion on authoritative-only servers, or set allow-recursion and allow-query-cache to explicit trusted networks.", "Run named-checkconf and query recursion from an untrusted test network under an approved test plan.", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", []string{"/etc/bind/named.conf.options", "/etc/named.conf"}, check.Ref{Title: "BIND 9 Administrator Reference Manual - Access Control", URL: "https://bind9.readthedocs.io/en/latest/reference.html#access-control"}, func(t string) []string {
		l := strings.ToLower(t)
		if strings.Contains(l, "recursion yes") && !strings.Contains(l, "allow-recursion") && !strings.Contains(l, "allow-query-cache") {
			return []string{"recursion yes without a client ACL"}
		}
		return nil
	})
	simpleFileCheck("NET-DB-011", "BIND Zone Transfers Allowed to Any", check.High, check.CatData, "BIND permits zone transfers to any client.", "Unrestricted transfers disclose the complete DNS namespace and provide attackers with a detailed target inventory.", "Reads named.conf and flags allow-transfer clauses containing any.", "Set allow-transfer to none or explicit secondary server addresses, preferably protected with TSIG.", "Run named-checkconf and verify AXFR is refused from an unauthorized test host.", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", []string{"/etc/bind/named.conf.options", "/etc/named.conf"}, check.Ref{Title: "BIND 9 Administrator Reference Manual - allow-transfer", URL: "https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-allow-transfer"}, func(t string) []string {
		l := strings.ToLower(t)
		if strings.Contains(l, "allow-transfer") && strings.Contains(l, "any;") {
			return []string{"allow-transfer includes any"}
		}
		return nil
	})
	registerMailChecks()
	registerExposureChecks()
}

func registerMailChecks() {
	simpleFileCheck("NET-DB-012", "Postfix Open Relay Controls", check.High, check.CatData, "Postfix relay restrictions are missing or mynetworks trusts overly broad ranges.", "An open relay enables spam and phishing, damages domain reputation, and can expose the host to blocklisting.", "Parses main.cf for smtpd_relay_restrictions with reject_unauth_destination and flags 0.0.0.0/0 or ::/0 in mynetworks.", "Set smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination and narrow mynetworks.", "Run postconf -n during approved administration and perform only an authorized relay test.", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L", []string{"/etc/postfix/main.cf"}, check.Ref{Title: "Postfix SMTP Relay and Access Control", URL: "https://www.postfix.org/SMTPD_ACCESS_README.html"}, func(t string) []string {
		m := collect.ParseKV(t)
		relay := strings.ToLower(strings.Join(m["smtpd_relay_restrictions"], " "))
		nets := strings.ToLower(strings.Join(m["mynetworks"], " "))
		var e []string
		if !strings.Contains(relay, "reject_unauth_destination") {
			e = append(e, "reject_unauth_destination missing")
		}
		if strings.Contains(nets, "0.0.0.0/0") || strings.Contains(nets, "::/0") {
			e = append(e, "mynetworks trusts all addresses")
		}
		return e
	})
	simpleFileCheck("NET-DB-013", "Mail Cleartext Authentication Allowed", check.Medium, check.CatCrypto, "Postfix or Dovecot permits plaintext authentication without requiring TLS.", "Credentials sent before transport encryption can be observed by any party able to intercept the connection.", "Reads Postfix smtpd_tls_auth_only and Dovecot disable_plaintext_auth, and flags no values.", "Set smtpd_tls_auth_only = yes and disable_plaintext_auth = yes. Use implicit TLS on ports 465, 993, and 995. STARTTLS assessment is out of scope.", "Confirm the effective mail configuration and that unauthenticated plaintext sessions do not advertise AUTH.", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", []string{"/etc/postfix/main.cf", "/etc/dovecot/conf.d/10-auth.conf"}, check.Ref{Title: "Dovecot Authentication Settings", URL: "https://doc.dovecot.org/main/core/config/auth/settings.html"}, func(t string) []string {
		m := collect.ParseKV(t)
		var e []string
		for _, k := range []string{"smtpd_tls_auth_only", "disable_plaintext_auth"} {
			for _, v := range m[k] {
				if strings.EqualFold(strings.TrimSpace(v), "no") {
					e = append(e, k+" is no")
				}
			}
		}
		return e
	})
}

// adminPorts are administrative, orchestration, monitoring and remote
// desktop services (vendor documentation and the IANA registry).
var adminPorts = map[int]string{2375: "Docker API without TLS", 2376: "Docker API", 6443: "Kubernetes API", 10250: "Kubelet API", 2379: "etcd client API", 8500: "Consul HTTP API", 9100: "Prometheus Node Exporter", 15672: "RabbitMQ Management", 10000: "Webmin", 2083: "cPanel", 2087: "WHM", 5900: "VNC", 3389: "RDP", 161: "SNMP"}

func registerExposureChecks() {
	ports := adminPorts
	check.Register(&check.Check{
		ID:        "NET-SVC-002",
		Title:     "Administrative Service Ports Network-Reachable",
		Domain:    check.DomainNetwork,
		Severity:  check.Critical,
		Category:  check.CatNetwork,
		Effort:    check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Administrative, orchestration, monitoring, or remote desktop ports listen on network-reachable addresses.",
		Rationale: "These services expose privileged control planes or sensitive telemetry and should not be reachable from untrusted networks.",
		Detection: "Parses local TCP and UDP socket tables and matches public listeners against vendor and IANA assigned service ports. It sends no packets.",
		Fix:       "Bind management services to loopback or a dedicated management address, require strong authentication and TLS, and filter access to approved source networks.",
		Verify:    "Review ss -tulpn and the host firewall from a trusted administrative session.",
		Refs:      []check.Ref{{Title: "IANA Service Name and Transport Protocol Port Number Registry", URL: "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"}, {Title: "Docker Protect the Daemon Socket", URL: "https://docs.docker.com/engine/security/protect-access/"}, {Title: "Kubernetes Ports and Protocols", URL: "https://kubernetes.io/docs/reference/networking/ports-and-protocols/"}},
		Standards: check.Standards{CWE: []string{"CWE-284", "CWE-668"}, OWASP: []string{"A05:2021"}, NIST: []string{"AC-17", "CM-7", "SC-7"}},
		Run: func(_ context.Context, s sys.System) []check.Result {
			ls, err := collect.Listeners(s)
			if err != nil {
				return []check.Result{check.IncompleteR("/proc/net", "Socket tables were unreadable or partial")}
			}
			var ev []string
			for _, l := range ls {
				if n, ok := ports[l.Port]; ok && l.Public() {
					ev = append(ev, l.String()+" "+n)
				}
			}
			if len(ev) > 0 {
				return []check.Result{check.FailR("sockets", "Privileged service ports are network-reachable", ev...)}
			}
			return []check.Result{check.PassR("sockets", "No listed administrative ports are network-reachable")}
		}})
}

func matchingLines(t string, needles ...string) []string {
	var out []string
	s := bufio.NewScanner(strings.NewReader(t))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		l := strings.ToLower(line)
		for _, n := range needles {
			if strings.Contains(l, strings.ToLower(n)) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}

var _ = fmt.Sprint
