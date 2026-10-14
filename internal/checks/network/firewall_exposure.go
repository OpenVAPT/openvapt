package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Checks that compare what the host firewall allows with what is actually
// listening. A firewall that is "on" can still let a database through, keep
// holes open for services long gone, or be bypassed by Docker.

// codePorts are debuggers, management protocols and shutdown ports of
// application servers that give code execution or control to whoever
// connects. Sources: Node.js, Apache Tomcat, PHP-FPM and Jupyter
// documentation.
var codePorts = map[int]string{
	9229: "Node.js inspector (debugger)", 8009: "Tomcat AJP connector", 8005: "Tomcat shutdown port",
	9000: "PHP-FPM FastCGI", 8888: "Jupyter Notebook",
}

// appPorts are the default HTTP ports of application servers and developer
// tools that are meant to sit behind a reverse proxy, never face the
// network. Reaching one directly bypasses TLS, headers and limits, but the
// port number alone does not prove code execution, so the severity is lower
// than codePorts. Sources: Node.js, Django, Flask, Vite and Tomcat docs.
var appPorts = map[int]string{
	3000: "Node.js / Express app server", 3001: "Node.js app server", 4000: "app server", 4200: "Angular dev server",
	5000: "Flask / Python dev server", 5173: "Vite dev server", 8000: "Django / Gunicorn / Uvicorn", 8008: "app server",
	8080: "Tomcat / Java HTTP connector", 8081: "app server", 8088: "app server",
}

// sensitivePort names a data, administrative or application server port.
func sensitivePort(p int) (string, bool) {
	for _, m := range []map[int]string{dataPorts, controlPorts, managementPorts, codePorts, appPorts} {
		if n, ok := m[p]; ok {
			return n, true
		}
	}
	return "", false
}

var refNIST41 = check.Ref{Title: "NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy", URL: "https://csrc.nist.gov/pubs/sp/800/41/r1/final"}

func publicListeners(s sys.System) ([]collect.Listener, []check.Result) {
	ls, err := collect.Listeners(s)
	if err != nil {
		return nil, []check.Result{check.IncompleteR("/proc/net", "One or more socket tables were unreadable or partial")}
	}
	var pub []collect.Listener
	for _, l := range ls {
		if l.Public() {
			pub = append(pub, l)
		}
	}
	return pub, nil
}

func init() {
	check.Register(&check.Check{
		ID: "NET-FW-003", Title: "Firewall Allows Sensitive Services From Anywhere", Domain: check.DomainNetwork,
		Severity: check.High, Category: check.CatNetwork, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether the host firewall explicitly opens a listening database, administrative or application server port to every address on the internet.",
		Rationale: "A default-deny firewall only protects what it does not allow. A single \"allow 3306 from anywhere\" rule, often added while debugging, makes a database or admin panel as exposed as if there were no firewall at all.",
		Detection: "Reads the incoming allow rules of ufw (ufw status verbose), nftables (nft list ruleset, input-hook chains) or iptables (iptables -S, INPUT and ufw chains), and matches rules with no source restriction against network-reachable listening sockets on well-known data, administrative and application server ports.",
		Fix:       "Delete the rule or restrict it to the addresses that need it, for example: ufw delete allow 3306 && ufw allow from 203.0.113.10 to any port 3306 proto tcp . Better, bind the service to 127.0.0.1 and reach it through an SSH tunnel or VPN.",
		Verify:    "ufw status numbered  or  nft list ruleset  shows no rule opening that port to Anywhere.",
		Refs:      []check.Ref{refNIST41, {Title: "ufw(8) manual (Ubuntu)", URL: "https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html"}},
		Standards: check.Standards{CWE: []string{"CWE-923", "CWE-1327"}, OWASP: []string{"A05:2021"}, NIST: []string{"SC-7", "AC-4", "CM-7"}, CISTopic: "Restrict firewall rules to required sources"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			fw := collect.ReadFirewall(ctx, s)
			if len(fw.Rules) == 0 {
				return []check.Result{check.SkipR("firewall", "No firewall allow rules found (see NET-FW-001 for whether a firewall is active)")}
			}
			pub, inc := publicListeners(s)
			if inc != nil {
				return inc
			}
			var bad []string
			for _, l := range pub {
				name, ok := sensitivePort(l.Port)
				if !ok {
					continue
				}
				for _, r := range fw.Rules {
					if r.Any() && r.Covers(l.Proto, l.Port) {
						bad = append(bad, fmt.Sprintf("%s (%s) allowed from anywhere by %s rule: %s", l.String(), name, r.Engine, r.Raw))
						break
					}
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("firewall", "Sensitive services are open to every address", bad...)}
			}
			return []check.Result{check.PassR("firewall", "No sensitive listening service is opened to every address")}
		},
	})

	check.Register(&check.Check{
		ID: "NET-FW-004", Title: "Firewall Rules Open Ports With No Service", Domain: check.DomainNetwork,
		Severity: check.Low, Category: check.CatNetwork, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks for firewall allow rules whose port has no listening service on this machine.",
		Rationale: "Stale rules are holes waiting for a service. Anything later started on that port, by an administrator, a package or an attacker, becomes reachable without anyone deciding it should be. Rule sets also become impossible to review when they no longer match reality.",
		Detection: "Compares each single-port incoming allow rule from ufw, nftables or iptables with the listening sockets in /proc/net (tcp, tcp6, udp, udp6). Port ranges are not judged, because they are often used for passive FTP or media and may be idle.",
		Fix:       "Remove rules for services that no longer exist (ufw status numbered, then ufw delete <n>), or note why a rule must stay. Review the firewall whenever a service is retired.",
		Verify:    "Re-run this check; every allowed port should have a listening service.",
		Refs:      []check.Ref{refNIST41},
		Standards: check.Standards{CWE: []string{"CWE-1188"}, NIST: []string{"SC-7", "CM-7", "CM-3"}, CISTopic: "Review firewall rules periodically"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			fw := collect.ReadFirewall(ctx, s)
			if len(fw.Rules) == 0 {
				return []check.Result{check.SkipR("firewall", "No firewall allow rules found")}
			}
			ls, err := collect.Listeners(s)
			if err != nil {
				return []check.Result{check.IncompleteR("/proc/net", "One or more socket tables were unreadable or partial")}
			}
			seen := map[string]bool{}
			var bad []string
			for _, r := range fw.Rules {
				if r.From != r.To {
					continue
				}
				used := false
				for _, l := range ls {
					if r.Covers(l.Proto, l.Port) {
						used = true
						break
					}
				}
				key := fmt.Sprintf("%s/%d", r.Proto, r.From)
				if !used && !seen[key] {
					seen[key] = true
					bad = append(bad, fmt.Sprintf("port %d%s allowed by %s but nothing listens on it: %s", r.From, protoSuffix(r.Proto), r.Engine, r.Raw))
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("firewall", fmt.Sprintf("%d allow rule(s) open ports with no service", len(bad)), bad...)}
			}
			return []check.Result{check.PassR("firewall", "Every single-port allow rule matches a listening service")}
		},
	})

	check.Register(&check.Check{
		ID: "NET-FW-005", Title: "Container Ports Bypass the Host Firewall", Domain: check.DomainNetwork,
		Severity: check.Medium, Category: check.CatNetwork, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks whether Docker publishes container ports through its own iptables chains with no DOCKER-USER filtering.",
		Rationale: "Docker inserts its NAT and FORWARD rules ahead of ufw and of the INPUT chain, so a port published with -p 8080:80 is reachable from the internet even when ufw says the port is denied. Administrators routinely believe the firewall protects these containers when it does not.",
		Detection: "Reads iptables -S and looks for ACCEPT rules with a destination port in the DOCKER chain (published container ports). Fails when there are such rules and the DOCKER-USER chain contains no DROP or REJECT rule.",
		Fix:       "Publish container ports on loopback only (-p 127.0.0.1:8080:80) and put a reverse proxy in front, or add filtering to DOCKER-USER, for example: iptables -I DOCKER-USER -i eth0 ! -s 203.0.113.0/24 -j DROP (persist it with your firewall tooling). Caution: test from an allowed address first; a wrong interface name or source range cuts access to every published container.",
		Verify:    "docker ps --format '{{.Ports}}'  shows 127.0.0.1 bindings, or iptables -S DOCKER-USER shows DROP rules.",
		Refs:      []check.Ref{{Title: "Docker documentation, Packet filtering and firewalls", URL: "https://docs.docker.com/engine/network/packet-filtering-firewalls/"}, refNIST41},
		Standards: check.Standards{CWE: []string{"CWE-923", "CWE-1327"}, OWASP: []string{"A05:2021"}, NIST: []string{"SC-7", "CM-7"}, CISTopic: "Filter container traffic"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			fw := collect.ReadFirewall(ctx, s)
			if len(fw.Docker) == 0 {
				return []check.Result{check.PassR("iptables", "No published container ports found in the Docker chain")}
			}
			if fw.DockerUser {
				return []check.Result{check.PassR("iptables", "Published container ports are filtered in DOCKER-USER")}
			}
			return []check.Result{check.FailR("iptables", fmt.Sprintf("%d published container port rule(s) are not filtered by the host firewall", len(fw.Docker)), fw.Docker...)}
		},
	})

	check.Register(&check.Check{
		ID: "NET-FW-006", Title: "Firewall Exposure Map of Listening Services", Domain: check.DomainNetwork,
		Severity: check.Info, Category: check.CatNetwork, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		Summary:   "Shows, for every network-reachable listening socket, what the host firewall does with traffic to it.",
		Rationale: "Exposure is the combination of what listens and what the firewall lets through. Seeing both side by side is how assessors find services that are open by accident and confirm that the rest are blocked on purpose.",
		Detection: "Combines the listening sockets in /proc/net with the firewall's default policy and allow rules (ufw, nftables or iptables). Each socket is labelled allowed from anywhere, allowed from restricted sources, blocked by default deny, or reachable because no filtering firewall is active.",
		Fix:       "For each socket labelled allowed from anywhere or reachable, decide whether it must be public. If not, bind it to 127.0.0.1 or restrict the firewall rule.",
		Verify:    "Re-run this check after changes and compare the map.",
		Refs:      []check.Ref{refNIST41, {Title: "NIST SP 800-115, Technical Guide to Information Security Testing and Assessment", URL: "https://csrc.nist.gov/pubs/sp/800/115/final"}},
		Standards: check.Standards{CWE: []string{"CWE-923"}, NIST: []string{"CM-7", "CM-8", "SC-7"}, CISTopic: "Network services inventory"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			pub, inc := publicListeners(s)
			if inc != nil {
				return inc
			}
			fw := collect.ReadFirewall(ctx, s)
			engine := fw.Engine
			if engine == "" {
				engine = "none detected"
			}
			ev := []string{fmt.Sprintf("firewall: %s, default deny: %v", engine, fw.DefaultDeny)}
			open := 0
			for _, l := range pub {
				state := "reachable (no default-deny firewall)"
				if fw.DefaultDeny {
					state = "blocked by default deny"
				}
				for _, r := range fw.Rules {
					if r.Covers(l.Proto, l.Port) {
						if r.Any() {
							state = "allowed from anywhere"
						} else {
							state = "allowed from " + r.Source
						}
						break
					}
				}
				if strings.HasPrefix(state, "allowed from anywhere") || strings.HasPrefix(state, "reachable") {
					open++
				}
				ev = append(ev, l.String()+portName(l.Port)+": "+state)
			}
			return []check.Result{check.PassR("firewall", fmt.Sprintf("%d network-reachable sockets, %d open to every address", len(pub), open), ev...)}
		},
	})

	check.Register(&check.Check{
		ID: "NET-APP-001", Title: "Debugger or Application Control Ports Exposed", Domain: check.DomainNetwork,
		Severity: check.High, Category: check.CatNetwork, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
		Summary:   "Checks whether the Node.js inspector, Tomcat AJP or shutdown port, PHP-FPM FastCGI or Jupyter listen on network-reachable addresses.",
		Rationale: "These ports are not web pages: the Node.js inspector and Jupyter run code for whoever connects, Tomcat AJP has been abused for file read and code execution (Ghostcat), the shutdown port stops the server, and PHP-FPM executes scripts handed to it. None of them is designed to face a network.",
		Detection: "Matches network-reachable listening TCP sockets from /proc/net against the default ports of these debuggers and control protocols, recording how each is bound. Plain application HTTP ports are rated separately by NET-APP-002. No packets are sent.",
		Fix:       "Bind each to 127.0.0.1 or a Unix socket (node --inspect=127.0.0.1:9229; Tomcat Connector address=\"127.0.0.1\" or remove the AJP connector; PHP-FPM listen = /run/php/php-fpm.sock; jupyter --ip=127.0.0.1) and never expose a debugger.",
		Verify:    "ss -tlnp  shows these ports on 127.0.0.1 or ::1 only.",
		Refs: []check.Ref{{Title: "Node.js, Inspector security implications", URL: "https://nodejs.org/en/learn/getting-started/debugging#security-implications"},
			{Title: "Apache Tomcat 9, AJP Connector", URL: "https://tomcat.apache.org/tomcat-9.0-doc/config/ajp.html"}},
		Standards: check.Standards{CWE: []string{"CWE-489", "CWE-1327"}, OWASP: []string{"A05:2021"}, NIST: []string{"SC-7", "CM-7"}, CISTopic: "Expose applications only through a hardened front end"},
		Run:       appPortRun(codePorts, "Debugger or application control ports are network-reachable", "No debugger or application control port is network-reachable"),
	})

	check.Register(&check.Check{
		ID: "NET-APP-002", Title: "Application Server Ports Reachable Without a Reverse Proxy", Domain: check.DomainNetwork,
		Severity: check.Medium, Category: check.CatNetwork, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks whether application servers and developer tools (Node.js, Tomcat, Django, Flask, Vite) serve HTTP on network-reachable addresses.",
		Rationale: "Application servers are designed to sit behind a reverse proxy that adds TLS, security headers, logging and request limits. Reached directly they bypass all of that, and development servers on these ports often run with debug pages on. The port number alone does not prove a weakness, so this is rated Medium and should be reviewed.",
		Detection: "Matches network-reachable listening TCP sockets from /proc/net against the default HTTP ports of common application servers and developer tools, recording how each is bound and whether a web server listens on port 80 or 443 on this machine (which suggests the application was meant to be proxied). No packets are sent.",
		Fix:       "Bind the application to 127.0.0.1 (Node.js: app.listen(3000, '127.0.0.1'); Gunicorn: --bind 127.0.0.1:8000; Tomcat: address=\"127.0.0.1\" on the Connector) and publish it only through nginx or Apache.",
		Verify:    "ss -tlnp  shows these ports on 127.0.0.1 or ::1 only.",
		Refs: []check.Ref{{Title: "OWASP Node.js Security Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html"},
			{Title: "Gunicorn documentation, Deploying Gunicorn (behind a proxy)", URL: "https://gunicorn.org/deploy/"}},
		Standards: check.Standards{CWE: []string{"CWE-1188", "CWE-1327"}, OWASP: []string{"A05:2021"}, NIST: []string{"SC-7", "CM-7"}, CISTopic: "Expose applications only through a hardened front end"},
		Run:       appPortRun(appPorts, "Application server ports are network-reachable", "No application server port is network-reachable"),
	})
}

// appPortRun reports network-reachable TCP listeners on the given ports,
// noting whether a web server (80 or 443) is present to front them.
func appPortRun(ports map[int]string, failMsg, passMsg string) func(context.Context, sys.System) []check.Result {
	return func(_ context.Context, s sys.System) []check.Result {
		pub, inc := publicListeners(s)
		if inc != nil {
			return inc
		}
		var bad []string
		web := false
		for _, l := range pub {
			if l.Port == 80 || l.Port == 443 {
				web = true
			}
		}
		for _, l := range pub {
			if n, ok := ports[l.Port]; ok && strings.HasPrefix(l.Proto, "tcp") {
				bad = append(bad, l.String()+" "+n+", bound to "+exposure(l))
			}
		}
		if len(bad) > 0 {
			if web {
				bad = append(bad, "a web server listens on port 80 or 443 on this machine: bind the application to 127.0.0.1 and publish it through that proxy")
			} else {
				bad = append(bad, "no web server listens on port 80 or 443 on this machine")
			}
			return []check.Result{check.FailR("sockets", failMsg, bad...)}
		}
		return []check.Result{check.PassR("sockets", passMsg)}
	}
}

// portName labels a port with its well-known service, if any.
func portName(p int) string {
	if n, ok := sensitivePort(p); ok {
		return " (" + n + ")"
	}
	return label(p)
}

func protoSuffix(p string) string {
	if p == "" {
		return ""
	}
	return "/" + p
}
