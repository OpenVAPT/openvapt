package web

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Apache Tomcat checks. They read server.xml, tomcat-users.xml and the
// deployed application folders; no request is sent to Tomcat, and passwords
// read from tomcat-users.xml are compared in memory and never reported.

var refTomcatSec = check.Ref{Title: "Apache Tomcat 10.1, Security Considerations", URL: "https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"}

type tomcatRule struct {
	id, title, summary, msg, rationale, detection, fix, verify, cvss string
	sev                                                              check.Severity
	cat                                                              check.Category
	refs                                                             []check.Ref
	std                                                              check.Standards
	eval                                                             func(context.Context, sys.System, collect.TomcatInstance) []string
}

func registerTomcat(r tomcatRule) {
	check.Register(&check.Check{ID: r.id, Title: r.title, Domain: check.DomainWeb, Severity: r.sev, Category: r.cat, Effort: check.EffortLow,
		CVSS: r.cvss, Summary: r.summary, Rationale: r.rationale, Detection: r.detection, Fix: r.fix, Verify: r.verify, Refs: r.refs, Standards: r.std,
		Run: func(ctx context.Context, s sys.System) []check.Result {
			ts := collect.Tomcats(s)
			if len(ts) == 0 {
				return []check.Result{check.SkipR("tomcat", "No Apache Tomcat installation found")}
			}
			var out []check.Result
			for _, t := range ts {
				if bad := r.eval(ctx, s, t); len(bad) > 0 {
					out = append(out, check.FailR(t.Conf, r.msg, bad...))
				} else {
					out = append(out, check.PassR(t.Conf, "No issue found"))
				}
			}
			return out
		},
	})
}

func readText(ctx context.Context, s sys.System, path string) string {
	r, err := s.ReadFile(ctx, path)
	if err != nil {
		return ""
	}
	return string(r.Data)
}

func loopbackAddr(a string) bool {
	if a == "localhost" {
		return true
	}
	ip := net.ParseIP(a)
	return ip != nil && ip.IsLoopback()
}

// Passwords Tomcat documentation, tutorials and scanners use as examples.
var tomcatDefaults = map[string]bool{"": true, "tomcat": true, "admin": true, "password": true, "s3cret": true, "secret": true,
	"changeit": true, "manager": true, "root": true, "123456": true, "role1": true, "both": true, "<must-be-changed>": true}

func init() {
	registerTomcat(tomcatRule{
		id: "WEB-TOM-001", title: "Tomcat Manager Reachable Without Address Restriction", sev: check.High, cat: check.CatWebApp, msg: "Tomcat Manager is deployed without an address restriction",
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		summary:   "Checks whether the Tomcat Manager or Host Manager application is deployed without an address filter limiting it to localhost.",
		rationale: "The Manager deploys WAR files, which means it runs any code it is given. Exposed to the network it is one stolen or guessed password away from full compromise, and it is a standard target of automated attacks.",
		detection: "Looks for the manager and host-manager applications in each Tomcat installation's webapps folder (and /usr/share/tomcatN-admin on Debian and Ubuntu), then reads their META-INF/context.xml and conf/Catalina/localhost/<app>.xml. Fails when no active RemoteAddrValve or RemoteCIDRValve restricts access.",
		fix:       "If you do not use them, delete the manager and host-manager folders (or apt remove tomcatN-admin). Otherwise keep the default valve in META-INF/context.xml: <Valve className=\"org.apache.catalina.valves.RemoteAddrValve\" allow=\"127\\.\\d+\\.\\d+\\.\\d+|::1|0:0:0:0:0:0:0:1\" /> and reach the Manager through an SSH tunnel.",
		verify:    "grep -A2 RemoteAddrValve <webapps>/manager/META-INF/context.xml",
		refs:      []check.Ref{refTomcatSec, {Title: "Apache Tomcat 10.1, Manager App How-To", URL: "https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html"}},
		std:       check.Standards{CWE: []string{"CWE-284", "CWE-1188"}, OWASP: []string{"A01:2021", "A05:2021"}, WSTG: []string{"WSTG-CONF-05"}, NIST: []string{"AC-3", "CM-7"}},
		eval: func(ctx context.Context, s sys.System, t collect.TomcatInstance) []string {
			var bad []string
			for _, app := range []string{"manager", "host-manager"} {
				var dirs []string
				for _, w := range t.Webapps {
					if collect.Exists(s, w+"/"+app+"/META-INF/context.xml") || collect.Exists(s, w+"/"+app+"/WEB-INF/web.xml") {
						dirs = append(dirs, w+"/"+app)
					}
				}
				if len(dirs) == 0 {
					continue
				}
				restricted := false
				for _, ctxFile := range []string{dirs[0] + "/META-INF/context.xml", t.Conf + "/Catalina/localhost/" + app + ".xml"} {
					for _, v := range collect.XMLElements(readText(ctx, s, ctxFile), "Valve") {
						cls := v["classname"]
						if (strings.HasSuffix(cls, "RemoteAddrValve") || strings.HasSuffix(cls, "RemoteCIDRValve")) && v["allow"] != "" && v["allow"] != ".*" {
							restricted = true
						}
					}
				}
				if !restricted {
					bad = append(bad, dirs[0]+" is deployed with no RemoteAddrValve or RemoteCIDRValve restriction")
				}
			}
			return bad
		},
	})

	registerTomcat(tomcatRule{
		id: "WEB-TOM-002", title: "Tomcat Administrative Users With Default or Weak Passwords", sev: check.Critical, cat: check.CatIdentity, msg: "Tomcat administrative users have weak credentials",
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		summary:   "Checks tomcat-users.xml for manager or admin accounts with well-known default passwords, passwords equal to the user name, or short passwords.",
		rationale: "Default Tomcat credentials (tomcat/tomcat, admin/admin, tomcat/s3cret) are in every attack tool's word list. A Manager account with such a password lets anyone deploy code on the server.",
		detection: "Parses the <user> elements of conf/tomcat-users.xml (comments ignored). For users with manager-gui, manager-script, manager-jmx, admin-gui or admin-script roles, compares the password in memory against a short list of documented defaults, the user name and a 12-character minimum. Passwords stored as digests are not judged. No password is ever written to the report.",
		fix:       "Remove accounts you do not need. Give the remaining ones long random passwords and store them as digests: configure a CredentialHandler (for example SecretKeyCredentialHandler with PBKDF2) in the Realm and generate hashes with bin/digest.sh. Restart Tomcat.",
		verify:    "Re-run this check; no administrative user should be listed.",
		refs:      []check.Ref{refTomcatSec, {Title: "Apache Tomcat 10.1, Realm Configuration How-To (digested passwords)", URL: "https://tomcat.apache.org/tomcat-10.1-doc/realm-howto.html"}},
		std:       check.Standards{CWE: []string{"CWE-1392", "CWE-521", "CWE-256"}, OWASP: []string{"A07:2021"}, ASVS: []string{"2.1.1", "2.5.4"}, NIST: []string{"IA-5"}},
		eval: func(ctx context.Context, s sys.System, t collect.TomcatInstance) []string {
			doc := readText(ctx, s, t.Conf+"/tomcat-users.xml")
			digest := regexp.MustCompile(`(?i)CredentialHandler`).MatchString(readText(ctx, s, t.Conf+"/server.xml"))
			var bad []string
			for _, u := range collect.XMLElements(doc, "user") {
				roles := strings.ToLower(u["roles"])
				if !strings.Contains(roles, "manager-") && !strings.Contains(roles, "admin-") {
					continue
				}
				pw, name := u["password"], u["username"]
				if digest && len(pw) >= 32 {
					continue
				}
				switch {
				case tomcatDefaults[strings.ToLower(pw)]:
					bad = append(bad, fmt.Sprintf("user %q (roles %s) uses a documented default password", name, u["roles"]))
				case strings.EqualFold(pw, name):
					bad = append(bad, fmt.Sprintf("user %q (roles %s) uses the user name as password", name, u["roles"]))
				case len(pw) < 12:
					bad = append(bad, fmt.Sprintf("user %q (roles %s): fewer than 12 characters in the password", name, u["roles"]))
				}
			}
			return bad
		},
	})

	registerTomcat(tomcatRule{
		id: "WEB-TOM-003", title: "Tomcat Shutdown Port Uses the Default Command", sev: check.Medium, cat: check.CatConfig, msg: "Tomcat shutdown port uses the default command",
		cvss:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
		summary:   "Checks whether Tomcat's shutdown port is enabled with the well-known default command SHUTDOWN.",
		rationale: "Anyone who can connect to the shutdown port (8005 by default) and send the shutdown string stops Tomcat. With the default string, every local user and every compromised process on the machine can take the applications offline.",
		detection: "Reads the <Server> element of conf/server.xml and fails when port is not -1 and the shutdown attribute is SHUTDOWN.",
		fix:       "Disable the port with <Server port=\"-1\" ...> and stop Tomcat through systemd, or set shutdown to a long random string. Restart Tomcat.",
		verify:    "grep '<Server' <conf>/server.xml  shows port=\"-1\".",
		refs:      []check.Ref{refTomcatSec, {Title: "Apache Tomcat 10.1 Configuration Reference, The Server Component", URL: "https://tomcat.apache.org/tomcat-10.1-doc/config/server.html"}},
		std:       check.Standards{CWE: []string{"CWE-1188"}, OWASP: []string{"A05:2021"}, NIST: []string{"CM-6", "CM-7"}},
		eval: func(ctx context.Context, s sys.System, t collect.TomcatInstance) []string {
			for _, srv := range collect.XMLElements(readText(ctx, s, t.Conf+"/server.xml"), "Server") {
				if srv["port"] != "-1" && srv["shutdown"] == "SHUTDOWN" {
					return []string{fmt.Sprintf("<Server port=%q shutdown=\"SHUTDOWN\">", srv["port"])}
				}
			}
			return nil
		},
	})

	registerTomcat(tomcatRule{
		id: "WEB-TOM-004", title: "Tomcat AJP Connector Unprotected (Ghostcat)", sev: check.Critical, cat: check.CatWebApp, msg: "AJP connector is reachable without protection",
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		summary:   "Checks for an active AJP connector that has no shared secret and is not bound to loopback, or that disables the secret requirement.",
		rationale: "AJP is a trusted, unauthenticated protocol between a web server and Tomcat. CVE-2020-1938 (Ghostcat) showed that a reachable AJP port lets an attacker read any file in the web applications and, where uploads exist, execute code. It is listed in the CISA Known Exploited Vulnerabilities catalogue.",
		detection: "Reads the <Connector> elements of conf/server.xml (comments ignored) and, for those with protocol AJP/1.3 or an AJP protocol class, fails when secretRequired=\"false\" or when there is no secret (or requiredSecret) and the address is not a loopback address.",
		fix:       "If you do not use AJP (most sites proxy over HTTP), delete or comment out the AJP <Connector>. Otherwise set address=\"127.0.0.1\", a long random secret=\"...\" with secretRequired=\"true\", and the same secret in the proxy (mod_proxy_ajp: ProxyPass ... secret=...). Upgrade Tomcat to a supported release.",
		verify:    "grep -i ajp <conf>/server.xml  and  ss -tlnp | grep 8009  shows nothing or 127.0.0.1 only.",
		refs:      []check.Ref{refTomcatSec, {Title: "Apache Tomcat 10.1 Configuration Reference, The AJP Connector", URL: "https://tomcat.apache.org/tomcat-10.1-doc/config/ajp.html"}, {Title: "NVD, CVE-2020-1938", URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"}},
		std:       check.Standards{CWE: []string{"CWE-306", "CWE-284"}, OWASP: []string{"A05:2021", "A06:2021"}, NIST: []string{"SC-7", "AC-3", "CM-7"}},
		eval: func(ctx context.Context, s sys.System, t collect.TomcatInstance) []string {
			var bad []string
			for _, c := range collect.XMLElements(readText(ctx, s, t.Conf+"/server.xml"), "Connector") {
				if !strings.Contains(strings.ToUpper(c["protocol"]), "AJP") {
					continue
				}
				port := c["port"]
				switch {
				case strings.EqualFold(c["secretrequired"], "false") && !loopbackAddr(c["address"]):
					bad = append(bad, "AJP connector on port "+port+" is not bound to loopback and does not require a secret")
				case c["secret"] == "" && c["requiredsecret"] == "" && !loopbackAddr(c["address"]):
					bad = append(bad, "AJP connector on port "+port+" is not bound to loopback and has no secret")
				}
			}
			return bad
		},
	})

	registerTomcat(tomcatRule{
		id: "WEB-TOM-005", title: "Tomcat Example and Documentation Applications Deployed", sev: check.Medium, cat: check.CatExposure, msg: "Tomcat sample applications are deployed",
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
		summary:   "Checks whether the examples or docs web applications that ship with Tomcat are deployed.",
		rationale: "The sample applications are written to demonstrate features, not to be safe. Some (such as the session example) let visitors change server-side session data, and all of them reveal the exact Tomcat version.",
		detection: "Looks for examples/ and docs/ application folders (WEB-INF/web.xml or index.html) in each Tomcat installation's webapps folders, including the Debian and Ubuntu tomcatN-examples and tomcatN-docs packages.",
		fix:       "Delete the examples and docs folders from webapps (or apt remove tomcatN-examples tomcatN-docs) and restart Tomcat.",
		verify:    "ls <webapps>  lists only your own applications (and ROOT).",
		refs:      []check.Ref{refTomcatSec, {Title: "OWASP WSTG-CONF-02, Test Application Platform Configuration", URL: "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration"}},
		std:       check.Standards{CWE: []string{"CWE-1188", "CWE-200"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-CONF-02"}, NIST: []string{"CM-7"}},
		eval: func(ctx context.Context, s sys.System, t collect.TomcatInstance) []string {
			var bad []string
			for _, w := range t.Webapps {
				for _, app := range []string{"examples", "docs"} {
					if collect.Exists(s, w+"/"+app+"/WEB-INF/web.xml") || collect.Exists(s, w+"/"+app+"/index.html") {
						bad = append(bad, w+"/"+app+" is deployed")
					}
				}
			}
			return bad
		},
	})
}
