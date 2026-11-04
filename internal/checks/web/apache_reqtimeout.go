package web

import (
	"strings"

	"github.com/openvapt/openvapt/internal/check"
)

// WEB-APA-011: slow-request protection. Read from configuration only; no
// slow or partial request is ever sent to the server.

func init() {
	registerServerRule(serverRule{
		id: "WEB-APA-011", title: "Apache Has No Slow Request Protection", sev: check.Medium, cat: check.CatConfig,
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
		summary:   "mod_reqtimeout does not appear to be loaded and no RequestReadTimeout is set, so a client that sends its request very slowly can hold a worker for the whole Timeout.",
		rationale: "Apache keeps one worker busy for each open request. Without minimum read rates, a few clients sending headers a byte at a time (the Slowloris technique) can use up every worker and take the site offline. The module is enabled by default on most distributions, so its absence usually means it was removed.",
		detection: "Looks for LoadModule reqtimeout_module or a RequestReadTimeout directive in the configuration tree, or reqtimeout.load under mods-enabled. A module compiled into the server binary does not appear in the configuration, so confirm with the Verify command. Configuration is only read; no slow request is sent.",
		fix:       "Enable the module (Debian and Ubuntu: a2enmod reqtimeout; other systems: LoadModule reqtimeout_module modules/mod_reqtimeout.so) and keep or set  RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500 , then reload.",
		verify:    "apachectl -M 2>/dev/null | grep reqtimeout",
		refs:      []check.Ref{{Title: "Apache HTTP Server, mod_reqtimeout", URL: "https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html"}, refApacheSecTips},
		std:       check.Standards{CWE: []string{"CWE-770"}, OWASP: []string{"A05:2021"}, NIST: []string{"SC-5", "CM-6"}, CISTopic: "Web server request time limits"},
		kind:      apacheKind,
		evaluate: func(c serverConf) (bool, []string) {
			var ev []string
			for _, l := range c.directive("loadmodule") {
				if strings.Contains(strings.ToLower(l.Value), "reqtimeout_module") {
					ev = append(ev, l.File+": "+l.Raw)
				}
			}
			for _, l := range c.directive("requestreadtimeout") {
				ev = append(ev, l.File+": "+l.Raw)
			}
			for _, p := range c.Paths {
				if strings.HasSuffix(strings.ToLower(p), "/reqtimeout.load") {
					ev = append(ev, p)
				}
			}
			if len(ev) == 0 {
				return true, []string{"no reqtimeout_module and no RequestReadTimeout directive"}
			}
			return false, ev
		},
		passMsg: "Slow request protection is configured",
	})
}
