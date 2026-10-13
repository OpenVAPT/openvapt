package network

import (
	"context"
	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
	"strings"
)

func init() {
	check.Register(&check.Check{
		ID:        "NET-FW-002",
		Title:     "IPv6 Listeners Without IPv6 Firewall",
		Domain:    check.DomainNetwork,
		Severity:  check.High,
		Category:  check.CatNetwork,
		Effort:    check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Network-reachable IPv6 listeners exist without a default-deny IPv6 firewall policy.",
		Rationale: "An IPv4-only firewall does not protect IPv6 services, creating an alternate path that bypasses intended filtering.",
		Detection: "Parses /proc/net/tcp6 and udp6, then inspects nft list ruleset and ip6tables -S for an input drop or reject policy.",
		Fix:       "Apply equivalent default-deny filtering for IPv6 with nftables or ip6tables and explicitly allow required services.",
		Verify:    "Run ip6tables -S and nft list ruleset, then confirm the input chain has a default drop or reject policy.",
		Refs:      []check.Ref{{Title: "NIST SP 800-119, Guidelines for the Secure Deployment of IPv6", URL: "https://csrc.nist.gov/pubs/sp/800/119/final"}},
		Standards: check.Standards{CWE: []string{"CWE-284"}, NIST: []string{"SC-7"}},
		Run:       runIPv6Firewall})
	check.Register(&check.Check{
		ID:        "NET-SVC-003",
		Title:     "Network Time Service Amplification Risk",
		Domain:    check.DomainNetwork,
		Severity:  check.High,
		Category:  check.CatLogging,
		Effort:    check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		Summary:   "NTP or chrony serves broad clients or permits legacy monitoring commands that can amplify traffic.",
		Rationale: "Internet-reachable time services with broad client access or legacy mode 6 or 7 controls can be abused for reflection and amplification.",
		Detection: "When UDP port 123 is network-reachable, reads ntp.conf or chrony.conf and flags broad allow directives or missing noquery restrictions.",
		Fix:       "Bind the time daemon to required interfaces, restrict clients to explicit networks, disable monitoring, and use noquery or equivalent controls.",
		Verify:    "Confirm UDP port 123 is filtered from untrusted networks and review the daemon's effective access restrictions.",
		Refs:      []check.Ref{{Title: "CISA Alert TA14-013A, NTP Amplification Attacks Using CVE-2013-5211", URL: "https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211"}, {Title: "chrony Documentation - Access Control", URL: "https://chrony-project.org/doc/4.6/chrony.conf.html"}},
		Standards: check.Standards{CWE: []string{"CWE-406"}, NIST: []string{"SC-5", "SC-7"}},
		Run:       runNTP})
}

func runIPv6Firewall(ctx context.Context, s sys.System) []check.Result {
	ls, err := collect.Listeners(s)
	if err != nil {
		return []check.Result{check.IncompleteR("/proc/net", "Socket tables were unreadable or partial")}
	}
	has6 := false
	for _, l := range ls {
		if strings.HasSuffix(l.Proto, "6") && l.Public() {
			has6 = true
		}
	}
	if !has6 {
		return []check.Result{check.SkipR("IPv6", "No network-reachable IPv6 listener was found")}
	}
	if out, e := s.Run(ctx, "nft", "list", "ruleset"); e == nil && nftInputDefaultDeny(strings.ToLower(out)) {
		return []check.Result{check.PassR("IPv6 firewall", "nftables has a default-deny input policy")}
	}
	if out, e := s.Run(ctx, "ip6tables", "-S"); e == nil {
		if strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT") {
			return []check.Result{check.PassR("IPv6 firewall", "ip6tables has a default-deny input policy")}
		}
		return []check.Result{check.FailR("IPv6 firewall", "IPv6 listeners exist but ip6tables input policy is not deny")}
	}
	return []check.Result{check.IncompleteR("IPv6 firewall", "IPv6 listeners exist but firewall state could not be read")}
}

func runNTP(ctx context.Context, s sys.System) []check.Result {
	ls, err := collect.Listeners(s)
	if err != nil {
		return []check.Result{check.IncompleteR("/proc/net", "Socket tables were unreadable or partial")}
	}
	public := false
	for _, l := range ls {
		if l.Port == 123 && l.Public() {
			public = true
		}
	}
	if !public {
		return []check.Result{check.SkipR("UDP 123", "No network-reachable time service was found")}
	}
	p, text, complete, ok := readAny(ctx, s, "/etc/ntp.conf", "/etc/chrony/chrony.conf", "/etc/chrony.conf")
	if !ok {
		return []check.Result{check.IncompleteR("NTP configuration", "UDP 123 is reachable but daemon configuration was not readable")}
	}
	lower := strings.ToLower(text)
	bad := strings.Contains(lower, "allow all") || strings.Contains(lower, "allow 0.0.0.0/0") || strings.Contains(lower, "restrict default kod nomodify notrap nopeer") || !strings.Contains(lower, "noquery")
	if bad {
		return []check.Result{check.FailR(p, "Time service access controls allow amplification-prone queries")}
	}
	if !complete {
		return []check.Result{check.IncompleteR(p, "Time service configuration was truncated")}
	}
	return []check.Result{check.PassR(p, "Time service query access is restricted")}
}
