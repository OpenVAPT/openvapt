package network

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "NET-FW-001",
		Title:     "No Active Host Firewall",
		Domain:    check.DomainNetwork,
		Severity:  check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks whether a host firewall (nftables, iptables, ufw or firewalld) is filtering incoming traffic.",
		Rationale: "A default-deny host firewall is a safety net: a service that is installed or misconfigured by mistake is still not reachable from the internet.",
		Detection: "Runs read-only status commands in order: ufw status, firewall-cmd --state, nft list ruleset, iptables -S. Passes if ufw/firewalld report active, or if nftables/iptables contain a drop/reject rule or a DROP input policy.",
		Fix:       "Ubuntu: ufw default deny incoming && ufw allow OpenSSH && ufw allow 80,443/tcp && ufw enable . RHEL family: systemctl enable --now firewalld . Always allow SSH before enabling, or you will lock yourself out.",
		Verify:    "ufw status verbose  or  firewall-cmd --list-all  or  nft list ruleset",
		Refs: []check.Ref{{Title: "NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy", URL: "https://csrc.nist.gov/pubs/sp/800/41/r1/final"},
			{Title: "nftables wiki", URL: "https://wiki.nftables.org/wiki-nftables/index.php/Main_Page"}},
		Standards: check.Standards{CWE: []string{"CWE-923"}, NIST: []string{"SC-7"}, CISTopic: "Host-based firewall configured"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if out, err := s.Run(ctx, "ufw", "status", "verbose"); err == nil && strings.Contains(strings.ToLower(out), "status: active") {
				l := strings.ToLower(out)
				if strings.Contains(l, "default: deny (incoming)") || strings.Contains(l, "default: reject (incoming)") {
					return []check.Result{check.PassR("firewall", "ufw has a default-deny incoming policy")}
				}
				return []check.Result{check.FailR("firewall", "ufw is active but its incoming default policy is not deny or reject")}
			}
			if out, err := s.Run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(out) == "running" {
				return []check.Result{check.IncompleteR("firewall", "firewalld is running, but its effective active-zone policy could not be determined")}
			}
			if out, err := s.Run(ctx, "nft", "list", "ruleset"); err == nil {
				l := strings.ToLower(out)
				if nftInputDefaultDeny(l) {
					return []check.Result{check.PassR("firewall", "nftables filters input traffic")}
				}
			}
			if out, err := s.Run(ctx, "iptables", "-S"); err == nil {
				if strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT") {
					return []check.Result{check.PassR("firewall", "iptables filters input traffic")}
				}
				return []check.Result{check.FailR("firewall", "iptables has no drop or reject rules (input policy ACCEPT)")}
			}
			return []check.Result{check.FailR("firewall", "No active host firewall detected (ufw, firewalld, nftables, iptables)")}
		},
	})
}

func nftInputDefaultDeny(rules string) bool {
	for _, block := range strings.Split(rules, "}") {
		if strings.Contains(block, "hook input") && (strings.Contains(block, "policy drop") || strings.Contains(block, "policy reject")) {
			return true
		}
	}
	return false
}
