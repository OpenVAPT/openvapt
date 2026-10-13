package host

import (
	"context"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID: "HOST-SSH-007", Title: "SSH Forwarding Features Enabled", Domain: check.DomainHost, Severity: check.Medium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N",
		Summary:   "Checks effective SSH Match contexts for TCP, agent, tunnel and gateway forwarding.",
		Rationale: "Forwarding can turn an SSH account into a route to protected services or expose a user's authentication agent.",
		Detection: "Evaluates sshd -T for root and an unprivileged user from loopback and a representative remote address. Any context enabling TCP, agent, tunnel or gateway forwarding fails.",
		Fix:       "Set AllowTcpForwarding no, AllowAgentForwarding no, PermitTunnel no and GatewayPorts no globally or in every applicable Match block, then reload sshd.",
		Verify:    "Run sshd -T -C user=nobody,host=localhost,addr=192.0.2.1 and confirm each forwarding option is no.",
		Refs:      []check.Ref{refSSHDManual}, Standards: check.Standards{CWE: []string{"CWE-441"}, NIST: []string{"AC-4", "CM-7"}, CISTopic: "SSH server configuration: forwarding"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			var bad []string
			for _, k := range []string{"allowtcpforwarding", "allowagentforwarding", "permittunnel", "gatewayports"} {
				v := cfg[k]
				if v == "yes" || v == "all" || v == "any" || k != "permittunnel" && v == "" {
					bad = append(bad, k+" "+map[bool]string{true: "default yes", false: v}[v == ""])
				}
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("sshd", "SSH forwarding is enabled in at least one evaluated context", bad...)}
			}
			return []check.Result{check.PassR("sshd", "SSH forwarding is disabled in all evaluated contexts")}
		},
	})
	check.Register(&check.Check{
		ID: "HOST-SSH-008", Title: "SSH Authentication Controls Too Permissive", Domain: check.DomainHost, Severity: check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks effective SSH authentication method and login grace settings.",
		Rationale: "Long login windows and unconstrained single-factor authentication give online guessing and stolen credentials more opportunity.",
		Detection: "Evaluates applicable Match contexts and flags LoginGraceTime over 60 seconds or an absent AuthenticationMethods restriction.",
		Fix:       "Set LoginGraceTime 60 or lower and choose AuthenticationMethods appropriate to the server, such as publickey, then restrict access with AllowUsers or AllowGroups where practical.",
		Verify:    "Use sshd -T -C for each allowed user and source context and inspect logingracetime, authenticationmethods, allowusers and allowgroups.",
		Refs:      []check.Ref{refSSHDManual}, Standards: check.Standards{CWE: []string{"CWE-307", "CWE-308"}, NIST: []string{"AC-7", "IA-2"}, CISTopic: "SSH server configuration: authentication restrictions"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			grace := 120
			if v := strings.TrimSuffix(cfg["logingracetime"], "s"); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					grace = n
				}
			}
			if grace > 60 || cfg["authenticationmethods"] == "" || cfg["authenticationmethods"] == "any" {
				return []check.Result{check.FailR("sshd", "SSH authentication restrictions are too permissive", "logingracetime "+strconv.Itoa(grace), "authenticationmethods "+cfg["authenticationmethods"])}
			}
			return []check.Result{check.PassR("sshd", "SSH authentication restrictions are configured")}
		},
	})
}
