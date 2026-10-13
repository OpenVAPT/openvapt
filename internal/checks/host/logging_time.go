package host

import (
	"context"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

func init() {
	check.Register(&check.Check{
		ID:        "HOST-LOG-001",
		Title:     "System Logging Not Persistent",
		Domain:    check.DomainHost,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks that system logs survive a reboot (rsyslog/syslog-ng running, or a persistent journal).",
		Rationale: "Without persistent logs there is no evidence after an incident: no record of logins, sudo use, or service errors.",
		Detection: "Checks whether rsyslog or syslog-ng is active, or whether /var/log/journal exists (systemd persistent journal).",
		Fix:       "Either install and enable rsyslog, or make the journal persistent: mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal && systemctl restart systemd-journald",
		Verify:    "ls -d /var/log/journal  or  systemctl is-active rsyslog",
		Refs:      []check.Ref{{Title: "NIST SP 800-92, Guide to Computer Security Log Management", URL: "https://csrc.nist.gov/pubs/sp/800/92/final"}, {Title: "journald.conf(5)", URL: "https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html"}},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-2", "AU-9", "AU-11"}, CISTopic: "Logging: persistent system logs"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if u, ok := collect.ServiceActive(ctx, s, "rsyslog", "syslog-ng"); ok {
				return []check.Result{check.PassR("logging", u+" is active")}
			}
			if st, err := s.Stat("/var/log/journal"); err == nil && st.IsDir {
				return []check.Result{check.PassR("logging", "systemd journal is persistent (/var/log/journal)")}
			}
			return []check.Result{check.FailR("logging", "No syslog daemon active and the journal is not persistent")}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-LOG-002",
		Title:     "Security Audit Daemon Not Running",
		Domain:    check.DomainHost,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks whether the Linux audit daemon (auditd) is running.",
		Rationale: "auditd records security-relevant events (changes to /etc/passwd, privilege use, file deletions) that ordinary logs miss, which incident responders rely on.",
		Detection: "Asks systemd whether the auditd unit is active.",
		Fix:       "Install the audit package (apt install auditd, or dnf install audit), enable it (systemctl enable --now auditd) and load a rule set appropriate to your policy.",
		Verify:    "systemctl is-active auditd  should print 'active'.",
		Refs:      []check.Ref{{Title: "auditd(8), Linux man-pages", URL: "https://man7.org/linux/man-pages/man8/auditd.8.html"}},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-2", "AU-12"}, CISTopic: "Logging and auditing: auditd"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if _, ok := collect.ServiceActive(ctx, s, "auditd"); ok {
				return []check.Result{check.PassR("auditd", "auditd is active")}
			}
			return []check.Result{check.FailR("auditd", "auditd is not active")}
		},
	})

	check.Register(&check.Check{
		ID:        "HOST-TIME-001",
		Title:     "Time Synchronisation Not Active",
		Domain:    check.DomainHost,
		Severity:  check.Low,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks that the clock is kept in sync (chrony, ntpd or systemd-timesyncd).",
		Rationale: "Accurate time is needed to correlate logs during an investigation, and TLS certificates and one-time-password codes fail when the clock drifts.",
		Detection: "Asks systemd whether chronyd, chrony, ntpd, ntp or systemd-timesyncd is active.",
		Fix:       "Enable one time service, for example: systemctl enable --now systemd-timesyncd  (or install chrony).",
		Verify:    "timedatectl  should show 'System clock synchronized: yes'.",
		Refs:      []check.Ref{refNIST80053},
		// No CWE is listed on purpose: CWE describes software weaknesses, and
		// none matches an unsynchronised clock. CWE-778 (Insufficient Logging)
		// is about security events that are not recorded at all, which is a
		// different problem from events recorded with a wrong time.
		Standards: check.Standards{NIST: []string{"AU-8"}, CISTopic: "Time synchronisation"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if u, ok := collect.ServiceActive(ctx, s, "chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp", "ntpsec"); ok {
				return []check.Result{check.PassR("time", u+" is active")}
			}
			return []check.Result{check.FailR("time", "No time synchronisation service is active")}
		},
	})
}
