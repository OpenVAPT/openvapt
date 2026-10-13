package host

import (
	"context"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// fileModeRule checks that existing files matching patterns are not readable
// or writable beyond what is safe. One table entry becomes one check.
type fileModeRule struct {
	id, title, summary, rationale, fix, verify string
	sev                                        check.Severity
	cat                                        check.Category
	cvss                                       string
	patterns                                   []string
	bad                                        fs.FileMode // permission bits that must not be set
	why                                        string
	cwe                                        string
	refs                                       []check.Ref
}

var fileModeRules = []fileModeRule{
	{
		id: "HOST-SSH-009", title: "SSH Host Private Keys Readable by Others", sev: check.High, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		summary:   "Checks that SSH host private keys are readable only by root.",
		rationale: "Anyone who can read a host private key can impersonate the server and intercept SSH sessions from users who trust it.",
		fix:       "chown root:root /etc/ssh/ssh_host_*_key && chmod 600 /etc/ssh/ssh_host_*_key  (0640 with group ssh_keys is acceptable on RHEL family).",
		verify:    "stat -c '%a %U:%G %n' /etc/ssh/ssh_host_*_key",
		patterns:  []string{"/etc/ssh/ssh_host_*_key"}, bad: 0o004 | 0o002, why: "readable or writable by others", cwe: "CWE-732",
		refs: []check.Ref{refSSHDManual},
	},
	{
		id: "HOST-SSH-010", title: "SSH Server Configuration Writable by Non-Root Users", sev: check.High, cat: check.CatAccess,
		cvss:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		summary:   "Checks that the SSH daemon configuration cannot be modified by group or other users.",
		rationale: "Whoever can edit sshd_config can enable root login, add their own keys file location or weaken authentication.",
		fix:       "chown root:root /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf && chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf",
		verify:    "stat -c '%a %U %n' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*",
		patterns:  []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"}, bad: 0o022, why: "writable by group or others", cwe: "CWE-732",
		refs: []check.Ref{refSSHDManual},
	},
	{
		id: "HOST-FS-006", title: "Boot Loader Configuration Exposed", sev: check.Medium, cat: check.CatAccess,
		cvss:      "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		summary:   "Checks that the GRUB configuration is not readable or writable by normal users.",
		rationale: "The boot loader configuration controls kernel parameters at boot. If writable, it allows boot-time privilege escalation; if readable, it may expose a boot password hash.",
		fix:       "chown root:root <grub.cfg> && chmod 600 <grub.cfg>  (for example /boot/grub/grub.cfg or /boot/grub2/grub.cfg).",
		verify:    "stat -c '%a %U %n' /boot/grub/grub.cfg /boot/grub2/grub.cfg",
		patterns:  []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/grub2/user.cfg"}, bad: 0o077, why: "accessible by group or others", cwe: "CWE-732",
		refs: []check.Ref{{Title: "GNU GRUB Manual, Security", URL: "https://www.gnu.org/software/grub/manual/grub/html_node/Security.html"}},
	},
	{
		id: "HOST-FS-007", title: "Private TLS Keys Readable by Others", sev: check.High, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		summary:   "Checks that TLS private keys under the standard key directories are not readable by other users.",
		rationale: "A stolen private key lets an attacker impersonate your websites and, with older key exchange, decrypt recorded traffic.",
		fix:       "chown root:root <key> && chmod 600 <key>  (or 640 with a dedicated group the web server runs in). Rotate any key that was exposed.",
		verify:    "stat -c '%a %U:%G %n' /etc/ssl/private/* /etc/pki/tls/private/* /etc/letsencrypt/archive/*/privkey*.pem",
		patterns:  []string{"/etc/ssl/private/*", "/etc/pki/tls/private/*", "/etc/letsencrypt/archive/*/privkey*.pem"}, bad: 0o004 | 0o002, why: "readable or writable by others", cwe: "CWE-732",
		refs: []check.Ref{{Title: "OWASP Key Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"}},
	},
	{
		id: "HOST-LOG-003", title: "Security Logs Readable by All Users", sev: check.Low, cat: check.CatLogging,
		cvss:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
		summary:   "Checks that authentication and system logs are not world-readable.",
		rationale: "Authentication logs contain user names, source addresses and sometimes passwords typed into the user name field. Only administrators should read them.",
		fix:       "chmod o-rwx /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages  and set the matching create mode in /etc/logrotate.d.",
		verify:    "stat -c '%a %n' /var/log/auth.log /var/log/secure",
		patterns:  []string{"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages"}, bad: 0o004 | 0o002, why: "readable or writable by others", cwe: "CWE-532",
		refs: []check.Ref{{Title: "NIST SP 800-92, Guide to Computer Security Log Management", URL: "https://csrc.nist.gov/pubs/sp/800/92/final"}},
	},
}

func init() {
	for _, r := range fileModeRules {
		registerFileMode(r)
	}
	registerHardening()
}

// registerFileMode turns one file permission rule into a registered check.
func registerFileMode(r fileModeRule) {
	{
		check.Register(&check.Check{
			ID: r.id, Title: r.title, Domain: check.DomainHost, Severity: r.sev, Category: r.cat, Effort: check.EffortLow, CVSS: r.cvss,
			Summary: r.summary, Rationale: r.rationale,
			Detection: "Stats every existing file matching " + strings.Join(r.patterns, ", ") + " (metadata only, contents are never read) and fails if it is " + r.why + ".",
			Fix:       r.fix, Verify: r.verify, Refs: r.refs,
			Standards: check.Standards{CWE: []string{r.cwe}, NIST: []string{"AC-3", "AC-6"}},
			Run: func(ctx context.Context, s sys.System) []check.Result {
				var bad []string
				seen := 0
				for _, pat := range r.patterns {
					paths := []string{pat}
					if strings.ContainsAny(pat, "*?[") {
						paths, _ = s.Glob(pat)
					}
					for _, p := range paths {
						st, err := s.Stat(p)
						if err != nil || st.IsDir {
							continue
						}
						seen++
						if st.Mode.Perm()&r.bad != 0 {
							bad = append(bad, perm(st.Mode)+" "+p)
						}
					}
				}
				if seen == 0 {
					return []check.Result{check.SkipR(r.patterns[0], "No matching files found")}
				}
				if len(bad) > 0 {
					return []check.Result{check.FailR(r.patterns[0], fmt.Sprintf("%d file(s) are %s", len(bad), r.why), bad...)}
				}
				return []check.Result{check.PassR(r.patterns[0], fmt.Sprintf("%d file(s) have safe permissions", seen))}
			},
		})
	}
}

func registerHardening() {
	check.Register(&check.Check{
		ID: "HOST-SSH-011", Title: "SSH Legacy Trust Options Enabled", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks for host-based trust and user environment options that weaken SSH authentication.",
		Rationale: "HostbasedAuthentication and ignoring .rhosts trust other machines instead of users. PermitUserEnvironment lets users set variables such as LD_PRELOAD that can bypass restrictions.",
		Detection: "Reads hostbasedauthentication, ignorerhosts and permituserenvironment from the effective sshd configuration (all evaluated Match contexts).",
		Fix:       "Set  HostbasedAuthentication no ,  IgnoreRhosts yes  and  PermitUserEnvironment no  in /etc/ssh/sshd_config, then reload sshd.",
		Verify:    "sshd -T | grep -Ei 'hostbasedauthentication|ignorerhosts|permituserenvironment'",
		Refs:      []check.Ref{refSSHDManual},
		Standards: check.Standards{CWE: []string{"CWE-287", "CWE-15"}, NIST: []string{"IA-2", "CM-6"}, CISTopic: "SSH host-based authentication and user environment"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			var bad []string
			if cfg["hostbasedauthentication"] == "yes" {
				bad = append(bad, "hostbasedauthentication yes")
			}
			if cfg["ignorerhosts"] == "no" {
				bad = append(bad, "ignorerhosts no")
			}
			if v := cfg["permituserenvironment"]; v != "" && v != "no" {
				bad = append(bad, "permituserenvironment "+v)
			}
			if len(bad) > 0 {
				return []check.Result{check.FailR("sshd", "Legacy trust options are enabled", bad...)}
			}
			return []check.Result{check.PassR("sshd", "No legacy trust options enabled")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SSH-012", Title: "SSH Logging Level Too Low", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks that sshd logs at INFO or VERBOSE level.",
		Rationale: "QUIET, FATAL or ERROR levels drop login records, so failed and successful logins cannot be investigated. VERBOSE also records the key fingerprint used.",
		Detection: "Reads loglevel from the effective sshd configuration; INFO and VERBOSE pass.",
		Fix:       "Set  LogLevel VERBOSE  (or INFO) in /etc/ssh/sshd_config and reload sshd.",
		Verify:    "sshd -T | grep -i loglevel",
		Refs:      []check.Ref{refSSHDManual},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-2", "AU-3"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg, ok := collect.SSHD(ctx, s)
			if !ok {
				return []check.Result{check.SkipR("sshd", "SSH daemon configuration not found")}
			}
			v := cfg["loglevel"]
			if v == "" || v == "info" || v == "verbose" {
				return []check.Result{check.PassR("sshd", "LogLevel "+orDefault(v))}
			}
			return []check.Result{check.FailR("sshd", "LogLevel "+v+" drops login records")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-008", Title: "Temporary Filesystems Allow Executables or Devices", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that /tmp, /var/tmp and /dev/shm are mounted with nodev and nosuid.",
		Rationale: "World-writable temporary areas are where attackers drop tools. nosuid stops planted setuid programs working there, and nodev stops device files being created.",
		Detection: "Reads /proc/mounts. For each of /tmp, /var/tmp and /dev/shm that is a separate mount, nodev and nosuid must be present. Paths that are not separate mounts are reported as skipped.",
		Fix:       "Mount the path as tmpfs or a separate filesystem with options nodev,nosuid (and noexec where software allows), for example via systemd tmp.mount or /etc/fstab, then remount.",
		Verify:    "findmnt -no OPTIONS /tmp /var/tmp /dev/shm",
		Refs:      []check.Ref{{Title: "mount(8), Linux man-pages (nodev, nosuid, noexec)", URL: "https://man7.org/linux/man-pages/man8/mount.8.html"}},
		Standards: check.Standards{CWE: []string{"CWE-276"}, NIST: []string{"CM-6", "CM-7"}, CISTopic: "Separate partitions and mount options for temporary directories"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			text, _, ok := readText(ctx, s, "/proc/mounts")
			if !ok {
				return []check.Result{check.SkipR("/proc/mounts", "Not readable")}
			}
			opts := map[string]string{}
			for _, line := range strings.Split(text, "\n") {
				f := strings.Fields(line)
				if len(f) >= 4 {
					opts[f[1]] = f[3]
				}
			}
			var out []check.Result
			for _, mp := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
				o, ok := opts[mp]
				if !ok {
					continue
				}
				var miss []string
				for _, need := range []string{"nodev", "nosuid"} {
					if !strings.Contains(","+o+",", ","+need+",") {
						miss = append(miss, need)
					}
				}
				if len(miss) > 0 {
					out = append(out, check.FailR(mp, mp+" is mounted without "+strings.Join(miss, ", "), "options "+o))
				} else {
					out = append(out, check.PassR(mp, mp+" has nodev and nosuid", "options "+o))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("/proc/mounts", "Temporary directories are not separate mounts")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "HOST-FS-009", Title: "Default File Creation Mask Too Permissive", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that the default umask makes new files unreadable to other users (027 or stricter).",
		Rationale: "With umask 022 every new file is readable by every local user, including configuration exports, reports and backups created by administrators.",
		Detection: "Reads UMASK from /etc/login.defs. Values that leave the 'other' read bit open (for example 022 or 002) fail.",
		Fix:       "Set  UMASK 027  in /etc/login.defs (and, if used, in /etc/profile or /etc/bash.bashrc).",
		Verify:    "grep '^UMASK' /etc/login.defs",
		Refs:      []check.Ref{refLoginDefs, {Title: "umask(2), Linux man-pages", URL: "https://man7.org/linux/man-pages/man2/umask.2.html"}},
		Standards: check.Standards{CWE: []string{"CWE-276"}, NIST: []string{"AC-6", "CM-6"}, CISTopic: "Default user umask"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			cfg := collect.ReadConfigs(ctx, s, "/etc/login.defs")
			if len(cfg) == 0 {
				return []check.Result{check.SkipR("/etc/login.defs", "File not found")}
			}
			v, _, ok := collect.First(cfg, "umask")
			n, err := strconv.ParseUint(strings.TrimSpace(v), 8, 32)
			if !ok || err != nil {
				return []check.Result{check.FailR("/etc/login.defs", "UMASK is not set")}
			}
			if n&0o004 == 0 {
				return []check.Result{check.FailR("/etc/login.defs", "UMASK "+v+" lets other users read new files (recommended 027)")}
			}
			return []check.Result{check.PassR("/etc/login.defs", "UMASK "+v)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-MAC-001", Title: "No Mandatory Access Control Enforced", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortHigh,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that AppArmor or SELinux is enabled and enforcing.",
		Rationale: "Mandatory access control confines services even when they run as root, so a compromised web server or database cannot freely read or change the rest of the system.",
		Detection: "Reads /sys/fs/selinux/enforce (1 means enforcing) and /sys/module/apparmor/parameters/enabled (Y means enabled).",
		Fix:       "Ubuntu/Debian: keep AppArmor enabled (systemctl enable --now apparmor) and its profiles in enforce mode. RHEL family: set SELINUX=enforcing in /etc/selinux/config and relabel. Test applications in permissive or complain mode first.",
		Verify:    "getenforce  or  aa-status",
		Refs:      []check.Ref{{Title: "Linux kernel documentation, Linux Security Module development and LSMs", URL: "https://docs.kernel.org/admin-guide/LSM/index.html"}},
		Standards: check.Standards{CWE: []string{"CWE-250"}, NIST: []string{"AC-3(3)", "AC-6"}, CISTopic: "Mandatory access control"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if v, _, ok := readText(ctx, s, "/sys/fs/selinux/enforce"); ok && strings.TrimSpace(v) == "1" {
				return []check.Result{check.PassR("selinux", "SELinux is enforcing")}
			}
			if v, _, ok := readText(ctx, s, "/sys/module/apparmor/parameters/enabled"); ok && strings.TrimSpace(v) == "Y" {
				return []check.Result{check.PassR("apparmor", "AppArmor is enabled")}
			}
			return []check.Result{check.FailR("mac", "Neither SELinux (enforcing) nor AppArmor is active")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-UPD-001", Title: "Automatic Security Updates Not Configured", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatPatch, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that security updates are installed automatically.",
		Rationale: "Many compromises use vulnerabilities fixed days or weeks earlier. Automatic security updates close that window without relying on someone remembering.",
		Detection: "Debian/Ubuntu: reads /etc/apt/apt.conf.d/20auto-upgrades (and 50unattended-upgrades) for APT::Periodic::Unattended-Upgrade \"1\". RHEL family: asks systemd whether dnf-automatic.timer or dnf-automatic-install.timer is active.",
		Fix:       "Debian/Ubuntu: apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades . RHEL family: dnf install dnf-automatic, set apply_updates = yes and upgrade_type = security, then systemctl enable --now dnf-automatic.timer .",
		Verify:    "Re-run this check.",
		Refs:      []check.Ref{{Title: "Debian, UnattendedUpgrades", URL: "https://wiki.debian.org/UnattendedUpgrades"}, {Title: "NIST SP 800-40 Rev. 4", URL: "https://csrc.nist.gov/pubs/sp/800/40/r4/final"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, OWASP: []string{"A06:2021"}, NIST: []string{"SI-2(2)"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			for _, p := range []string{"/etc/apt/apt.conf.d/20auto-upgrades", "/etc/apt/apt.conf.d/50unattended-upgrades"} {
				if t, _, ok := readText(ctx, s, p); ok && strings.Contains(t, `Unattended-Upgrade "1"`) {
					return []check.Result{check.PassR(p, "Unattended upgrades are enabled")}
				}
			}
			if u, ok := collect.ServiceActive(ctx, s, "dnf-automatic.timer", "dnf-automatic-install.timer"); ok {
				return []check.Result{check.PassR(u, u+" is active")}
			}
			return []check.Result{check.FailR("updates", "No automatic security update mechanism is enabled")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-UPD-002", Title: "Reboot Required to Apply Updates", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatPatch, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks whether installed updates (often kernel or core library fixes) are waiting for a reboot.",
		Rationale: "Updated packages do not protect anything until the running kernel and libraries are replaced. A pending reboot means known-fixed vulnerabilities are still live.",
		Detection: "Checks for /var/run/reboot-required (Debian/Ubuntu) and reads the package list in /var/run/reboot-required.pkgs when present.",
		Fix:       "Schedule a maintenance window and reboot (or use live patching where supported).",
		Verify:    "ls /var/run/reboot-required  should not exist after the reboot.",
		Refs:      []check.Ref{{Title: "NIST SP 800-40 Rev. 4", URL: "https://csrc.nist.gov/pubs/sp/800/40/r4/final"}},
		Standards: check.Standards{CWE: []string{"CWE-1104"}, NIST: []string{"SI-2"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if _, err := s.Stat("/var/run/reboot-required"); err == nil {
				ev := []string{"/var/run/reboot-required exists"}
				if t, _, ok := readText(ctx, s, "/var/run/reboot-required.pkgs"); ok {
					ev = append(ev, firstN(strings.Fields(t), 20)...)
				}
				return []check.Result{check.FailR("reboot", "A reboot is required to apply installed updates", ev...)}
			}
			if _, err := s.Stat("/etc/debian_version"); err != nil {
				return []check.Result{check.SkipR("reboot", "Reboot-required marker is a Debian/Ubuntu feature")}
			}
			return []check.Result{check.PassR("reboot", "No reboot is pending")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SVC-001", Title: "Unnecessary Legacy Services Running", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks for desktop and legacy network services that servers rarely need.",
		Rationale: "Each running service adds attack surface. Zeroconf discovery, printing, RPC portmapping and inetd-style super-servers are common, long-forgotten exposures.",
		Detection: "Asks systemd whether avahi-daemon, cups, rpcbind, xinetd, telnet.socket, rsh.socket, rlogin.socket or vsftpd is active.",
		Fix:       "systemctl disable --now <service>  for each listed service you do not need, or remove its package.",
		Verify:    "systemctl is-active avahi-daemon cups rpcbind xinetd",
		Refs:      []check.Ref{{Title: "NIST SP 800-123, Guide to General Server Security", URL: "https://csrc.nist.gov/pubs/sp/800/123/final"}},
		Standards: check.Standards{CWE: []string{"CWE-1188"}, NIST: []string{"CM-7"}, CISTopic: "Remove or disable unnecessary services"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var on []string
			for _, u := range []string{"avahi-daemon", "cups", "rpcbind", "xinetd", "telnet.socket", "rsh.socket", "rlogin.socket", "vsftpd"} {
				if _, ok := collect.ServiceActive(ctx, s, u); ok {
					on = append(on, u)
				}
			}
			if len(on) > 0 {
				return []check.Result{check.FailR("services", "Unnecessary services are active", on...)}
			}
			return []check.Result{check.PassR("services", "No unnecessary legacy services are active")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-DKR-001", Title: "Users With Root-Equivalent Docker Access", Domain: check.DomainHost,
		Severity: check.High, Category: check.CatIdentity, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Checks whether non-root users can control Docker, which is equivalent to root access.",
		Rationale: "Members of the docker group, or anyone who can write to the Docker socket, can start a container that mounts the host filesystem and become root.",
		Detection: "Reads members of the docker group from /etc/group and the permissions of /var/run/docker.sock.",
		Fix:       "Remove users who do not need it from the docker group (gpasswd -d <user> docker); consider rootless Docker or Podman; keep docker.sock at 660 root:docker.",
		Verify:    "getent group docker ; stat -c '%a %U:%G' /var/run/docker.sock",
		Refs:      []check.Ref{{Title: "Docker documentation, Docker daemon attack surface", URL: "https://docs.docker.com/engine/security/#docker-daemon-attack-surface"}},
		Standards: check.Standards{CWE: []string{"CWE-269", "CWE-250"}, NIST: []string{"AC-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var ev []string
			if t, _, ok := readText(ctx, s, "/etc/group"); ok {
				for _, line := range strings.Split(t, "\n") {
					f := strings.Split(line, ":")
					if len(f) >= 4 && f[0] == "docker" && strings.TrimSpace(f[3]) != "" {
						ev = append(ev, "docker group members: "+f[3])
					}
				}
			}
			st, err := s.Stat("/var/run/docker.sock")
			if err == nil && st.Mode.Perm()&0o002 != 0 {
				ev = append(ev, "/var/run/docker.sock is world-writable ("+perm(st.Mode)+")")
			}
			if err != nil && len(ev) == 0 {
				return []check.Result{check.SkipR("docker", "Docker is not installed")}
			}
			if len(ev) > 0 {
				return []check.Result{check.FailR("docker", "Non-root users can control Docker (root equivalent)", ev...)}
			}
			return []check.Result{check.PassR("docker", "Docker access is restricted to root")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-SUDO-001", Title: "Sudo Commands Not Logged to a Dedicated File", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks that sudo uses a pseudo-terminal and keeps its own log file.",
		Rationale: "Defaults use_pty stops background processes from a sudo session lingering after it ends. A dedicated logfile keeps an easily reviewed record of privileged commands.",
		Detection: "Reads /etc/sudoers and /etc/sudoers.d/* for 'Defaults use_pty' and 'Defaults logfile='.",
		Fix:       "With visudo add:  Defaults use_pty  and  Defaults logfile=\"/var/log/sudo.log\"",
		Verify:    "grep -rE 'use_pty|logfile' /etc/sudoers /etc/sudoers.d",
		Refs:      []check.Ref{{Title: "sudoers(5) manual", URL: "https://www.sudo.ws/docs/man/sudoers.man/"}},
		Standards: check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, NIST: []string{"AU-2", "AU-12"}, CISTopic: "Sudo uses pty and log file"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			files := []string{"/etc/sudoers"}
			more, _ := s.Glob("/etc/sudoers.d/*")
			files = append(files, more...)
			var all strings.Builder
			read := false
			for _, f := range files {
				if t, _, ok := readText(ctx, s, f); ok {
					read = true
					all.WriteString(t + "\n")
				}
			}
			if !read {
				return []check.Result{check.SkipR("/etc/sudoers", "Not readable (run as root for this check)")}
			}
			var miss []string
			if !strings.Contains(all.String(), "use_pty") {
				miss = append(miss, "Defaults use_pty")
			}
			if !strings.Contains(all.String(), "logfile") {
				miss = append(miss, "Defaults logfile=")
			}
			if len(miss) > 0 {
				return []check.Result{check.FailR("/etc/sudoers", "Missing: "+strings.Join(miss, ", "))}
			}
			return []check.Result{check.PassR("/etc/sudoers", "sudo uses a pty and a dedicated log file")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-IDS-001", Title: "No Brute-Force Protection Service", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that a log-based intrusion prevention service (fail2ban, sshguard or CrowdSec) is running.",
		Rationale: "Internet-facing services receive constant guessing. Automatically blocking sources that fail repeatedly reduces noise and risk, and turns logs into active defence.",
		Detection: "Asks systemd whether fail2ban, sshguard or crowdsec is active.",
		Fix:       "Install and enable one, for example: apt install fail2ban && systemctl enable --now fail2ban , with an sshd jail enabled.",
		Verify:    "systemctl is-active fail2ban",
		Refs:      []check.Ref{{Title: "fail2ban project", URL: "https://github.com/fail2ban/fail2ban"}, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-307"}, OWASP: []string{"A07:2021"}, NIST: []string{"SI-4", "AC-7"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if u, ok := collect.ServiceActive(ctx, s, "fail2ban", "sshguard", "crowdsec"); ok {
				return []check.Result{check.PassR(u, u+" is active")}
			}
			return []check.Result{check.FailR("ids", "No brute-force protection service is active")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-LOG-004", Title: "Log Rotation Not Configured", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatLogging, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
		Summary:   "Checks that logrotate (or journald size limits) keeps logs from filling the disk.",
		Rationale: "Unrotated logs eventually fill the disk and stop services, and an attacker can deliberately flood logs to cause that or to hide activity.",
		Detection: "Checks for /etc/logrotate.conf, or a SystemMaxUse setting in /etc/systemd/journald.conf.",
		Fix:       "Install logrotate (apt install logrotate / dnf install logrotate) and keep its daily timer enabled, or set SystemMaxUse= in journald.conf.",
		Verify:    "ls /etc/logrotate.conf ; systemctl is-active logrotate.timer",
		Refs:      []check.Ref{{Title: "logrotate(8), Linux man-pages", URL: "https://man7.org/linux/man-pages/man8/logrotate.8.html"}},
		Standards: check.Standards{CWE: []string{"CWE-400"}, NIST: []string{"AU-4", "AU-11"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			if _, err := s.Stat("/etc/logrotate.conf"); err == nil {
				return []check.Result{check.PassR("/etc/logrotate.conf", "logrotate is configured")}
			}
			cfg := collect.ReadConfigs(ctx, s, "/etc/systemd/journald.conf")
			if v, _, ok := collect.First(cfg, "systemmaxuse"); ok && v != "" {
				return []check.Result{check.PassR("journald.conf", "SystemMaxUse="+v)}
			}
			return []check.Result{check.FailR("logs", "No log rotation or journal size limit configured")}
		},
	})
}
