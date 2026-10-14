package host

import (
	"context"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// HOST-SVC inventory: legacy and rarely needed services that are installed
// or enabled at boot. HOST-SVC-001 asks systemd what is active right now;
// these checks look at what is installed (dpkg status, dpkg info, rpm) and
// what is wanted at boot (*.wants links, systemctl is-enabled), because a
// service that is installed but stopped comes back with the next package
// upgrade or reboot and is one command away from running.

// legacyRule describes one family of services. One rule becomes one check.
type legacyRule struct {
	id, title               string
	sev                     check.Severity
	cvss                    string
	cwe                     []string
	pkgs, units             []string
	summary, rationale, fix string
	cisTopic                string
	refs                    []check.Ref
	cleartext               bool // the protocol itself sends credentials or data unencrypted
	whenNeeded              string
}

var (
	cvssLegacyLow    = "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
	cvssLegacyMedium = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
	refTelnetRisk    = check.Ref{Title: "MITRE ATT&CK T1040, Network Sniffing", URL: "https://attack.mitre.org/techniques/T1040/"}
	refNFSSec        = check.Ref{Title: "NFS security, Linux kernel documentation (exports and rpcbind)", URL: "https://docs.kernel.org/filesystems/nfs/index.html"}
)

var legacyRules = []legacyRule{
	{
		id: "HOST-SVC-002", title: "Telnet Server Installed or Enabled", sev: check.Medium, cvss: cvssLegacyMedium,
		cwe:       []string{"CWE-319", "CWE-1188"},
		pkgs:      []string{"telnetd", "inetutils-telnetd", "telnetd-ssl", "telnet-server"},
		units:     []string{"telnet.socket", "telnetd.service", "inetutils-telnetd.service"},
		summary:   "Checks whether a Telnet server is installed or set to start at boot.",
		rationale: "Telnet sends user names, passwords and every keystroke in the clear. Anyone on the network path reads them. SSH replaced it decades ago; a Telnet server on a modern server is almost always forgotten rather than needed.",
		fix:       "apt purge telnetd inetutils-telnetd  or  dnf remove telnet-server , and  systemctl disable --now telnet.socket . Use SSH.",
		cisTopic:  "Telnet server is not installed (CIS Controls v8 4.8)", refs: []check.Ref{refTelnetRisk, refNIST800123}, cleartext: true,
	},
	{
		id: "HOST-SVC-003", title: "rsh, rlogin, rexec or finger Server Installed or Enabled", sev: check.Medium, cvss: cvssLegacyMedium,
		cwe:       []string{"CWE-319", "CWE-1188"},
		pkgs:      []string{"rsh-server", "rsh-redone-server", "fingerd", "finger-server", "efingerd", "cfingerd"},
		units:     []string{"rsh.socket", "rlogin.socket", "rexec.socket", "finger.socket", "rsh-redone-server.service", "fingerd.service"},
		summary:   "Checks whether the Berkeley r-services (rsh, rlogin, rexec) or a finger server is installed or enabled.",
		rationale: "The r-services trust the client's claim of who it is and send everything unencrypted; .rhosts files (HOST-USR-007) exist for them. finger lists account names and login times to anyone who asks, which is reconnaissance for password guessing.",
		fix:       "apt purge rsh-server rsh-redone-server fingerd  or  dnf remove rsh-server finger-server , and  systemctl disable --now rsh.socket rlogin.socket rexec.socket finger.socket .",
		cisTopic:  "rsh and finger servers are not installed (CIS Controls v8 4.8)", refs: []check.Ref{refTelnetRisk, refNIST800123}, cleartext: true,
	},
	{
		id: "HOST-SVC-004", title: "TFTP Server Installed or Enabled", sev: check.Medium, cvss: cvssLegacyMedium,
		cwe:       []string{"CWE-306", "CWE-1188"},
		pkgs:      []string{"tftpd-hpa", "atftpd", "tftp-server", "tftpd"},
		units:     []string{"tftpd-hpa.service", "atftpd.service", "tftp.socket", "tftp.service"},
		summary:   "Checks whether a TFTP server is installed or set to start at boot.",
		rationale: "TFTP has no authentication and no encryption: any client that can reach it can read, and often write, every file in its directory. It is needed only on network boot (PXE) servers and for some network equipment, and is a frequent source of leaked configuration files.",
		fix:       "apt purge tftpd-hpa atftpd  or  dnf remove tftp-server , and  systemctl disable --now tftpd-hpa.service tftp.socket . Where PXE is required, serve only that directory, read-only, from a dedicated host.",
		cisTopic:  "TFTP server is not installed (CIS Controls v8 4.8)", refs: []check.Ref{refNIST800123}, cleartext: true,
		whenNeeded: "network boot (PXE) servers",
	},
	{
		id: "HOST-SVC-005", title: "FTP Server Installed or Enabled", sev: check.Medium, cvss: cvssLegacyMedium,
		cwe:       []string{"CWE-319", "CWE-1188"},
		pkgs:      []string{"vsftpd", "proftpd-core", "proftpd-basic", "proftpd", "pure-ftpd", "pure-ftpd-common"},
		units:     []string{"vsftpd.service", "proftpd.service", "pure-ftpd.service"},
		summary:   "Checks whether an FTP server (vsftpd, ProFTPD or Pure-FTPd) is installed or set to start at boot.",
		rationale: "Plain FTP sends passwords and files unencrypted and needs a wide range of ports open. SFTP over SSH, which the SSH server already provides, does the same job encrypted. An FTP server is usually a leftover from a web hosting panel.",
		fix:       "Move users to SFTP (the OpenSSH internal-sftp subsystem), then  apt purge vsftpd proftpd-core pure-ftpd  or  dnf remove vsftpd proftpd  and  systemctl disable --now vsftpd . If FTP must stay, enforce TLS (FTPS) and restrict it to named users.",
		cisTopic:  "FTP server is not installed (CIS Controls v8 4.8)", refs: []check.Ref{refTelnetRisk, refNIST800123}, cleartext: true,
		whenNeeded: "hosts that must serve legacy FTP clients",
	},
	{
		id: "HOST-SVC-006", title: "NIS Server or Client Installed or Enabled", sev: check.Medium, cvss: cvssLegacyMedium,
		cwe:       []string{"CWE-319", "CWE-522"},
		pkgs:      []string{"nis", "ypserv", "ypbind", "yp-tools"},
		units:     []string{"ypserv.service", "ypbind.service", "nis.service", "yppasswdd.service"},
		summary:   "Checks whether the Network Information Service (NIS, ypserv or ypbind) is installed or enabled.",
		rationale: "NIS distributes account and password hash databases over the network without encryption or strong authentication; anyone who can reach the server can request the whole password map. HOST-USR-006 looks for its + entries in the account files; this check looks for the software itself.",
		fix:       "Replace NIS with a modern directory (SSSD with LDAPS or FreeIPA), then  apt purge nis  or  dnf remove ypserv ypbind  and  systemctl disable --now ypserv ypbind .",
		cisTopic:  "NIS server and client are not installed (CIS Controls v8 4.8)", refs: []check.Ref{refTelnetRisk, refNIST800123}, cleartext: true,
	},
	{
		id: "HOST-SVC-007", title: "Avahi or CUPS Installed or Enabled", sev: check.Low, cvss: cvssLegacyLow,
		cwe:       []string{"CWE-1188"},
		pkgs:      []string{"avahi-daemon", "cups", "cups-daemon"},
		units:     []string{"avahi-daemon.service", "avahi-daemon.socket", "cups.service", "cups.socket", "cups-browsed.service"},
		summary:   "Checks whether zero-configuration discovery (Avahi) or the printing system (CUPS) is installed or enabled.",
		rationale: "Avahi announces the machine and its services to the local network, and CUPS listens for print jobs and runs a web interface. Both are desktop features with a history of vulnerabilities and no purpose on a server.",
		fix:       "apt purge avahi-daemon cups cups-daemon  or  dnf remove avahi cups , and  systemctl disable --now avahi-daemon.socket avahi-daemon.service cups.socket cups.service .",
		cisTopic:  "Avahi and CUPS are not installed (CIS Controls v8 4.8)", refs: []check.Ref{refNIST800123},
		whenNeeded: "desktops and print servers",
	},
	{
		id: "HOST-SVC-008", title: "NFS Server or rpcbind Installed or Enabled", sev: check.Low, cvss: cvssLegacyLow,
		cwe:       []string{"CWE-1188", "CWE-306"},
		pkgs:      []string{"nfs-kernel-server", "rpcbind"},
		units:     []string{"nfs-server.service", "rpcbind.service", "rpcbind.socket", "nfs-kernel-server.service"},
		summary:   "Checks whether the NFS server or the RPC port mapper (rpcbind) is installed or enabled.",
		rationale: "NFS exports whole directory trees with trust based on client IP address and numeric user ids, and rpcbind tells any caller which RPC services are running. Unless this machine is a file server, both are attack surface with no benefit. The rpcbind package is often pulled in as a dependency and left running.",
		fix:       "apt purge nfs-kernel-server rpcbind  or  dnf remove nfs-utils rpcbind  where NFS is not served, and  systemctl disable --now nfs-server rpcbind.socket rpcbind.service . Where NFS is required, export read-only with root_squash to named hosts and firewall port 2049 and 111.",
		cisTopic:  "NFS and rpcbind are not installed unless required (CIS Controls v8 4.8)", refs: []check.Ref{refNFSSec, refNIST800123},
		whenNeeded: "file servers",
	},
	{
		id: "HOST-SVC-009", title: "DHCP or DNS Server Installed or Enabled", sev: check.Low, cvss: cvssLegacyLow,
		cwe:       []string{"CWE-1188"},
		pkgs:      []string{"isc-dhcp-server", "dhcp-server", "kea-dhcp4-server", "kea-dhcp6-server", "bind9", "bind", "bind9-dnsutils-server"},
		units:     []string{"isc-dhcp-server.service", "dhcpd.service", "kea-dhcp4-server.service", "named.service", "bind9.service"},
		summary:   "Checks whether a DHCP server or an authoritative or recursive DNS server (BIND) is installed or enabled on a machine that is not a network server.",
		rationale: "A rogue DHCP server hands out addresses and gateways to the whole network segment, and BIND is a large, privileged network service with a long vulnerability history. Both belong on dedicated infrastructure hosts. On a web or application server they are either forgotten or an attacker's foothold.",
		fix:       "apt purge isc-dhcp-server bind9  or  dnf remove dhcp-server bind , and  systemctl disable --now isc-dhcp-server named . If this machine is meant to be a DNS or DHCP server, record that in the suppression file and review NET-SVC findings for its configuration.",
		cisTopic:  "DHCP and DNS servers are not installed unless required (CIS Controls v8 4.8)", refs: []check.Ref{refNIST800123},
		whenNeeded: "dedicated network infrastructure hosts",
	},
	{
		id: "HOST-SVC-010", title: "Samba File Server Installed or Enabled", sev: check.Low, cvss: cvssLegacyLow,
		cwe:       []string{"CWE-1188"},
		pkgs:      []string{"samba"},
		units:     []string{"smbd.service", "nmbd.service", "smb.service", "nmb.service", "samba.service"},
		summary:   "Checks whether the Samba SMB file server is installed or set to start at boot.",
		rationale: "SMB file sharing exposes files, printers and authentication to the network and has been the target of worms and several critical remote code execution flaws. It is needed only on file servers for Windows-style clients.",
		fix:       "apt purge samba  or  dnf remove samba , and  systemctl disable --now smbd nmbd  (smb nmb on the RHEL family). Where it is required, disable SMB1, require signing and restrict shares to named users.",
		cisTopic:  "Samba is not installed unless required (CIS Controls v8 4.8)", refs: []check.Ref{refNIST800123},
		whenNeeded: "file servers",
	},
	{
		id: "HOST-SVC-011", title: "SNMP Agent or Squid Proxy Installed or Enabled", sev: check.Low, cvss: cvssLegacyLow,
		cwe:       []string{"CWE-1188", "CWE-319"},
		pkgs:      []string{"snmpd", "net-snmp", "squid", "squid-openssl"},
		units:     []string{"snmpd.service", "squid.service"},
		summary:   "Checks whether an SNMP agent or the Squid caching proxy is installed or enabled.",
		rationale: "SNMP v1 and v2c authenticate with a community string sent in clear text (public and private are the usual defaults) and reveal routing tables, interfaces, processes and installed software. Squid turns the machine into a relay for other traffic and is often left open. Both need a deliberate configuration to be anything but a liability.",
		fix:       "apt purge snmpd squid  or  dnf remove net-snmp squid , and  systemctl disable --now snmpd squid . If monitoring needs SNMP, use version 3 with authPriv and bind the agent to the management network.",
		cisTopic:  "SNMP and proxy servers are not installed unless required (CIS Controls v8 4.8)", refs: []check.Ref{refNIST800123},
		whenNeeded: "monitored hosts using SNMPv3 and dedicated proxy servers",
	},
	{
		id: "HOST-SVC-012", title: "inetd Super-Server Installed or Enabled", sev: check.Low, cvss: cvssLegacyLow,
		cwe:       []string{"CWE-1188"},
		pkgs:      []string{"xinetd", "openbsd-inetd", "inetutils-inetd"},
		units:     []string{"xinetd.service", "inetd.service", "openbsd-inetd.service", "inetutils-inetd.service"},
		summary:   "Checks whether xinetd or another inetd super-server is installed or enabled.",
		rationale: "inetd-style super-servers exist to launch small network services (echo, chargen, telnet, tftp) on demand from a shared configuration. On a systemd machine every service they would start has a native unit; the super-server adds a second, rarely reviewed, place where network services are switched on.",
		fix:       "apt purge xinetd openbsd-inetd  or  dnf remove xinetd , and  systemctl disable --now xinetd . Review /etc/inetd.conf and /etc/xinetd.d first so nothing needed disappears.",
		cisTopic:  "xinetd and inetd are not installed (CIS Controls v8 4.8)", refs: []check.Ref{refNIST800123},
	},
}

func init() {
	for _, r := range legacyRules {
		registerLegacy(r)
	}
}

func registerLegacy(r legacyRule) {
	detect := "Reads installed packages from /var/lib/dpkg/status (only entries marked 'install ok installed'; /var/lib/dpkg/info/*.list is a fallback used only when the status file cannot be read) and the allow-listed rpm -qa, and looks for " + strings.Join(r.pkgs, ", ") +
		". Reads the *.wants links under /etc/systemd/system (and asks the allow-listed systemctl is-enabled) for " + strings.Join(r.units, ", ") +
		". Either an installed package or an enabled unit fails. Incomplete when no package database and no systemd unit directory could be read."
	cwe := r.cwe
	nist := []string{"CM-7", "CM-7(1)"}
	if r.cleartext {
		nist = append(nist, "SC-8")
	}
	rationale := r.rationale
	if r.whenNeeded != "" {
		rationale += " If this machine is one of the " + r.whenNeeded + " that legitimately run it, record the reason in the suppression file so the finding stays visible but accepted."
	}
	check.Register(&check.Check{
		ID: r.id, Title: r.title, Domain: check.DomainHost,
		Severity: r.sev, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      r.cvss,
		Summary:   r.summary,
		Rationale: rationale,
		Detection: detect,
		Fix:       r.fix + " Before removing a package, check that no application on this machine or the network still uses the service, and keep console access when the service is remote-access related.",
		Verify:    "dpkg -l " + strings.Join(r.pkgs, " ") + " 2>/dev/null | grep '^ii' ; systemctl is-enabled " + strings.Join(r.units, " ") + " 2>/dev/null",
		Refs:      r.refs,
		Standards: check.Standards{CWE: cwe, NIST: nist, CISTopic: r.cisTopic},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			pkgs, pkgOK := installedPackages(ctx, s)
			unitsOK := exists(s, "/etc/systemd/system")
			if !pkgOK && !unitsOK {
				return []check.Result{check.IncompleteR("services", "No package database (dpkg or rpm) and no systemd unit directory could be read")}
			}
			var ev []string
			for _, p := range packagesPresent(pkgs, r.pkgs...) {
				ev = append(ev, "package "+p+" is installed")
			}
			for _, u := range enabledUnits(ctx, s, r.units...) {
				ev = append(ev, "unit "+u+" is enabled at boot")
			}
			if len(ev) > 0 {
				return []check.Result{check.FailR("services", fmt.Sprintf("%d legacy service component(s) present", len(ev)), ev...)}
			}
			msg := "Not installed and not enabled"
			if !pkgOK {
				msg = "Not enabled at boot (no package database was readable, so installation could not be confirmed)"
				return []check.Result{check.IncompleteR("services", msg)}
			}
			return []check.Result{check.PassR("services", msg)}
		},
	})
}
