# Defence Playbook: Remediate, Harden, Detect, Respond

Every change here modifies the machine, and some steps (package updates, certificate renewal, image scanners) download from the internet, so say so before running them. Every change needs the user's approval first. The pattern is always the same:

1. **Back up**: copy the file, keeping its path, to a backup folder outside any web root, for example `sudo install -d -m 700 /root/vapt-backups/$(date -u +%Y%m%dT%H%M%SZ)` then `sudo cp -a --parents /etc/ssh/sshd_config <that folder>/`.
2. **Change** one thing.
3. **Validate** before reload (`sshd -t`, `nginx -t`, `apachectl configtest`, `visudo -c`, `nft -c -f <file>`).
4. **Reload** and **test** that the service still works.
5. **Record** the change and how to undo it (copy the backup back and reload).

Never lock the user out: before SSH or firewall changes, keep the current session open, add an allow rule for the user's own access first, and test a fresh login before closing anything. For remote-only machines, suggest a timed rollback (for example `at now + 5 minutes` restoring the old ruleset) that the user cancels after testing.

## 1. Patching First

- Debian/Ubuntu: `sudo apt update && sudo apt upgrade`; enable `unattended-upgrades` for security updates.
- RHEL family: `sudo dnf upgrade --security`; enable `dnf-automatic` with `upgrade_type = security`.
- Reboot when the kernel or libc changed (agree the time). End-of-life release: plan an upgrade; no config change fixes it.

## 2. Accounts and Privilege

- Lock unused accounts: `sudo usermod -L -s /usr/sbin/nologin <user>`.
- Remove extra UID 0 accounts (after checking what uses them).
- Narrow sudo: replace `ALL=(ALL) NOPASSWD: ALL` with the specific commands needed; edit only with `visudo -f /etc/sudoers.d/<file>`.
- Lockout and password quality: never hand-edit `/etc/pam.d` (a mistake can lock everyone out, and on RHEL authselect overwrites hand edits). RHEL family: `sudo authselect enable-feature with-faillock`, then set `deny = 5` and `unlock_time = 900` in `/etc/security/faillock.conf`. Debian and Ubuntu: set the same in `/etc/security/faillock.conf`; these systems ship no faillock profile for `pam-auth-update`, so faillock needs a local profile in `/usr/share/pam-configs/` (check that `pam-auth-update` then lists it) before it takes effect. If unsure, leave lockout to fail2ban and say so. Password quality: `minlen = 14` in `/etc/security/pwquality.conf`. Keep a root session open and test a fresh login before closing it.
- Remove users from the `docker` group unless they need root-equivalent access.

## 3. SSH

sshd uses the first value it reads, and drop-in files load in name order, so use `/etc/ssh/sshd_config.d/01-hardening.conf` (a cloud image's `50-cloud-init.conf` can otherwise re-enable passwords). Check that the main `/etc/ssh/sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf` near the top; if not (older releases such as RHEL 8), edit the main file instead. sshd_config does not allow comments at the end of a line, so comments go on their own line.

```
PermitRootLogin no
# Only after a working key login is confirmed:
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
# 4 leaves room for an SSH agent that offers several keys:
MaxAuthTries 4
X11Forwarding no
# Unless port forwarding is needed:
AllowTcpForwarding no
# Create the group and add the real users first:
AllowGroups ssh-users
LogLevel VERBOSE
```
`sudo sshd -t && sudo systemctl reload ssh` (the unit is `sshd` on the RHEL family). Confirm the effective values with `sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|allowgroups'`, then test a new login in a second terminal. On Ubuntu 24.04 and later sshd may be socket-activated (`ssh.socket`); a Port change there needs `sudo systemctl daemon-reload && sudo systemctl restart ssh.socket`. Optional: add multi-factor login (for example a FIDO2 `sk-` key or a TOTP PAM module) for internet-facing hosts.

## 4. Network Exposure and Firewall

- Bind internal services to loopback in their own config (Redis `bind 127.0.0.1 ::1` and `protected-mode yes`; MySQL/MariaDB `bind-address = 127.0.0.1`; PostgreSQL `listen_addresses = 'localhost'`; MongoDB `bindIp: 127.0.0.1`; Elasticsearch `network.host: 127.0.0.1`; Ollama `OLLAMA_HOST=127.0.0.1`), and turn authentication on.
- Default-deny inbound, allow only what is needed. With ufw: read the real SSH port first (`sudo sshd -T | grep ^port`), then `sudo ufw default deny incoming; sudo ufw allow <ssh-port>/tcp; sudo ufw allow 443/tcp; sudo ufw enable` (it asks for confirmation). Make sure `IPV6=yes` in `/etc/default/ufw` so IPv6 is filtered too.
- RHEL, Alma, Rocky and Fedora use firewalld; do not install ufw beside it. `sudo firewall-cmd --permanent --add-service=ssh` (or `--add-port=<ssh-port>/tcp`), `sudo firewall-cmd --permanent --add-service=https`, `sudo firewall-cmd --reload`, then check with `sudo firewall-cmd --list-all`. The default zone already rejects anything not listed.
- Docker publishes ports through its own iptables chains, which bypass ufw and firewalld INPUT rules. Publish such ports on `127.0.0.1:` or filter them in the `DOCKER-USER` chain. With nftables, keep the ruleset in `/etc/nftables.conf` and check it with `nft -c -f` first.
- Disable services nobody uses: `sudo systemctl disable --now <unit>` (confirm with the user what each one does first).

## 5. Kernel and Filesystem

Kernel settings go in `/etc/sysctl.d/60-hardening.conf`:

```
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.suid_dumpable = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
```
`rp_filter = 1` can break hosts with several network interfaces or asymmetric routing; use `2` (loose) there. On servers with static IPv6 addresses also consider `net.ipv6.conf.all.accept_ra = 0`.
`net.ipv4.ip_forward = 0` only if the host is not a router or container host (Docker and Kubernetes need forwarding). Apply with `sudo sysctl --system`.

- Permissions: restore the distribution default rather than guessing. `/etc/shadow` is `640 root:shadow` on Debian, Ubuntu and SUSE but `000 root:root` on the RHEL and Fedora family; compare with `rpm -V setup` (RHEL) or `dpkg-statoverride --list` first. GRUB config `chmod 600` (`/boot/grub/grub.cfg`, or `/boot/grub2/grub.cfg` on RHEL); remove world-write bits found in the assessment, remove SUID from binaries that do not need it (`chmod u-s`, after checking the package owner with `dpkg -S` or `rpm -qf`).
- Mount `/tmp` and `/dev/shm` with `nodev,nosuid,noexec` where the software allows (`noexec` on `/tmp` can break package maintainer scripts and some installers; test an update afterwards).
- Disable unused kernel modules in `/etc/modprobe.d/blacklist-vapt.conf` (`install cramfs /bin/false`, the same for `dccp`, `sctp`, `rds`, `tipc`, and `usb-storage` on servers without USB use); set `* hard core 0` in `/etc/security/limits.conf`; restrict cron and at with `/etc/cron.allow` and `/etc/at.allow` (an allow file blocks every user not listed, so first list who has a crontab with `sudo ls /var/spool/cron/crontabs /var/spool/cron 2>/dev/null` and add them); set a login banner in `/etc/issue.net` if the organisation requires one.

## 6. Web Servers and Applications

- nginx: `server_tokens off; autoindex off; ssl_protocols TLSv1.2 TLSv1.3;` and security headers (`Strict-Transport-Security "max-age=31536000"`, adding `includeSubDomains` only when every subdomain serves HTTPS; `X-Content-Type-Options nosniff`; `Referrer-Policy strict-origin-when-cross-origin`; a `Content-Security-Policy` built for the site that includes `frame-ancestors 'self'`, or `X-Frame-Options SAMEORIGIN`).
- Apache: `ServerTokens Prod`, `ServerSignature Off`, `TraceEnable Off`, `Options -Indexes`, `SSLProtocol -all +TLSv1.2 +TLSv1.3`, same headers via `mod_headers`.
- Deny dotfiles and backups: nginx `location ~ /\.(?!well-known) { deny all; }`; remove stray backups and `phpinfo.php` from the web root (move them to a backup folder outside the web root rather than deleting).
- PHP: `expose_php = Off`, `display_errors = Off`, `allow_url_include = Off`, session cookies `Secure`, `HttpOnly`, `SameSite=Lax`.
- Frameworks: production mode (`APP_DEBUG=false`, `DEBUG = False`, `NODE_ENV=production`); env files outside the web root, mode 600.
- CMS: update core, plugins and themes; remove unused ones; disable file editing from the admin panel.
- TLS certificates: automatic renewal (certbot timer), no expired or self-signed certificate on a public site.

## 7. Mandatory Access Control

Keep SELinux (RHEL family) or AppArmor (Debian, Ubuntu, SUSE) enforcing. SELinux: `getenforce`; if it is Permissive, review denials first with `sudo ausearch -m avc -ts recent` and fix labels (`restorecon`) or write a reviewed local policy (`audit2allow`), then `sudo setenforce 1` and `SELINUX=enforcing` in `/etc/selinux/config`. AppArmor: `sudo aa-status`; move profiles from complain to enforce with `aa-enforce` after checking the logs. Never disable either to make an application work.

## 8. Containers

Run containers as a non-root user, never `--privileged`, publish ports on `127.0.0.1:` when only a local proxy needs them, set `read_only: true` and `no-new-privileges:true` where possible, keep images updated and pinned by digest, and scan images for known vulnerabilities with a local scanner the user chooses (for example Trivy or Grype, run on this machine).

## 9. Detection and Monitoring

- auditd rules (`/etc/audit/rules.d/50-vapt.rules`):
  ```
  -w /etc/passwd -p wa -k identity
  -w /etc/shadow -p wa -k identity
  -w /etc/group -p wa -k identity
  -w /etc/sudoers -p wa -k privilege
  -w /etc/sudoers.d/ -p wa -k privilege
  -w /etc/ssh/sshd_config -p wa -k sshd
  -a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root-exec
  -a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root-exec
  ```
  Load with `sudo augenrules --load` (if the existing rules end with `-e 2`, the rule set is locked and the new rules apply only after a reboot); review with `ausearch -k identity -ts today`.
- Persistent journal with a size cap (`Storage=persistent`, `SystemMaxUse=1G`); time sync on.
- File integrity: `aide --init`, move the new database into place, schedule `aide --check`.
- Failed logins: review `journalctl -u ssh -u sshd --since today | grep -i failed`; fail2ban for SSH on internet-facing hosts.
- Scheduled re-assessment: a weekly systemd user timer that runs `openvapt scan --baseline <last report.json>` as the user who accepted the terms, writing to the default `~/openvapt-reports/` (mode 700) on the machine. A user timer stops when the user logs out unless `sudo loginctl enable-linger <user>` is set, and without root some checks report coverage gaps; say both.
- Central logging: sending logs to another machine helps detect tampering, but it sends data off this machine, so it is the user's decision; describe the trade-off and let them choose.
- Backups: confirm that backups of data and configuration exist, are kept off the machine by the user's own choice, and that a test restore works. Hardening does not help if a disk or ransomware event loses everything.

## Incident First Response

If the assessment finds signs of compromise (unknown UID 0 user, unknown SSH key, unexpected SUID binary, an unknown process listening, web shell names in the web root, cron entries nobody recognises):

1. **Stop changing things.** Do not "clean up"; that destroys evidence. Do not reboot: memory and live connections are lost.
2. **Tell the user plainly** what was seen and why it matters.
3. **Preserve**: first capture volatile state (`date -u`, `ss -tupan`, `ps auxww`, `who`, `last -w | head`) to a file; then copy (do not move) relevant logs and the suspicious files' metadata (`stat`, `sha256sum`) to a folder outside the web root. Keep a chain-of-custody note: who collected what, when (UTC), from where, and the hash of each copy.
4. **Contain with approval**: isolate the machine from the network at the provider or firewall level, rotate credentials from a clean machine.
5. **Escalate**: the user's incident response team, hosting provider or a qualified responder; national CERT/CSIRT if required by law. Follow NIST SP 800-61 Rev. 3 (incident response aligned with CSF 2.0).
6. Rebuild from known-good media is usually safer than repairing a compromised host.
