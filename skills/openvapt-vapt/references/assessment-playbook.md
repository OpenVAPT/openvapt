# Assessment Playbook: Read-Only Manual Checks

These commands are for Linux (Debian, Ubuntu, RHEL, Alma, Rocky, Fedora, SUSE families); paths differ slightly between them and are noted where they matter.

Every command here only reads. Run them on the machine being assessed. Some need root to see everything; if the user runs without root, note the gaps. Never paste secrets, hashes or keys into notes: record the file and line number and write `REDACTED`.

The matching OpenVAPT check prefix is shown in brackets so you can cross-check with `openvapt explain <ID>`.

## 1. System, Inventory and Patches [HOST-OS, HOST-PKG, HOST-UPD, HOST-CVE]

```
cat /etc/os-release; uname -r
# Debian/Ubuntu
# Uses the local package lists only; they may be stale until the user runs apt update.
apt list --upgradable 2>/dev/null | head -50
# RHEL/Fedora/Alma/Rocky: -C reads the local cache only (no download), which may also be stale
dnf -C check-update --security 2>/dev/null | head -50
# Software inventory (CIS Controls 1 and 2): keep a copy with the report
dpkg -l 2>/dev/null | wc -l; rpm -qa 2>/dev/null | wc -l
# Is the release still supported? Compare with the vendor's end-of-life page.
```
Look for: end-of-life releases, pending security updates, kernel older than the installed package (reboot pending: `needrestart -r l` or compare `uname -r` with the newest installed kernel), automatic updates off.

## 2. Users, Groups and Privilege [HOST-USR, HOST-SUDO, HOST-PWD, HOST-PAM]

```
awk -F: '$3==0{print $1}' /etc/passwd                 # only root should have UID 0
awk -F: '($2==""){print $1}' /etc/shadow               # empty passwords (root needed)
getent group sudo wheel admin
sudo -l -U <user>                                      # per user, as root
grep -rhv '^#' /etc/sudoers /etc/sudoers.d/ | grep -E 'NOPASSWD|ALL[[:space:]]*$'
lastlog 2>/dev/null | grep -v 'Never' || lastlog2 2>/dev/null || last -w | head -30
grep -E '^(PASS_MAX_DAYS|PASS_MIN_LEN|UMASK)' /etc/login.defs
grep -rE 'pam_(pwquality|faillock|tally2)' /etc/pam.d/
```
Look for: extra UID 0 accounts, unused accounts with shells, broad NOPASSWD rules, no lockout after failed logins, weak password policy.

## 3. SSH [HOST-SSH]

```
sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|x11forwarding|allowtcpforwarding|ciphers|macs|kexalgorithms|allowusers|allowgroups|loglevel)'
ls -l /etc/ssh/ssh_host_*_key
find /home /root -name authorized_keys -exec ls -l {} \; 2>/dev/null
```
Look for: root login allowed, password login on an internet-facing host, weak ciphers or MACs, world-readable host keys or authorized_keys, no AllowUsers or AllowGroups.

## 4. Files and Permissions [HOST-FS]

```
stat -c '%a %U %n' /etc/passwd /etc/shadow /etc/gshadow /etc/group /etc/crontab
find / -xdev -perm -4000 -type f 2>/dev/null           # SUID
find / -xdev -perm -2000 -type f 2>/dev/null           # SGID
find / -xdev -type f -perm -0002 2>/dev/null | head    # world-writable files
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head   # world-writable dirs without sticky bit
findmnt -no TARGET,OPTIONS /tmp /var/tmp /dev/shm
```
Look for: shadow readable by others, unexpected SUID binaries (check which package owns each one with `dpkg -S <file>` or `rpm -qf <file>`; a file no package owns needs a closer look), world-writable paths, /tmp without nodev,nosuid,noexec.

## 5. Kernel and Boot [HOST-KRN, HOST-BOOT, HOST-MAC]

```
sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict \
  kernel.yama.ptrace_scope fs.protected_symlinks fs.protected_hardlinks fs.suid_dumpable \
  net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
  net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter
stat -c '%a %n' /boot/grub*/grub.cfg 2>/dev/null     # /boot/grub2 on RHEL
getenforce 2>/dev/null; aa-status --enabled 2>/dev/null && echo apparmor-on
```

## 6. Services, Timers and Cron [HOST-SVC, HOST-SYSD, HOST-CRON]

```
systemctl list-units --type=service --state=running --no-pager
systemctl list-timers --all --no-pager
ls -la /etc/cron.* /var/spool/cron* 2>/dev/null
systemd-analyze security --no-pager 2>/dev/null | head -30
```
Look for: services nobody needs (telnet, rsh, ftp, avahi, cups on servers), cron scripts writable by non-root users, units running as root with no sandboxing.

## 7. Logging and Audit [HOST-LOG, HOST-AUD, HOST-IDS, HOST-TIME]

```
systemctl is-active rsyslog systemd-journald auditd chronyd systemd-timesyncd 2>/dev/null
auditctl -l 2>/dev/null | head -40
grep -E 'Storage|SystemMaxUse' /etc/systemd/journald.conf
timedatectl | grep -i synchronized
```

## 8. Containers and Orchestration [HOST-CTR, HOST-DKR, HOST-K8S]

```
ls -l /var/run/docker.sock 2>/dev/null; getent group docker
docker ps --format '{{.Names}} {{.Image}} {{.Ports}}' 2>/dev/null
docker inspect --format '{{.Name}} priv={{.HostConfig.Privileged}} user={{.Config.User}}' $(docker ps -q) 2>/dev/null
```
Look for: users in the docker group (equal to root), privileged containers, containers running as root, ports published on 0.0.0.0.

## 9. Network as Seen From Loopback [NET-LSN, NET-FW, NET-DB, NET-SVC, NET-MAIL, NET-DNS, NET-AI]

```
ss -tulpn                                   # what listens, on which address (IPv4 and IPv6)
nft list ruleset 2>/dev/null || { iptables -S; ip6tables -S; } 2>/dev/null; ufw status verbose 2>/dev/null
```
Check IPv6 separately: a service on `[::]` is reachable over IPv6 even when the IPv4 firewall blocks it, and ufw filters IPv6 only with `IPV6=yes`.
Look for: databases, caches, admin panels or AI model servers (Redis, MongoDB, Elasticsearch, Memcached, MySQL, PostgreSQL, Ollama, Jupyter) bound to 0.0.0.0 or `::` without a firewall rule; default-accept firewall policy; an open mail relay configuration. Read the service's config file to confirm authentication is on. Do not connect from another machine and do not try passwords.

TLS on local services (reads the certificate and the offered protocols only):
```
openssl s_client -connect 127.0.0.1:443 -servername <site-hostname> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
for p in tls1 tls1_1 tls1_2 tls1_3; do echo -n "$p: "; openssl s_client -connect 127.0.0.1:443 -servername <site-hostname> -$p -cipher 'DEFAULT:@SECLEVEL=0' </dev/null >/dev/null 2>&1 && echo offered || echo no; done
```
A "no" for TLS 1.0 or 1.1 can also mean the local OpenSSL refuses them; treat it as inconclusive and read the server's `ssl_protocols` or `SSLProtocol` setting. Note the certificate's `notAfter` date: an expiry within 30 days is a finding.
[NET-TLS, WEB-TLS]

## 10. Web, Through Loopback Only [WEB-*]

Always pin the site's name to `127.0.0.1` with `--resolve`, never let the public name resolve (it may point to another machine or a CDN). `--resolve` connects only to loopback while sending the right SNI and Host, so name-based sites answer correctly. One GET per path, no parameters, no payloads.

```
H=<site-hostname>
R="--resolve $H:443:127.0.0.1"
curl -skI $R "https://$H/" | grep -Ei 'server|x-powered-by|strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|set-cookie'
for p in .git/HEAD .env .env.bak wp-config.php.bak backup.zip phpinfo.php server-status .DS_Store composer.json; do
  printf '%s %s\n' "$(curl -sk $R -o /dev/null -w '%{http_code}' "https://$H/$p")" "$p"
done
```
Then read the server and app config files rather than probing:
- nginx: `nginx -T 2>/dev/null | grep -E 'server_tokens|autoindex|ssl_protocols|add_header'` [WEB-NGX]
- Apache: `apachectl -S; grep -rE 'ServerTokens|ServerSignature|Options .*Indexes|TraceEnable' /etc/apache2 /etc/httpd 2>/dev/null` [WEB-APA]
- PHP: the web server's PHP settings, not the CLI's: `grep -Ei '^(display_errors|expose_php|allow_url_include|session.cookie_(secure|httponly|samesite))' /etc/php/*/fpm/php.ini /etc/php.ini 2>/dev/null` (`php -i` shows only the command-line configuration) [WEB-PHP]
- Framework debug: read only the named keys, never the whole file, for example `grep -E '^(APP_DEBUG|APP_ENV|DEBUG|NODE_ENV)=' <app>/.env` [WEB-APP, WEB-PY, WEB-NODE]
- CMS: core and plugin versions from files on disk, compared with vendor advisories [WEB-CMS, WEB-CVE]

## 11. Integrity and Stray Secrets [HOST-PKG, HOST-SEC]

```
debsums -s 2>/dev/null || rpm -Va 2>/dev/null | grep -v '^\.\.\.\.\.\.\.T' | head -40   # changed package files
find / -xdev \( -name '.env' -o -name '*.sql' -o -name '*.bak' -o -name '*.key' -o -name 'id_rsa' \) -perm -o=r -type f 2>/dev/null | head
ls -l /root/.bash_history /home/*/.bash_history 2>/dev/null
```
Report only the path and the permission problem. Never open, print or copy the contents.

## What This Playbook Does Not Do

No SQL injection, XSS, authentication bypass, IDOR or business logic testing; no port scanning of other hosts; no password checks against live services. List these as gaps that need an authorised human tester or a code review.
