# Sources Cited by Checks and the Academy

Generated from the code by `internal/sources` (regenerate with `go test ./internal/sources -update`); do not edit by hand. Every reference that any check or Academy module cites is listed here, grouped by publisher, with the publisher's terms and any credit line those terms ask for. OpenVAPT cites sources by title, identifier and link; it does not copy their text. Use of a source does not imply that its publisher endorses OpenVAPT.

Totals: 170 distinct sources from 33 publishers, cited by 168 checks and 21 Academy modules.

## NIST (National Institute of Standards and Technology)

- Terms: Works of the U.S. Government, not subject to copyright in the United States. Cited by title, identifier and link.
- Credit: Includes references to NIST publications and the National Vulnerability Database (NVD). Use of NIST material does not imply endorsement by NIST.

| Source | Cited By |
|---|---|
| [NIST SP 800-115, Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final) | Academy A1, Academy A3, Academy F2, NET-FW-006, NET-LSN-001 |
| [NIST SP 800-119, Guidelines for the Secure Deployment of IPv6](https://csrc.nist.gov/pubs/sp/800/119/final) | NET-FW-002 |
| [NIST SP 800-12 Rev. 1, An Introduction to Information Security](https://csrc.nist.gov/pubs/sp/800/12/r1/final) | Academy F1 |
| [NIST SP 800-123, Guide to General Server Security](https://csrc.nist.gov/pubs/sp/800/123/final) | Academy P1, HOST-FS-001, HOST-FS-003, HOST-SSH-001, HOST-SVC-001, HOST-SYSD-001, NET-SVC-001 |
| [NIST SP 800-131A Rev. 2, Transitioning Cryptographic Algorithms](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) | HOST-SSH-004, NET-TLS-005 |
| [NIST SP 800-190, Application Container Security Guide](https://csrc.nist.gov/pubs/sp/800/190/final) | Academy P9, HOST-CTR-002, HOST-CTR-003, HOST-CTR-004 |
| [NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments](https://csrc.nist.gov/pubs/sp/800/30/r1/final) | Academy F1 |
| [NIST SP 800-40 Rev. 4, Guide to Enterprise Patch Management Planning](https://csrc.nist.gov/pubs/sp/800/40/r4/final) | Academy A2, Academy P1, HOST-PKG-001, HOST-UPD-001, HOST-UPD-002 |
| [NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/pubs/sp/800/41/r1/final) | Academy P12, Academy P3, NET-FW-001, NET-FW-003, NET-FW-004, NET-FW-005, NET-FW-006 |
| [NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations](https://csrc.nist.gov/pubs/sp/800/52/r2/final) | Academy P4, NET-TLS-001, NET-TLS-002, NET-TLS-003, NET-TLS-004 |
| [NIST SP 800-53 Rev. 5, Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | HOST-IDS-001, HOST-PWD-004, HOST-TIME-001, HOST-USR-001 |
| [NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html) | Academy P7, HOST-PWD-001, HOST-PWD-002, HOST-PWD-003, HOST-PWD-005, HOST-SSH-002 |
| [NIST SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) | HOST-LOG-001, HOST-LOG-003 |
| [NIST Transitioning Away from SHA-1](https://csrc.nist.gov/News/2022/nist-transitioning-away-from-sha-1-for-all-apps) | NET-TLS-006 |
| [NVD](https://nvd.nist.gov/) | HOST-CVE-001, HOST-CVE-002, HOST-CVE-003, WEB-CVE-001 |
| [NVD, CVE-2018-7600](https://nvd.nist.gov/vuln/detail/cve-2018-7600) | WEB-CMS-011 |
| [NVD, CVE-2020-1938](https://nvd.nist.gov/vuln/detail/cve-2020-1938) | WEB-TOM-004 |
| [NVD, CVE-2023-23752](https://nvd.nist.gov/vuln/detail/cve-2023-23752) | WEB-CMS-010 |

## The MITRE Corporation (ATT&CK, CWE, CVE)

- Terms: Identifiers, names and links only, under the published ATT&CK, CWE and CVE terms of use.
- Credit: © The MITRE Corporation. ATT&CK®, CVE® and CWE™ are trademarks of The MITRE Corporation; identifiers are cited under MITRE's published terms of use, and their use does not imply endorsement by MITRE.

| Source | Cited By |
|---|---|
| [CVE Program](https://www.cve.org/) | Academy F3 |
| [MITRE ATT&CK T1053.003, Cron](https://attack.mitre.org/techniques/T1053/003/) | HOST-FS-005 |
| [MITRE ATT&CK T1543.002, Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/) | Academy P11, HOST-SYSD-003 |
| [MITRE ATT&CK T1548, Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) | Academy P7 |
| [MITRE ATT&CK T1548.001, Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/) | HOST-FS-004 |
| [MITRE ATT&CK T1552.001, Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) | HOST-USR-007 |
| [MITRE ATT&CK T1574.010, Hijack Execution Flow: Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010/) | HOST-SYSD-004 |
| [MITRE CWE](https://cwe.mitre.org/) | Academy F3 |

## FIRST (Forum of Incident Response and Security Teams)

- Terms: The CVSS v3.1 scale and vector notation are applied; the specification text is not copied.
- Credit: CVSS is owned by FIRST.Org, Inc. and is used under the terms FIRST publishes for public use of CVSS, with attribution and a link to https://www.first.org/cvss/. FIRST does not endorse OpenVAPT.

| Source | Cited By |
|---|---|
| [FIRST, CVSS v3.1 Specification Document](https://www.first.org/cvss/v3.1/specification-document) | Academy F3 |

## OWASP Foundation

- Terms: The cited OWASP projects are published under CC BY-SA 4.0. Cited by title, identifier and link; no text is copied.
- Credit: References OWASP Top 10, ASVS, WSTG and Cheat Sheet Series, © OWASP Foundation, CC BY-SA 4.0.

| Source | Cited By |
|---|---|
| [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) | WEB-HDR-003 |
| [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | WEB-HDR-002 |
| [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html) | Academy P3, Academy P8, NET-DB-001 |
| [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | Academy P9, HOST-CTR-001, HOST-CTR-003 |
| [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | WEB-HDR-001, WEB-HDR-007 |
| [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) | HOST-FS-007 |
| [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | WEB-EXP-008 |
| [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html) | Academy P13, NET-APP-002, WEB-NODE-002, WEB-NODE-003 |
| [OWASP PHP Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html) | WEB-PHP-001, WEB-PHP-002, WEB-PHP-003 |
| [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | Academy P6, WEB-DOC-001, WEB-DOC-003, WEB-EXP-002 |
| [OWASP Secure Headers Project](https://owasp.org/projects/secure-headers-project) | Academy P5, WEB-HDR-004, WEB-HDR-005, WEB-HDR-006 |
| [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | Academy P5, WEB-CK-001 |
| [OWASP Top 10 2021, A05 Security Misconfiguration](https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/) | Academy P6 |
| [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | WEB-TLS-001 |
| [OWASP WSTG-CLNT-07, Testing Cross Origin Resource Sharing](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/) | WEB-COR-001 |
| [OWASP WSTG-CONF-02, Test Application Platform Configuration](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration/) | WEB-TOM-005 |
| [OWASP WSTG-CONF-04, Review Old Backup and Unreferenced Files for Sensitive Information](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/) | WEB-DOC-001, WEB-DOC-003, WEB-EXP-001, WEB-EXP-004, WEB-EXP-007, WEB-EXP-008, WEB-EXP-009 |
| [OWASP WSTG-CONF-05, Enumerate Infrastructure and Application Admin Interfaces](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces/) | WEB-EXP-011 |
| [OWASP WSTG-CONF-09, Test File Permission](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission/) | WEB-DOC-002 |
| [OWASP WSTG-ERRH-01, Testing for Improper Error Handling](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling/) | WEB-EXP-012 |
| [OWASP WSTG-INFO-02, Fingerprint Web Server](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server/) | WEB-EXP-010 |
| [OWASP Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide) | Academy F2 |

## Center for Internet Security (CIS)

- Terms: CIS Controls v8 is published by the Center for Internet Security, Inc. under CC BY-NC-ND 4.0. Referred to by Control number and link only; no CIS text is reproduced.
- Credit: CIS Controls® is a trademark of the Center for Internet Security, Inc. Use does not imply endorsement by CIS.

| Source | Cited By |
|---|---|
| [CIS Critical Security Controls v8, Control 5 (Account Management)](https://www.cisecurity.org/controls/account-management) | HOST-PWD-005 |

## IETF / RFC Editor

- Terms: RFCs are © IETF Trust and the persons identified as authors (BCP 78). Cited by number, title and link.

| Source | Cited By |
|---|---|
| [RFC 6125, Representation and Verification of Domain-Based Application Service Identity](https://www.rfc-editor.org/rfc/rfc6125.html) | NET-TLS-003 |
| [RFC 6265, HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265.html) | WEB-CK-001 |
| [RFC 6797, HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797.html) | Academy P4, WEB-HDR-001 |
| [RFC 8996, Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html) | Academy P4, NET-TLS-001, NET-TLS-004 |
| [RFC 9116, A File Format to Aid in Security Vulnerability Disclosure](https://www.rfc-editor.org/rfc/rfc9116.html) | WEB-SEC-001 |
| [RFC 9142, Key Exchange Method Updates for SSH](https://www.rfc-editor.org/rfc/rfc9142.html) | Academy P2, HOST-SSH-004 |

## CISA (U.S. Cybersecurity and Infrastructure Security Agency)

- Terms: U.S. Government work. Cited by title and link; the KEV catalogue is used only by the release pipeline.

| Source | Cited By |
|---|---|
| [CISA Alert TA14-013A, NTP Amplification Attacks Using CVE-2013-5211](https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211) | NET-SVC-003 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Academy P10, HOST-CVE-001, HOST-CVE-002, HOST-CVE-003 |
| [CISA, DNS Amplification Attacks (Alert TA13-088A)](https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks) | Academy P8 |

## OSV (Open Source Vulnerabilities, osv.dev) and the OSV Schema (OpenSSF)

- Terms: Cited by link. Advisory data is downloaded only by the release pipeline; licences vary by originating database and are recorded per release (docs/VULNDB.md).

| Source | Cited By |
|---|---|
| [OSV schema, defined ecosystems (WordPress)](https://ossf.github.io/osv-schema/) | WEB-CVE-001 |
| [OSV vulnerability database](https://osv.dev/) | Academy P10, HOST-CVE-001, HOST-CVE-002, HOST-CVE-003, WEB-CVE-001 |

## OASIS Open

- Terms: The SARIF 2.1.0 format is implemented; the specification text is not copied.

| Source | Cited By |
|---|---|
| [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) | Academy A3 |

## W3C

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [W3C Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) | WEB-HDR-002 |

## IANA

- Terms: Public registry data (port numbers) consulted; cited by link.

| Source | Cited By |
|---|---|
| [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers) | NET-SVC-002, NET-SVC-004 |

## PTES (Penetration Testing Execution Standard)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Main_Page) | Academy F2 |

## Linux Kernel Documentation

- Terms: Kernel documentation is generally distributed under GPL-2.0; individual files may carry other licences. Cited by title and link only.

| Source | Cited By |
|---|---|
| [Linux kernel documentation, /proc/sys/fs](https://docs.kernel.org/admin-guide/sysctl/fs.html) | HOST-KRN-004, HOST-KRN-011, HOST-KRN-012 |
| [Linux kernel documentation, /proc/sys/kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html) | HOST-KRN-001, HOST-KRN-002, HOST-KRN-003, HOST-KRN-009, HOST-KRN-018 |
| [Linux kernel documentation, IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html) | HOST-KRN-005, HOST-KRN-006, HOST-KRN-007, HOST-KRN-008, HOST-KRN-013, HOST-KRN-014, HOST-KRN-015, HOST-KRN-016, HOST-KRN-017 |
| [Linux kernel documentation, Linux Security Module development and LSMs](https://docs.kernel.org/admin-guide/LSM/index.html) | HOST-MAC-001 |
| [Linux kernel documentation, Yama LSM](https://docs.kernel.org/admin-guide/LSM/Yama.html) | HOST-KRN-010 |

## Linux Manual Pages (man7.org, Ubuntu and Debian Manpages)

- Terms: Man pages carry per-page licences. Cited by page name and link only.

| Source | Cited By |
|---|---|
| [Linux exports(5)](https://man7.org/linux/man-pages/man5/exports.5.html) | NET-DB-008 |
| [auditd(8), Linux man-pages](https://man7.org/linux/man-pages/man8/auditd.8.html) | HOST-LOG-002 |
| [chmod(1), Linux man-pages (restricted deletion flag)](https://man7.org/linux/man-pages/man1/chmod.1.html) | HOST-FS-002 |
| [crontab(5), Linux man-pages](https://man7.org/linux/man-pages/man5/crontab.5.html) | HOST-FS-005 |
| [crypt(5), libxcrypt, Debian trixie manual pages (hashing methods)](https://manpages.debian.org/trixie/libcrypt-dev/crypt.5.en.html) | HOST-PWD-002 |
| [login.defs(5), Linux man-pages](https://man7.org/linux/man-pages/man5/login.defs.5.html) | HOST-FS-009, HOST-PWD-001, HOST-PWD-005 |
| [logrotate(8), Linux man-pages](https://man7.org/linux/man-pages/man8/logrotate.8.html) | HOST-LOG-004 |
| [mount(8), Linux man-pages (nodev, nosuid, noexec)](https://man7.org/linux/man-pages/man8/mount.8.html) | HOST-FS-008 |
| [nologin(8), Linux man-pages](https://man7.org/linux/man-pages/man8/nologin.8.html) | HOST-USR-005 |
| [nsswitch.conf(5), Linux man-pages (compat mode)](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) | HOST-USR-006 |
| [pam_faillock(8), Linux-PAM](https://man7.org/linux/man-pages/man8/pam_faillock.8.html) | HOST-PWD-004 |
| [passwd(5), Linux man-pages](https://man7.org/linux/man-pages/man5/passwd.5.html) | HOST-USR-001, HOST-USR-004 |
| [proc_net(5), Linux man-pages](https://man7.org/linux/man-pages/man5/proc_net.5.html) | NET-LSN-001 |
| [pwquality.conf(5), libpwquality, Debian trixie manual pages](https://manpages.debian.org/trixie/libpwquality-common/pwquality.conf.5.en.html) | HOST-PWD-003 |
| [shadow(5), Linux man-pages](https://man7.org/linux/man-pages/man5/shadow.5.html) | HOST-FS-001, HOST-USR-002 |
| [ufw(8) manual (Ubuntu)](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html) | NET-FW-003 |
| [umask(2), Linux man-pages](https://man7.org/linux/man-pages/man2/umask.2.html) | HOST-FS-009 |

## OpenBSD (OpenSSH Manual Pages)

- Terms: Manual pages generally under BSD or ISC style licences. Cited by page name and link only.

| Source | Cited By |
|---|---|
| [OpenBSD, sshd_config(5) manual page](https://man.openbsd.org/sshd_config) | Academy P2, HOST-SSH-001, HOST-SSH-002, HOST-SSH-003, HOST-SSH-004, HOST-SSH-005, HOST-SSH-006, HOST-SSH-007, HOST-SSH-008, HOST-SSH-009, HOST-SSH-010, HOST-SSH-011, HOST-SSH-012 |

## freedesktop.org and systemd

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [journald.conf(5)](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html) | HOST-LOG-001 |
| [systemd, System and Service Credentials](https://systemd.io/CREDENTIALS/) | Academy P11, HOST-SYSD-005 |
| [systemd-analyze(1), security verb](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html) | HOST-SYSD-002 |
| [systemd.exec(5), execution environment configuration](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) | Academy P11, HOST-SYSD-001, HOST-SYSD-002, HOST-SYSD-004, HOST-SYSD-005 |
| [systemd.unit(5), unit configuration](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) | HOST-SYSD-003 |

## GNU Project

- Terms: Most GNU manuals are published under the GNU FDL. Cited by title and link only.

| Source | Cited By |
|---|---|
| [GNU GRUB Manual, Security](https://www.gnu.org/software/grub/manual/grub/html_node/Security.html) | HOST-FS-006 |

## sudo Project

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [sudoers(5) manual](https://www.sudo.ws/docs/man/sudoers.man/) | HOST-SUDO-001, HOST-USR-003 |

## nftables Project

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page) | NET-FW-001 |

## chrony Project

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [chrony Documentation - Access Control](https://chrony-project.org/doc/4.6/chrony.conf.html) | NET-SVC-003 |

## Linux Distributions (Debian, Ubuntu, Red Hat)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Debian Policy Manual, Version numbering](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version) | Academy P10 |
| [Debian releases and LTS](https://wiki.debian.org/LTS) | HOST-OS-001 |
| [Debian, UnattendedUpgrades](https://wiki.debian.org/UnattendedUpgrades) | HOST-PKG-001, HOST-UPD-001 |
| [Red Hat Enterprise Linux life cycle](https://access.redhat.com/support/policy/updates/errata) | HOST-OS-001 |
| [Ubuntu release cycle](https://ubuntu.com/about/release-cycle) | HOST-OS-001 |

## endoflife.date (Community-Maintained)

- Terms: Community-maintained data, published by the project under its stated open licence, consulted for release dates, cross-checked with vendor pages.

| Source | Cited By |
|---|---|
| [endoflife.date (community-maintained lifecycle data)](https://endoflife.date/) | HOST-OS-001 |
| [endoflife.date, Node.js (community-maintained lifecycle data)](https://endoflife.date/nodejs) | WEB-NODE-001 |

## Mozilla (MDN Web Docs and Mozilla Wiki)

- Terms: MDN prose is published by Mozilla Contributors under CC BY-SA 2.5; Mozilla wiki pages carry the licence stated on the wiki. Cited by title and link only.

| Source | Cited By |
|---|---|
| [MDN Web Docs, Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin) | WEB-COR-001 |
| [MDN Web Docs, Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy) | WEB-HDR-006 |
| [MDN Web Docs, Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy) | WEB-HDR-005 |
| [MDN Web Docs, Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security) | WEB-HDR-001 |
| [MDN Web Docs, X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options) | WEB-HDR-004 |
| [MDN Web Docs, X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options) | WEB-HDR-003 |
| [Mozilla Server Side TLS guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS) | NET-TLS-001, NET-TLS-004 |

## Let's Encrypt (ISRG)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Let's Encrypt, certificate lifetimes and renewal](https://letsencrypt.org/docs/faq/) | NET-TLS-002 |

## Apache Software Foundation (HTTP Server, Tomcat)

- Terms: Apache documentation is published under the Apache License 2.0. Cited by title and link only.

| Source | Cited By |
|---|---|
| [Apache HTTP Server, Options directive](https://httpd.apache.org/docs/2.4/mod/core.html#options) | WEB-EXP-005 |
| [Apache HTTP Server, ServerTokens directive](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens) | WEB-HDR-007 |
| [Apache HTTP Server, mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html) | WEB-EXP-006 |
| [Apache Tomcat 10.1 Configuration Reference, The AJP Connector](https://tomcat.apache.org/tomcat-10.1-doc/config/ajp.html) | WEB-TOM-004 |
| [Apache Tomcat 10.1 Configuration Reference, The Server Component](https://tomcat.apache.org/tomcat-10.1-doc/config/server.html) | WEB-TOM-003 |
| [Apache Tomcat 10.1, Manager App How-To](https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html) | WEB-TOM-001 |
| [Apache Tomcat 10.1, Realm Configuration How-To (digested passwords)](https://tomcat.apache.org/tomcat-10.1-doc/realm-howto.html) | WEB-TOM-002 |
| [Apache Tomcat 10.1, Security Considerations](https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html) | Academy P13, WEB-TOM-001, WEB-TOM-002, WEB-TOM-003, WEB-TOM-004, WEB-TOM-005 |
| [Apache Tomcat 9, AJP Connector](https://tomcat.apache.org/tomcat-9.0-doc/config/ajp.html) | NET-APP-001 |

## PHP Documentation

- Terms: The PHP manual is published under CC BY 3.0. Cited by title and link only.

| Source | Cited By |
|---|---|
| [PHP manual, Session security](https://www.php.net/manual/en/session.security.php) | WEB-PHP-005 |
| [PHP manual, php.ini directives](https://www.php.net/manual/en/ini.list.php) | WEB-PHP-001, WEB-PHP-002, WEB-PHP-003, WEB-PHP-005 |
| [PHP manual, phpinfo()](https://www.php.net/manual/en/function.phpinfo.php) | WEB-EXP-003 |
| [PHP, Supported Versions](https://www.php.net/supported-versions.php) | WEB-PHP-004 |

## Web Frameworks and Runtimes (Django, Flask, Werkzeug, Node.js, Express, Gunicorn)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Django documentation, Deployment checklist](https://docs.djangoproject.com/en/6.1/howto/deployment/checklist/) | Academy P13, WEB-PY-001, WEB-PY-002, WEB-PY-003 |
| [Django documentation, django-admin runserver (not for production)](https://docs.djangoproject.com/en/6.1/ref/django-admin/#runserver) | WEB-PY-005 |
| [Django settings reference, ALLOWED_HOSTS](https://docs.djangoproject.com/en/6.1/ref/settings/#allowed-hosts) | WEB-PY-002 |
| [Django settings reference, DEBUG](https://docs.djangoproject.com/en/6.1/ref/settings/#debug) | WEB-PY-001 |
| [Django settings reference, SECRET_KEY](https://docs.djangoproject.com/en/6.1/ref/settings/#secret-key) | WEB-PY-003 |
| [Express documentation, Production best practices: performance and reliability](https://expressjs.com/en/advanced/best-practice-performance/) | WEB-NODE-003 |
| [Flask documentation, Debug mode](https://flask.palletsprojects.com/en/stable/quickstart/#debug-mode) | WEB-PY-004 |
| [Flask documentation, Deploying to Production](https://flask.palletsprojects.com/en/stable/deploying/) | WEB-PY-005 |
| [Gunicorn documentation, Deploying Gunicorn (behind a proxy)](https://gunicorn.org/deploy/) | NET-APP-002 |
| [Node.js documentation, Debugging guide (security implications)](https://nodejs.org/learn/getting-started/debugging) | WEB-NODE-002 |
| [Node.js, Inspector security implications](https://nodejs.org/en/learn/getting-started/debugging#security-implications) | NET-APP-001 |
| [Werkzeug documentation, Debugging Applications](https://werkzeug.palletsprojects.com/en/stable/debug/) | WEB-PY-004 |

## Content Management Systems (WordPress, Drupal, Joomla)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Drupal.org, Securing file permissions and ownership](https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-file-permissions-and-ownership) | Academy P14, WEB-CMS-004, WEB-CMS-005 |
| [Drupal.org, Security advisories](https://www.drupal.org/security) | WEB-CMS-011 |
| [Joomla Documentation, Security Checklist](https://docs.joomla.org/Security_Checklist) | Academy P14, WEB-CMS-010 |
| [Joomla Documentation, Security Checklist: Site Administration](https://docs.joomla.org/Security_Checklist/Site_Administration) | WEB-CMS-009 |
| [WordPress Developer Resources, Brute Force Attacks (XML-RPC)](https://developer.wordpress.org/advanced-administration/security/brute-force/) | WEB-CMS-002 |
| [WordPress Developer Resources, Configuring Automatic Background Updates](https://developer.wordpress.org/advanced-administration/upgrade/upgrading/#configuring-automatic-background-updates) | WEB-CMS-008 |
| [WordPress Developer Resources, Debugging in WordPress](https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/) | WEB-CMS-006 |
| [WordPress Developer Resources, Editing wp-config.php](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/) | WEB-CMS-007 |
| [WordPress Developer Resources, Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/) | Academy P14, WEB-CMS-001, WEB-CMS-004, WEB-CMS-005, WEB-CMS-007 |
| [WordPress Developer Resources, REST API Users endpoint](https://developer.wordpress.org/rest-api/reference/users/) | WEB-CMS-003 |

## Containers and Orchestration (Docker, Kubernetes)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Docker documentation, Docker Engine security](https://docs.docker.com/engine/security/) | HOST-CTR-002 |
| [Docker documentation, Docker daemon attack surface](https://docs.docker.com/engine/security/#docker-daemon-attack-surface) | HOST-DKR-001 |
| [Docker documentation, Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/) | Academy P12, NET-FW-005 |
| [Docker documentation, Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/) | HOST-CTR-001, HOST-CTR-004, NET-SVC-002 |
| [Kubernetes Ports and Protocols](https://kubernetes.io/docs/reference/networking/ports-and-protocols/) | NET-SVC-002 |
| [Kubernetes documentation, Kubelet authentication and authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/) | Academy P9, HOST-K8S-001 |
| [Kubernetes documentation, Operating etcd clusters for Kubernetes](https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/) | HOST-K8S-002 |
| [Kubernetes documentation, Securing a cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) | HOST-K8S-001, HOST-K8S-002, HOST-K8S-003 |

## Prometheus (The Linux Foundation)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Prometheus, Security model](https://prometheus.io/docs/operating/security/) | NET-SVC-004 |

## Databases and Data Services (MySQL, PostgreSQL, MongoDB, Redis, Memcached, Elastic)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Elastic Security Minimal Setup](https://www.elastic.co/docs/deploy-manage/security/set-up-minimal-security) | NET-DB-007 |
| [MongoDB Security Checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/) | NET-DB-003 |
| [MySQL Server Security Guidelines](https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html) | NET-DB-005 |
| [PostgreSQL Client Authentication](https://www.postgresql.org/docs/current/client-authentication.html) | NET-DB-004 |
| [Redis security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/) | Academy P8, NET-DB-001, NET-DB-002 |
| [memcached Configuration](https://docs.memcached.org/serverguide/configuring/) | NET-DB-006 |

## Network Services (BIND 9, Samba, Postfix, Dovecot)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [BIND 9 Administrator Reference Manual - Access Control](https://bind9.readthedocs.io/en/latest/reference.html#access-control) | NET-DB-010 |
| [BIND 9 Administrator Reference Manual - allow-transfer](https://bind9.readthedocs.io/en/latest/reference.html#namedconf-statement-allow-transfer) | NET-DB-011 |
| [Dovecot Authentication Settings](https://doc.dovecot.org/main/core/config/auth/settings.html) | NET-DB-013 |
| [Postfix SMTP Relay and Access Control](https://www.postfix.org/SMTPD_ACCESS_README.html) | NET-DB-012 |
| [Samba smb.conf Manual](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) | NET-DB-009 |

## Projects Hosted on GitHub (Publisher Named in Each Title)

- Terms: Copyright of the publisher. Cited by title and link only; no text is copied.

| Source | Cited By |
|---|---|
| [Node.js Release Working Group, release schedule](https://github.com/nodejs/Release) | WEB-NODE-001 |
| [OpenVAPT source code](https://github.com/OpenVAPT/openvapt) | Academy A4 |
| [fail2ban project](https://github.com/fail2ban/fail2ban) | HOST-IDS-001 |

