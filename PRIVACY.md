# Privacy Policy

Version 1.7, effective 2026-10-14. This policy was drafted by an AI Cybersecurity Engineer and reviewed by a separate AI system acting as the project's legal reviewer; no human lawyer drafted or reviewed it. It is an information notice, not a contract.

## Summary

**We collect no data.** OpenVAPT does not collect, use, analyse, sell, rent, share or transfer any personal data or any other data about visitors of openvapt.com or users of the OpenVAPT software. The only exception is the web server log files created before logging was turned off on 2026-10-13. These are held, unused, in an access-restricted area until they are permanently deleted after 2026-11-12, as explained in section 2. Below we explain, honestly and completely, every place where data could flow, and what happens there.

## 1. Who "We" Are

"We" means OpenVAPT, an academic, non-commercial project run by its project owner. "OpenVAPT" is a project name, not a registered legal entity; the human owner who runs it is the person responsible in law. Because we collect no personal data, there is no data controller holding any of your data. Questions can be raised publicly on GitHub (see section 9).

## 2. This Website (openvapt.com)

| Possible Data Flow | What Actually Happens |
|---|---|
| Cookies | None. The website sets no cookies of any kind, so there is no cookie banner. |
| Browser storage | None. No localStorage, sessionStorage or IndexedDB is used. |
| Analytics, advertising, tracking pixels | None. |
| Third-party scripts, fonts, embeds, CDNs | None. Every file (pages, styles, fonts, icons, charts and the data grid) is served from openvapt.com itself. Your browser makes no requests to any other website while you read this site. |
| Forms, accounts, logins, newsletters, comments | None exist. |
| The download acknowledgement checklist | Runs only inside your browser. Your ticks are not stored, sent or remembered; the page asks again every time. |
| Web server access logs and error logs | Turned off for openvapt.com on 2026-10-13. Older log files that existed before then (which contained IP addresses) were moved out of the logging folder to an access-restricted area on the server and will be permanently deleted after 2026-11-12. |
| Email | We publish no email address and accept no contact by email. |

### Hosting, Network and Certificates

To be fully transparent about the infrastructure that delivers the website:

- The website runs on a virtual private server rented from **The Constant Company, LLC (Vultr)**, administered by the project owner. The same server also hosts other, unrelated websites. None of them receive any data from openvapt.com.
- The domain's DNS is answered by that same server, which is configured not to log DNS queries (query logging is off).
- The HTTPS certificate is issued by **Let's Encrypt**. Your browser may contact Let's Encrypt's certificate status services as part of normal HTTPS checks; that is between your browser and Let's Encrypt.
- Like any internet service, the hosting provider's network equipment necessarily handles your IP address while delivering the pages. We have configured our server to keep no record of your visit. We do not control, and cannot see, any network-level records the hosting provider may keep for its own security or legal purposes; those are governed by the provider's own privacy policy.

### One Site for Every Channel

There is no separate preview site. Every release channel (alpha, beta, release candidate and stable) is shown publicly on openvapt.com. The old openvapt.com/beta/ preview no longer exists, and the same no-data rules apply everywhere.

## 3. The OpenVAPT Software

- The software runs entirely on your own machine and is designed to make **no network connection to any other machine at all**. Every connection is restricted in code to loopback addresses (127.0.0.0/8 and ::1). There is no telemetry, crash reporting, licence check, update check or usage statistics.
- When you run a scan, the software **reads** information on your machine to assess it, which may include sensitive information: system configuration files, the list of user accounts, `/etc/shadow` (when run as root, to find accounts without passwords), sudo rules, listening network services, installed packages, web server configuration, systemd service unit files, application configuration files (for example for Apache Tomcat, Django, Flask, WordPress, Joomla and Drupal), the output of an allow-list of read-only commands (for example `node --version`), and the home pages and selected paths of the websites your machine serves (requested through 127.0.0.1). In full, the files and folders read also include: the boot loader configuration (GRUB files including user.cfg) and the firmware Secure Boot variables under `/sys/firmware/efi/efivars`; the audit daemon configuration and rules and the journald configuration; the PAM stacks, `/etc/login.defs` and root's shell start-up files; container runtime configuration for Docker, containerd and Podman, the Docker socket's ownership and permissions, and each container's `hostconfig.json` and `config.v2.json`; nginx and Apache configuration trees; MySQL or MariaDB, PostgreSQL (including `pg_hba.conf`), Redis and MongoDB configuration; Postfix, Dovecot and BIND configuration; application framework files such as `.env`, Django and Rails settings and key paths; cron tables and cron folders; `authorized_keys` files of root and of user accounts; and a bounded walk of `/etc` and of each web document root (file names and permissions, then the contents of at most 300 world-readable configuration-like files) matched against credential patterns, where only the file name and the kind of pattern are recorded and no matched value is ever copied.
- Configuration files that can contain secrets are read for pattern matching only, and the checks are designed never to copy secret values into a report. As a second safeguard, before anything is written into a report, the software **redacts** recognised secrets such as passwords, keys, tokens and password hashes. Redaction is pattern-based and may not catch every secret; please review a report before sharing it.
- Reports are written **only to your own disk**, in a folder you choose, readable only by your user account (permissions 0700 for the folder and 0600 for the files). We never receive them.
- If you choose to sign reports, a signing key is created on your machine (`~/.config/openvapt/report-key`, permission 0600) and never leaves it.
- What happens to your reports afterwards (who you share them with, where you store them) is entirely your responsibility.

## 4. GitHub

The source code, bug reports, discussions, security reports and the automated build pipeline are hosted on **GitHub, Inc.** (a subsidiary of Microsoft), at github.com/OpenVAPT/openvapt.

- If you visit the repository, download from it, open an issue, start a discussion, submit a pull request or send a private vulnerability report, **GitHub** processes your data under the GitHub Privacy Statement. GitHub may store data on servers in other countries, including the United States.
- Anything you post publicly on GitHub (issues, discussions, pull requests, comments) is public to everyone and may be copied or archived by others. **Never post secrets, full reports, hostnames, IP addresses or personal data.**
- Private vulnerability reports are visible only to the project maintainers and GitHub until a fix is published, after which a public security advisory describes the issue.
- The maintainers can see what GitHub shows any repository maintainer (for example your GitHub username on issues you open). We do not copy, export or keep that information anywhere else.

## 5. Software Packages and Fonts

The website uses self-hosted copies of AG Grid Community, Apache ECharts, Lucide icons and the IBM Plex fonts. They run inside your browser and make no network requests. The IBM Plex font packages include an install-time telemetry configuration intended for IBM; our build installs packages with scripts disabled, so it never runs, and only the font files are copied.

## 6. Legal Basis and Your Rights

OpenVAPT is an academic, non-commercial project that accepts no payments or donations, and it is used in many countries. We collect no personal data through the website or the software. The only exception is the older web server log files described in section 2, which were created before logging was turned off on 2026-10-13, contain IP addresses, are kept in an access-restricted area, are not used for any purpose and will be permanently deleted after 2026-11-12. Apart from those old logs, we believe we do not act as a controller, processor or business holding your personal data under laws such as the EU General Data Protection Regulation, the UK GDPR, the California Consumer Privacy Act or Malaysia's Personal Data Protection Act 2010, and that their obligations about notice, consent, access, correction, retention, breach notification, data protection officers and cross-border transfer have little or nothing to apply to. We follow their spirit by collecting nothing new. GitHub is responsible for the data it processes under its own privacy statement (section 4). If you believe we hold any data about you, or you wish to exercise a right that any such law gives you, tell us through a GitHub issue (without posting the data) or privately through GitHub Private Vulnerability Reporting, and we will check and answer honestly.

## 7. Children

The website and software collect no data from anyone, including children.

## 8. Security

There is no personal data to protect, so a breach of the website cannot expose your data. The website could, like any website, be tampered with; the full source of the website is public on GitHub, so its contents can be compared with the repository.

## 9. Who Wrote This Policy

This policy, like the rest of OpenVAPT, was developed by AI Cybersecurity Engineers (see `AI-DISCLOSURE.md`), reviewed by an AI system acting as the project's legal reviewer, and approved by the project owner. No human lawyer drafted or reviewed it. Every factual statement in it was checked against the real server and code configuration on the date above.

## 10. Questions

Ask publicly in GitHub Discussions at github.com/OpenVAPT/openvapt. There is no email contact.

## 11. Changes

Any change to this policy will be dated, published here and kept in the public Git history before it takes effect. We do not intend ever to start collecting data. Version 1.6 (2026-10-14) adds to section 3 the full list of files and folders the software reads after its coverage expansion; it is a factual addition that describes what the software already did and changes nothing about what we receive, which remains nothing. Version 1.7 (2026-10-14) states that OpenVAPT is used in many countries, explains in section 6 why we believe data protection laws such as the GDPR, the UK GDPR, the CCPA and the Personal Data Protection Act 2010 have little or nothing to apply to, apart from the older log files described in section 2, and says GitHub may store data in other countries; what we collect is unchanged, which remains nothing.
