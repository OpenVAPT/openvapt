# Privacy Policy

Version 1.3, effective 2026-10-13. This policy was drafted by an AI Cybersecurity Engineer and reviewed by a separate AI system acting as the project's legal reviewer; no human lawyer drafted or reviewed it. It is an information notice, not a contract.

## Summary

**We collect no data.** OpenVAPT does not collect, use, analyse, sell, rent, share or transfer any personal data or any other data about visitors of openvapt.com or users of the OpenVAPT software. The only exception is the web server log files created before logging was turned off on 2026-10-13. These are held, unused, in an access-restricted area until they are permanently deleted after 2026-11-12, as explained in section 2. Below we explain, honestly and completely, every place where data could flow, and what happens there.

## 1. Who "We" Are

"We" means OpenVAPT, an academic, non-commercial project run by its project owner. Because we collect no personal data, there is no data controller holding any of your data. Questions can be raised publicly on GitHub (see section 9).

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

### The Beta Site

openvapt.com/beta/ is an internal preview, excluded from search engines. It follows exactly the same no-data rules.

## 3. The OpenVAPT Software

- The software runs entirely on your own machine and is designed to make **no network connection to any other machine at all**. Every connection is restricted in code to loopback addresses (127.0.0.0/8 and ::1). There is no telemetry, crash reporting, licence check, update check or usage statistics.
- When you run a scan, the software **reads** information on your machine to assess it, which may include sensitive information: system configuration files, the list of user accounts, `/etc/shadow` (when run as root, to find accounts without passwords), sudo rules, listening network services, installed packages, web server configuration, systemd service unit files, application configuration files (for example for Apache Tomcat, Django, Flask, WordPress, Joomla and Drupal), the output of an allow-list of read-only commands (for example `node --version`), and the home pages and selected paths of the websites your machine serves (requested through 127.0.0.1).
- Configuration files that can contain secrets are read for pattern matching only, and the checks are designed never to copy secret values into a report. As a second safeguard, before anything is written into a report, the software **redacts** recognised secrets such as passwords, keys, tokens and password hashes. Redaction is pattern-based and may not catch every secret; please review a report before sharing it.
- Reports are written **only to your own disk**, in a folder you choose, readable only by your user account (permissions 0700 for the folder and 0600 for the files). We never receive them.
- If you choose to sign reports, a signing key is created on your machine (`~/.config/openvapt/report-key`, permission 0600) and never leaves it.
- What happens to your reports afterwards (who you share them with, where you store them) is entirely your responsibility.

## 4. GitHub

The source code, bug reports, discussions, security reports and the automated build pipeline are hosted on **GitHub, Inc.** (a subsidiary of Microsoft), at github.com/OpenVAPT/openvapt.

- If you visit the repository, download from it, open an issue, start a discussion, submit a pull request or send a private vulnerability report, **GitHub** processes your data under the GitHub Privacy Statement. GitHub may store data on servers outside Malaysia, including in the United States.
- Anything you post publicly on GitHub (issues, discussions, pull requests, comments) is public to everyone and may be copied or archived by others. **Never post secrets, full reports, hostnames, IP addresses or personal data.**
- Private vulnerability reports are visible only to the project maintainers and GitHub until a fix is published, after which a public security advisory describes the issue.
- The maintainers can see what GitHub shows any repository maintainer (for example your GitHub username on issues you open). We do not copy, export or keep that information anywhere else.

## 5. Software Packages and Fonts

The website uses self-hosted copies of AG Grid Community, Apache ECharts, Lucide icons and the IBM Plex fonts. They run inside your browser and make no network requests. The IBM Plex font packages include an install-time telemetry configuration intended for IBM; our build installs packages with scripts disabled, so it never runs, and only the font files are copied.

## 6. Legal Basis and Your Rights

OpenVAPT is an academic, non-commercial project that accepts no payments or donations. Malaysia's Personal Data Protection Act 2010 (as amended in 2024) applies to personal data processed in respect of commercial transactions, and we carry out none. We also do not collect personal data through the website or the software. For these reasons we believe the Act's obligations about notice, consent, access, correction, retention, breach notification, data protection officers and cross-border transfer do not apply to us. We nevertheless follow its spirit by collecting nothing. We do not target visitors in the European Union and we collect no data, so we believe the EU General Data Protection Regulation does not apply either. If you believe we hold any data about you, tell us publicly on GitHub (without posting the data) and we will check and answer honestly.

## 7. Children

The website and software collect no data from anyone, including children.

## 8. Security

There is no personal data to protect, so a breach of the website cannot expose your data. The website could, like any website, be tampered with; the full source of the website is public on GitHub, so its contents can be compared with the repository.

## 9. Who Wrote This Policy

This policy, like the rest of OpenVAPT, was developed by AI Cybersecurity Engineers (see `AI-DISCLOSURE.md`), reviewed by an AI system acting as the project's legal reviewer, and approved by the project owner. No human lawyer drafted or reviewed it. Every factual statement in it was checked against the real server and code configuration on the date above.

## 10. Questions

Ask publicly in GitHub Discussions at github.com/OpenVAPT/openvapt. There is no email contact.

## 11. Changes

Any change to this policy will be dated, published here and kept in the public Git history before it takes effect. We do not intend ever to start collecting data.
