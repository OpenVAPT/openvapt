# Changelog

All notable changes are documented here. This project follows Semantic Versioning and Conventional Commits.

## [Unreleased]

### Release Channels
- One codebase and one website with four channels: Alpha, Beta, Release Candidate and Stable. Promotion is decided by evidence gates in internal/channels (CI, lab proof, soak time, AI legal review of the exact build, installer test, signing, provenance and SBOM, public release sign-off), run daily by .github/workflows/promote.yml; every promotion is recorded in release/channels.json (Claude).
- `openvapt version`, every report and the website show the channel; pre-release builds carry a warning. The installer takes `--channel` (Stable by default). The website stays noindex until a signed-off Stable release exists. New Release Channels page.

### Licence and Legal (2026-10-13)
- Relicensed before any release from PolyForm Noncommercial 1.0.0 with an Additional Permission to the self-contained OpenVAPT Source-Available Licence 1.0 (`LicenseRef-OpenVAPT-SAL-1.0`): only Own Use is licensed, and providing any service, paid or unpaid, is not licensed for anyone. ADDITIONAL-PERMISSION.md removed. Free Teaching (simulated lab or the institution's own authorised machines) is licensed and is not a service.
- Pre-release warning for alpha, beta and rc builds in the licence, EULA, Disclaimer, Acceptable Use Policy, README and website.
- Terminology: OpenVAPT is described as researched, developed and built by AI agents under human direction.
- EULA 2.0, Disclaimer 1.4, Acceptable Use Policy 1.3, Licence summary 2.0, acknowledgements 1.3: gift framing, no relationship or duty, release of claims, no reliance, read-down liability limit, non-affiliation notice for third-party names, installer risk notice.

### Coverage Expansion: Services, Firewall Correlation, Application Stacks and CMS
- 31 new checks, 165 in total (Claude): systemd service hardening HOST-SYSD-001 to 005 (root services, sandboxing, writable unit files and programs, secrets in Environment=); firewall versus listener correlation NET-FW-003 to 006 (sensitive ports open to anywhere, stale rules, Docker bypassing the host firewall, exposure map) and NET-APP-001 (application server ports exposed directly); Apache Tomcat WEB-TOM-001 to 005 (Manager restriction, default credentials, shutdown port, AJP Ghostcat, sample apps); Node.js WEB-NODE-001 to 003 (end of life, inspector, production mode); Python WEB-PY-001 to 005 (Django DEBUG, ALLOWED_HOSTS, generated SECRET_KEY, Flask/Werkzeug debugger, development servers); CMS WEB-CMS-004 to 011 (configuration permissions, WordPress debug display, file editor and automatic updates, Joomla debug and version manifest, Drupal changelog).
- New read-only collectors for systemd units with drop-ins, ufw, nftables and iptables allow rules, Tomcat installations, Django settings and CMS configuration; `node --version` added to the read-only command allow-list.
- Academy modules P11 (systemd), P12 (firewall policy versus listeners), P13 (Tomcat, Node.js, Python) and P14 (CMS hardening), seven new glossary terms; vulnerable and hardened labs extended so every new check is proven both ways.

### Vulnerability Management and Containers
- Offline vulnerability matching: HOST-CVE-001 to 003 and WEB-CVE-001, Debian and RPM version comparison, inventory of OS packages and web libraries, release-time snapshot from OSV and CISA KEV (OpenAI Codex, GPT-6; reviewed and corrected by Claude).
- Docker and Kubernetes host checks HOST-CTR-001 to 004 and HOST-K8S-001 to 003; Academy modules P9 and P10 (Claude).

### Redesign to Professional Standards
- Control-category framework: every check belongs to one of ten categories mapped to CIS Controls v8 and NIST CSF 2.0, with a remediation effort and OWASP WSTG ids where applicable (Claude).
- 123 checks (from 58): 47 server and web checks by Claude; 18 network, data-service and TLS checks by OpenAI Codex.
- Report schema v3 with executive summary, risk heat map, framework coverage and prioritised remediation plan (OpenAI Codex).
- Coverage Dashboard, category and standard filters in the catalogue, Academy modules P7 and P8 (Claude).

### Security and Fixes (contributed by OpenAI Codex, reviewed by Claude)
- Independent code review by OpenAI Codex (17 findings) and fixes for all 16 code findings: exclusive private report writing, exact command allow-list, SSH Match evaluation, Incomplete status instead of false passes, stricter firewall, HSTS, CSP and TLS checks, certificate chain verification, vhost include parsing, Debian LTS dates, Markdown escaping.
- New checks HOST-SSH-007 (forwarding and tunnels) and HOST-SSH-008 (login grace and authentication methods), documented exit codes, report schema v2, coverage-gap summaries, docs/REPORT_SIGNING.md.

### Added (contributed by Claude)
- OpenVAPT Academy (15 modules, glossary, `openvapt learn`), FAQ and comparison pages, structured data, acknowledgement gate, AI disclosure, credits, contributors, revised legal documents.

### Added
- First public build of OpenVAPT: 58 read-only checks across server, network and web apps.
- Loopback-only scope guard, read-only command allow-list, dry-run recorder.
- Reports in HTML, JSON, SARIF 2.1.0 and Markdown, with methodology and limitations; report diff; Ed25519 report signing.
- Simulated vulnerable and hardened lab servers (`openvapt demo`) used by the test suite.
- Website generator that cites the source of every check.
