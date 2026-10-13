# Changelog

All notable changes are documented here. This project follows Semantic Versioning and Conventional Commits.

## [Unreleased]

### Governance
- One public site (owner decision in chat, 2026-10-13): everything is published at https://openvapt.com/ for every channel. Privacy Policy 1.5 replaces the internal /beta/ preview paragraph with this; no data practice changed. AGENTS.md 1.3 clarifies that the stable gate needs release/legal-review.json for that exact stable candidate version (no rule changed). Governance, Control and Assurance Framework status notes: terminology test and internal findings register now listed as existing.
- Legal (2026-10-13, AI legal reviewer, an AI system, not a human lawyer): the owner accepted in chat the personal risk that OpenVAPT is a project name and not a registered legal entity, approved the public website launch (indexed, with pre-release banners) and chose to publish answer keys in every channel. `release/legal-review.json` now covers v0.1.0-alpha.2 with `open_high_risks: 0` (entity risk accepted, not closed) and `public_launch_approved: true`. EULA 2.2, Disclaimer 1.6, Privacy Policy 1.4 and NOTICE state that OpenVAPT is built by AI Cybersecurity Engineers under the direction of one human owner, who is the licensor in law and bears residual risk; no right or obligation changed. Teaching With OpenVAPT 1.1 states that answer keys are public and how to set fair graded work. GOVERNANCE.md, CITATION.cff authors and the Governance, Control and Assurance Framework status notes updated to match (no control changed).
- Adopted the Governance, Control and Assurance Framework 1.0 (GOVERNANCE-CONTROL-ASSURANCE.md), effective 2026-10-13, approved by the owner in chat and reviewed by the AI legal reviewer (an AI system, not a human lawyer). AGENTS.md bumped to 1.2 and incorporates it by reference (new section 11, precedence unchanged). Added the docs/TASK-CARD.md template, a GOVERNANCE.md pointer and a plain-English summary in AI-DISCLOSURE.md.

### Security
- Workflows: every checkout uses `persist-credentials: false` except the promote record job, which pushes and runs only setup-go and `go run ./cmd/channel`; Go comes from the `toolchain go1.26.9` line in go.mod (`check-latest: false`).
- Release: full `go test -race ./...` on the shipped build; the release is created as a draft, every asset is uploaded and re-verified against SHA256SUMS, then it is published. A re-run on an existing release fails unless all expected assets are present and match SHA256SUMS, so record never runs on an incomplete release. A leftover draft from an interrupted run stops the release with instructions; it is never published or deleted automatically. Provenance attests both binaries explicitly.
- Promote: the signed gate now requires and verifies the arm64 binary and its Sigstore bundle as well as amd64.
- vulndbgen: KEV matching over ID, aliases and OSV `upstream` (Debian records); conservative CVSS v4 and Ubuntu priority severities; HTTPS-only streamed downloads with a 1 GiB cap, redirect refusal and timeouts; one ecosystem at a time; oversized records, too many records and parse failures above 1% fail the build.
- Installer: HTTPS only with TLS 1.2 or newer across redirects for curl and wget; `file://` only with `OPENVAPT_ALLOW_FILE=1`; `OPENVAPT_REQUIRE_SIGNATURE=1` makes a missing cosign fatal; strict version format; channel names validated before use or display. Release verification with `gh attestation verify` documented in docs/REPORT_SIGNING.md.
- Release: the release workflow is split into a `build` job without write access and a `publish` job (`needs: build`) that holds the write token, approved by the owner; it first runs at the next release.
- cmd/channel: updating CITATION.cff fails if its version or date line is missing; table tests for channel precedence.

### Report Signing (2026-10-13)
- Signature format `openvapt.sign/2`: the signature covers the canonical JSON of the report without its integrity block, and `report.json` is written as exactly that JSON with the block added. `openvapt verify` decodes the file strictly (unknown fields, duplicate keys and letter case variants are refused), requires it to match the canonical JSON byte for byte (one trailing newline allowed) and caps it at 64 MiB. Reports with the older `openvapt.report/2` schema give "cannot verify: signed with an older report format" instead of a false tamper result. See docs/REPORT_SIGNING.md.
- Reports are written unsigned, with a warning, when there is no per-user configuration folder; the key is never kept in a shared folder such as /tmp. The key folder and key must not be symlinks, must be owned by the effective user and must deny group and other access; new keys are created exclusively without following symlinks.

### Scanner Safety (2026-10-13)
- Files are opened with O_NONBLOCK (a FIFO or device cannot stall the scan) and with O_NOFOLLOW where a symlink must not be followed; every check runs under its own timeout.

### Check Metadata and Severity (2026-10-13)
- HOST-PWD-005 (forced periodic password rotation) is now Info, citing NIST SP 800-63B-4, which says verifiers should not require periodic password changes.
- CWE, NIST SP 800-53, OWASP ASVS, OWASP WSTG and OWASP Top 10 mappings corrected across checks, including a specific CWE for each data service check.
- End of support tables: new rows for Fedora 42, Ubuntu 25.10 and 26.04 LTS, Ubuntu interim releases 20.10 to 23.04, CentOS Stream 9, RHEL, Rocky and AlmaLinux 10, Oracle Linux 7 to 9 and Amazon Linux 1. A release older than the oldest row of its distribution (and PHP below 5.6) now fails as past end of support instead of being unknown.

### Check Logic Fixes (2026-10-13)
- End of support table re-verified against each vendor's published dates: Fedora 42 2026-05-27, Fedora 44 2027-06-02, CentOS Stream 10 2030-05-31, AlmaLinux 8 2029-05-31; Ubuntu 16.04, 23.04, 23.10, 25.04 and 25.10 dates corrected; Oracle Linux 10 added.
- HOST-KRN-005: on Docker hosts a trailing RETURN rule in DOCKER-USER no longer causes a false fail.
- sshd Match evaluation: Match user and group names keep their letter case, and a Group is represented by its primary-group members as well as the members listed in /etc/group.
- SSH: the parser accepts `Key=value`, applies first value wins across Include files (relative paths resolved against /etc/ssh), keeps settings after a Match line from overriding global values, and applies OpenSSH defaults for unset forwarding and password keywords.
- Kernel: per-interface sysctl rules require `all`, `default` and every interface to hold the hardened value (interface names with dots such as VLANs are read directly); a kernel without IPv6 is no longer an unreadable input.
- Firewall: a port-less accept rule (ufw, nftables, iptables) is treated as admitting every port unless it only matches return traffic or a protocol without ports; ufw's own boilerplate chain is excluded.
- Web: header and cookie checks skip a site whose home page answers with a redirect; HSTS max-age accepted as a token or quoted string; framing evaluates CSP frame-ancestors before X-Frame-Options; Referrer-Policy uses the last recognised token; cookies being cleared and anti-CSRF token cookies are no longer flagged for missing HttpOnly.
- Accounts: lockout requires pam_faillock with both preauth and authfail and reads deny from the module line, then faillock.conf, then the default of 3 (pam_tally2 needs an explicit deny); service accounts are judged against UID_MIN from /etc/login.defs.
- Files: world-writable directories without the sticky bit are found without following symlinks.
- TLS: ECDSA keys below 256 bits are reported as weak, alongside RSA below 2048 bits.

### Website (2026-10-13)
- Accessibility and SEO: heading order fixed (card headings are real h2 elements), canonical and og:url emitted once per page and omitted on the 404 page, WebSite structured data, long Academy navigation labels truncate instead of overflowing, Title Case fixes.
- Build assertions: sitegen fails when a page title (with suffix) or meta description breaks the length rules, and when it cannot resolve the git commit for pinned source links (unless `-allow-unpinned` is passed).
- Governance pages published: legal/governance.html (Governance, Control and Assurance Framework) and legal/agents.html (AI Cybersecurity Engineer Policy).
- One public site for every channel (owner decision, 2026-10-13): openvapt.com/beta/ is retired and every /beta/ URL redirects (301) to the same page at the root, so alpha, beta, rc and stable are all visible at https://openvapt.com/.
- Redirects: HTTP to HTTPS and www.openvapt.com to openvapt.com (301).
- Repository Markdown links that point to files not published on the site now link to the file on GitHub instead of a missing page.
- Release wording: releases are described as built only through promote.yml after every channel gate passed, not from signed tags; the download page and README document `OPENVAPT_REQUIRE_SIGNATURE=1` and HTTPS-only downloads, and pin the cosign identity to release.yml on main.

### Tests (2026-10-13)
- `internal/sources` TestTerminology fails the build if public text calls OpenVAPT "open source" or "non-profit", or uses "AI-generated" or "AI agents", unless the line plainly negates or quotes the phrase or names a third party.

### Deferred (2026-10-13)
- None open. The release job split is done (see Security) and HOST-KRN-005 is container-aware (see Added).

### Docs
- SOURCES.md: generated by the new `internal/sources` package from every check and Academy reference (165 sources, 31 publishers), grouped by publisher with terms, credit lines and the checks citing each; published at legal/sources.html. Tests fail if it goes stale or a check cites an unrecorded publisher.
- CREDITS.md: section 7 now points to SOURCES.md; new 7b credit lines for MITRE, FIRST, CIS, OWASP, NIST and IETF (reviewed by the AI legal reviewer, 0 open high risks); added CIS Controls v8, NIST CSF 2.0, OWASP WSTG and MITRE ATT&CK to the standards table; exact pinned GitHub Actions versions.
- CITATION.cff: version corrected to 0.1.0-alpha.2 and repository URL capitalisation; `cmd/channel promote` now updates it automatically and a test enforces it.
- CREDITS.md: file-by-file inventory of every third-party file (upstream path, copyright, licence, SHA-256); cite ZRender, d3.js, Feather and Tailwind preflight, which are bundled inside shipped files; publish their licence texts.

### Audit and Fixes (Claude, with three independent AI review passes)
- Severity now always matches the check's own CVSS v3.1 vector: a shared calculator (internal/check/cvss.go, tested against FIRST reference scores) is enforced at registration; 56 overstated or wrong vectors corrected and 12 severities adjusted to their honest scores.
- Release pipeline: release.yml runs only from promote.yml (no gate bypass by tag push), re-runs the tests and installer test on exactly the shipped binaries, states the embedded snapshot checksum, covers every asset in SHA256SUMS, is safe to re-run, and pins every action to a commit; the record step retries on a moving main and refuses a version that differs from the published one; channel outputs are validated; promotion requires the exact tested commit and the same release cycle.
- Installer: signature identity pinned to release.yml on main, Ctrl-C stops it, help works when piped, clear error when HOME is unset, Windows line endings tolerated.
- Check accuracy: negated iptables and nftables sources and ports, nftables comments and loopback rules, ufw rules on lo, systemd drop-ins ordered across all directories including /run, commented-out WordPress define() lines ignored, Django's last DEBUG assignment honoured, --inspect-port no longer reported as the inspector.
- Teacher toolkit: openvapt teach (course plans, worksheets and answer keys, rubric, practice-lab answer keys with --only and --skip), seeded practice labs (openvapt demo --lab practice --seed), For Teachers page, printable worksheets and keys for every module, TEACHING.md.
- Website: Title Case fixes, noindex on sample reports, clearer channel gate wording, CITATION.cff version.

### Release Channels
- One codebase and one website with four channels: Alpha, Beta, Release Candidate and Stable. Promotion is decided by evidence gates in internal/channels (CI, lab proof, soak time, AI legal review of the exact build, installer test, signing, provenance and SBOM, public release sign-off), run daily by .github/workflows/promote.yml; every promotion is recorded in release/channels.json (Claude).
- `openvapt version`, every report and the website show the channel; pre-release builds carry a warning. The installer takes `--channel` (Stable by default). The website is indexed since the owner approved the public launch on 2026-10-13 (recorded in release/legal-review.json), and every page carries a pre-release banner until a Stable release exists. New Release Channels page.

### Licence and Legal (2026-10-13)
- Licence version 1.1 (`LicenseRef-OpenVAPT-SAL-1.1`): release v0.1.0-alpha.1 was published under version 1.0, so the widened Teaching grant is a new version rather than an edit of 1.0. Version 1.1 adds the Teaching With OpenVAPT terms and their conditions and leaves every other term unchanged; licence section 15 records the history. A student's own machine is that student's Own Use, not Teaching.
- Relicensed before any release from PolyForm Noncommercial 1.0.0 with an Additional Permission to the self-contained OpenVAPT Source-Available Licence 1.0 (`LicenseRef-OpenVAPT-SAL-1.0`): only Own Use is licensed, and providing any service, paid or unpaid, is not licensed for anyone. ADDITIONAL-PERMISSION.md removed. Free Teaching (simulated lab or the institution's own authorised machines) is licensed and is not a service.
- Pre-release warning for alpha, beta and rc builds in the licence, EULA, Disclaimer, Acceptable Use Policy, README and website.
- TEACHING.md 1.0, Teaching With OpenVAPT terms; licence Teaching definition and grant aligned; EULA 2.1, Acceptable Use Policy 1.5, Licence summary 2.1.
- Terminology: OpenVAPT is described as researched, developed and built by AI Cybersecurity Engineers under human direction.
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
- HOST-KRN-005 (IP forwarding) now detects a container runtime or Kubernetes node read-only (runtime sockets, /etc/kubernetes, or docker0, cni0, cbr0 or flannel.1 in /sys/class/net). There forwarding is required, so the check passes with context when the forward path is filtered (FORWARD policy DROP, nftables forward policy drop, or DOCKER-USER DROP/REJECT rules), fails when forwarded traffic is accepted by default, and is incomplete when the policy cannot be read. New lab variant `lab.ContainerHost()`.
- The sshd allow-list now also permits `sshd -T -C user=<u>,host=localhost,addr=<a>` built only from validated Match User, Group and Address values (user names `^[a-z_][a-z0-9_-]{0,31}$`, canonical IP literals or the first address of a CIDR, a Group represented by its first member in /etc/group, at most 8 extra contexts, no shell). Risky values found this way are reported as conditional Match findings. Still read-only: sshd only evaluates its configuration.
