# Changelog

All notable changes are documented here. This project follows Semantic Versioning and Conventional Commits.

## [Unreleased]

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
