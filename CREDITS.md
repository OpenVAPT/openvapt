# Credits, Sources and Citations

OpenVAPT is transparent and open about where every line of code comes from, because it exists for own use and academic purposes: a reader should be able to trace any file back to its author, its exact upstream source and its licence. This file lists everything OpenVAPT uses, includes, refers to, applies, integrates or was built with, so that every source is cited accurately and honestly. If you find something missing or wrong, please open an issue.

**Forked code:** none. OpenVAPT does not fork or copy any other project's source code. The only third-party texts included word for word are licence texts (listed below), and the only third-party code shipped is the self-hosted website libraries listed below, unmodified.

## 1. Authorship

All code, tests, documentation, website content, course material and legal drafts were researched, developed and built by AI Cybersecurity Engineers under the direction of the project owner. See [AI-DISCLOSURE.md](AI-DISCLOSURE.md) for the exact systems, models, versions and roles:

- **Claude Opus 5.5** (Anthropic), through **Claude Code**: primary author of everything.
- **GPT-5.6** (OpenAI, `gpt-5.6-sol`), through **Codex CLI 0.162.1**: independent code review, fixes, network and data-service checks, report redesign.
- **GPT-6** (OpenAI, `gpt-6-sol`), through **Codex CLI 0.162.1**: offline vulnerability matching engine.

## 2. Included in the Compiled Program

| Component | Version | Licence | Source |
|---|---|---|---|
| Go standard library and runtime | Built with Go 1.26.x in CI and releases (Go 1.27.1 used for local development); minimum language version 1.22 (`go.mod`) | BSD 3-Clause | https://go.dev/ , licence text in THIRD_PARTY_NOTICES.md |

No third-party Go modules are used (`go.mod` has no `require` entries).

## 3. Included in the Website (Self-Hosted, Unmodified)

| Component | Version | Licence | Source | Used for |
|---|---|---|---|---|
| AG Grid Community | 36.2.0 | MIT | https://www.ag-grid.com/ , https://github.com/ag-grid/ag-grid | Check catalogue data grid |
| Apache ECharts | 6.1.0 | Apache-2.0 | https://echarts.apache.org/ | Charts |
| Lucide (lucide-static) | 1.55.0 | ISC | https://lucide.dev/ | Icons, inlined as SVG at build time |
| IBM Plex Sans | 1.1.0 (npm @ibm/plex-sans) | SIL Open Font License 1.1 | https://github.com/IBM/plex | Body and heading typeface |
| IBM Plex Mono | 2.5.0 (npm @ibm/plex-mono) | SIL Open Font License 1.1 | https://github.com/IBM/plex | Code typeface |

Exact versions are also recorded in `site/static/assets/vendor/VERSIONS.txt`, and each licence is published in `site/static/assets/vendor/LICENSES/`.

### 3a. File-by-File Inventory of Third-Party Code

Every third-party file served by the website, the exact upstream file it was copied from (by `site/scripts/vendor.mjs`, byte for byte, unmodified), its copyright holder, licence, and SHA-256 at the time of writing (2026-10-13). Re-run `shasum -a 256` on the files to verify.

| Published File | Upstream Source (npm package path) | Copyright | Licence | SHA-256 |
|---|---|---|---|---|
| `assets/vendor/ag-grid-community.min.js` | `ag-grid-community@36.2.0/dist/ag-grid-community.min.noStyle.js` | (c) 2015-2026 AG GRID LTD | MIT | `3b05777f78aa10b6d7fd020bc2076936b889e5a0ff9c1a764fdbe6aa19456993` |
| `assets/vendor/ag-grid.min.css` | `ag-grid-community@36.2.0/styles/ag-grid.min.css` | (c) 2015-2026 AG GRID LTD | MIT | `f1cab681a9157b54dc8124e3add01c0189c9f20cc86f09879702c44f4411e778` |
| `assets/vendor/ag-theme-quartz.min.css` | `ag-grid-community@36.2.0/styles/ag-theme-quartz-no-font.min.css` | (c) 2015-2026 AG GRID LTD | MIT | `d8a81f37f3f2f9a93cfbcfd715c415a8c190e19d1f9a577309d61cf1f530ba89` |
| `assets/vendor/echarts.min.js` | `echarts@6.1.0/dist/echarts.min.js` | (c) 2017-2026 The Apache Software Foundation; bundles ZRender 6.1.0 ((c) 2017 Baidu Inc.) and code derived from d3.js ((c) 2010-2016 Mike Bostock) | Apache-2.0; ZRender BSD 3-Clause; d3 parts BSD 3-Clause | `b66b25aeb4df84e33199dc21694014d336d222cbd9deb0e5a7c14bd6aa0d0fd0` |
| `assets/fonts/IBMPlexSans-{Regular,Medium,SemiBold,Bold}.woff2` | `@ibm/plex-sans@1.1.0/fonts/complete/woff2/` | (c) 2017 IBM Corp., Reserved Font Name "Plex" | SIL OFL 1.1 | Regular `ba711a3085ff9f27440b6b9c4550cfc47c97bf36591d5da958b975bb3add8c1a`; Medium `5660f8a658f8bb50dbc005232f885eadffd2bc1c235c4f6fbb63469d1f9cde6d`; SemiBold `f78048030eab62e860efa39a0df79e2e5581bf122eb95b9bc42c0b8a4988d205`; Bold `fa7130d854a660b39a7fc9e6e0f2dc23dba5f1346e2adea3e1fe37b6d884133d` |
| `assets/fonts/IBMPlexMono-{Regular,Medium}.woff2` | `@ibm/plex-mono@2.5.0/fonts/complete/woff2/` | (c) 2017 IBM Corp., Reserved Font Name "Plex" | SIL OFL 1.1 | Regular `ba204497f16b6d334cee9d1e963a831b73e3a56e1d6300a8489d18df7214b350`; Medium `33faf307fa6031fb4062276d7320a6d632de890cbb347576fd80cfa01077bc25` |
| Inline SVG icons (26): shield-check, calendar, code-xml, book-open, download, git-pull-request, list-checks, scale, server, network, globe, search, wrench, circle-check, triangle-alert, info, external-link, file-text, lock, eye-off, ban, graduation-cap, chevron-right, flask-conical, quote, gauge | `lucide-static@1.55.0/icons/<name>.svg`, copied to `site/icons/` and inlined into pages at build time | (c) 2026 Lucide Icons and Contributors; calendar, chevron-right, download, external-link, info, lock, search and server are derived from Feather, (c) 2013-present Cole Bemis | ISC; Feather-derived icons also MIT | per icon, see `site/icons/` |
| `assets/site.css` (generated) | Generated by Tailwind CSS 4.3.3 from `site/styles/site.css`; embeds Tailwind's preflight base styles (`tailwindcss@4.3.3/preflight.css`, which itself credits CSS Remedy and modern-normalize) | Utility output and preflight (c) Tailwind Labs, Inc.; the project's own styles are OpenVAPT's | MIT (Tailwind parts); OpenVAPT Licence (own styles) | `2717364508fd660c0e893f4aba5ac6ab6fcffd2b4fe8462a4c2f6f2b645a1052` |

Published licence texts: `assets/vendor/LICENSES/ag-grid-community.txt`, `echarts.txt`, `echarts-NOTICE.txt`, `zrender.txt`, `d3.txt`, `lucide.txt` (includes Feather's MIT notice), `ibm-plex.txt`, `tailwindcss.txt`.

Everything else in the repository (all Go code under `cmd/` and `internal/`, templates under `site/templates/`, the website's own CSS and JavaScript, tests, fixtures, scripts and documents) is original OpenVAPT work as described in section 1; no snippet was copied from Stack Overflow, blogs or other projects. Where a check's logic follows a published standard, that standard is cited on the check's own page next to a GitHub permalink to the exact source lines.

## 4. Build and Development Tools (Not Shipped)

| Tool | Version | Licence | Used for |
|---|---|---|---|
| Tailwind CSS and @tailwindcss/cli | 4.3.3 | MIT | Generating the website stylesheet (its preflight base styles end up in `site.css`; see 3a) |
| Node.js | 24.x | MIT | Running the website asset build |
| staticcheck | 2025.1.1 | MIT | Static analysis in CI |
| gosec | v2.22.0 | Apache-2.0 | Security static analysis in CI |
| govulncheck | v1.1.4 | BSD 3-Clause | Known-vulnerability scanning in CI |
| cosign (via sigstore/cosign-installer v3) | v3 action | Apache-2.0 | Keyless signing of release binaries |
| cyclonedx-gomod | v1.8.0 | Apache-2.0 | Software bill of materials for releases |
| GitHub Actions: actions/checkout v4, actions/setup-go v5, actions/setup-node v4, actions/attest-build-provenance v2 | as listed | MIT | CI and release automation |
| Git, GitHub, GitHub CLI | current | various | Version control, hosting, repository settings |

## 5. Licence and Legal Texts Used

| Text | How Used | Source |
|---|---|---|
| OpenVAPT Source-Available Licence 1.1 (1.0 before the Teaching terms) | Original text drafted by an AI Cybersecurity Engineer in `LICENSE`; replaced the PolyForm Noncommercial License 1.0.0 before any release, and no PolyForm text is retained | `LICENSE` |
| Go BSD 3-Clause licence | Included word for word in THIRD_PARTY_NOTICES.md | https://go.dev/LICENSE |
| Contributor Covenant 2.1 | Adopted by reference (linked, not copied) | https://www.contributor-covenant.org/version/2/1/code_of_conduct/ |
| Developer Certificate of Origin 1.1 | Referenced for commit sign-off | https://developercertificate.org/ |
| Malaysian legislation named in the legal documents | Referred to by name only; no text copied | Computer Crimes Act 1997, Cyber Security Act 2024, Personal Data Protection Act 2010 (as amended 2024), Contracts Act 1950, Consumer Protection Act 1999, Strategic Trade Act 2010, Copyright Act 1987, Communications and Multimedia Act 1998, Electronic Commerce Act 2006 |

The licence, EULA, Disclaimer, Privacy Policy and Acceptable Use Policy are original drafts written by AI Cybersecurity Engineers. They were not copied from any template.

## 6. Standards and Methodologies Applied

| Standard | Applied to |
|---|---|
| NIST SP 800-115, Technical Guide to Information Security Testing and Assessment | Scan phases (planning, discovery, analysis, reporting) and report structure |
| FIRST CVSS v3.1 Specification | Severity scale and representative base vectors for every check |
| OWASP Top 10 (2021) | Check mapping |
| OWASP Application Security Verification Standard (ASVS) 4.0.3 | Check mapping |
| MITRE Common Weakness Enumeration (CWE) | Check mapping and links |
| NIST SP 800-53 Rev. 5 | Control mapping |
| OASIS SARIF 2.1.0 | SARIF report format |
| Schema.org vocabulary | Website structured data (JSON-LD) |
| Sitemaps protocol 0.9, llms.txt convention | Website discovery files |
| Semantic Versioning 2.0.0, Conventional Commits 1.0.0 | Versioning and commit messages |
| CIS Benchmarks | Topics named only; no CIS text copied |

## 7. Sources Cited by Checks and the Academy

Each check cites at least one public source on its own page (`openvapt explain <ID>` or the website check page). Each Academy module lists its references. The sources include:

- NIST Special Publications: 800-12 Rev. 1, 800-30 Rev. 1, 800-40 Rev. 4, 800-41 Rev. 1, 800-52 Rev. 2, 800-53 Rev. 5, 800-63B, 800-92, 800-115, 800-123, 800-131A Rev. 2 (https://csrc.nist.gov/).
- IETF RFCs: 6125, 6265, 6797, 8996, 9142 (https://www.rfc-editor.org/).
- OWASP: Top 10, ASVS, Web Security Testing Guide, Cheat Sheet Series (Content Security Policy, Clickjacking Defense, Database Security, HTTP Headers, PHP Configuration, Secrets Management, Session Management, Transport Layer Security), Secure Headers Project (https://owasp.org/).
- MITRE: CWE (https://cwe.mitre.org/), ATT&CK techniques T1053.003 and T1548.001 (https://attack.mitre.org/).
- The CVE Program (https://www.cve.org/) and the Penetration Testing Execution Standard (http://www.pentest-standard.org/).
- Linux and software manuals: Linux man-pages (passwd(5), shadow(5), crontab(5), chmod(1), auditd(8), proc_net(5)), Linux kernel documentation (sysctl kernel, fs and IP), OpenBSD sshd_config(5), sudoers(5), systemd journald.conf(5), Apache HTTP Server documentation (ServerTokens, Options, mod_status), PHP manual (ini directives, phpinfo), nftables wiki, Redis security documentation, WordPress hardening and brute force guides, MDN Web Docs (HTTP headers), Let's Encrypt FAQ.

## 7a. Vulnerability Data

| Source | Used for | Licence |
|---|---|---|
| OSV (osv.dev) ecosystem exports | Advisories for Debian, Ubuntu, AlmaLinux, Rocky Linux, Packagist and npm, downloaded only in the release pipeline by `cmd/vulndbgen` | Varies by originating source; each release records what the sources state (see docs/VULNDB.md) |
| CISA Known Exploited Vulnerabilities catalogue | Marking advisories that are known to be exploited | See the CISA site; recorded per release |

The repository currently ships a small, hand-written **test fixture** snapshot whose versions are illustrative, not authoritative.

## 8. Data Sources for Version Tables

| Table | Location | Sources (Dated 2026-10-13) |
|---|---|---|
| Operating system end-of-life dates | `internal/checks/host/os_patch.go` | Ubuntu release cycle, Debian releases and LTS, Red Hat Enterprise Linux life cycle, endoflife.date (community data) |
| PHP end of security support | `internal/checks/web/php.go` | https://www.php.net/supported-versions.php |
| Well-known service ports | `internal/checks/network/listeners.go` | IANA Service Name and Transport Protocol Port Number Registry |

These tables can contain errors and become outdated; Codex's review found one (Debian LTS dates), which Codex corrected on 2026-10-13.

## 9. Design References

The website and report design follow, without copying code, the public design guidance of:

- **Ant Design 5** (Ant Group, MIT): colour tokens, component shapes and states. https://ant.design/
- **IBM Carbon Design System** (IBM, Apache-2.0): grid, typography and data density. https://carbondesignsystem.com/
- Apple's published interface guidance on response and motion, as summarised in the "apple-design" agent skill by Emil Kowalski (https://github.com/emilkowalski/skills), and the "taste-skill" anti-template design guidance; both were used as AI instructions, not shipped.

## 10. Infrastructure (Not Part of the Software)

- Website hosting: a virtual private server from The Constant Company, LLC (Vultr).
- HTTPS certificate: Let's Encrypt.
- Source hosting, issues and CI: GitHub, Inc.
