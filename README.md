# OpenVAPT

An open academic project that shows, in full and in public, how a vulnerability assessment tool is designed, built, tested and released.

OpenVAPT runs read-only checks on the Linux machine it is installed on (and only that machine) to **identify** weaknesses in the server, its network exposure and its websites, **evaluate** them with CVSS v3.1 ratings, **propose fixes** with cited sources, and **verify** them. It writes a report to your own disk and is designed never to send data anywhere.

> **Academic. Non-commercial. Built by AI Cybersecurity Engineers. Open, source-available code. Free to download and use, for your own personal or business use, 100% at your own risk. Open to anyone, in any country.**
> You may download and use OpenVAPT on computers and servers you own or control (or that your employer owns or controls and has authorised you to assess), for your own use. You may **not** sell it and you may **not** provide any service to anyone else with anything from or produced by OpenVAPT (no consulting, no scanning for clients, no hosted service, no reselling reports), paid or unpaid, even with their permission. The project itself is not a business and accepts no payments or donations. It comes as is, with no warranty, and the developers accept no responsibility for anything that happens.
>
> **All of OpenVAPT was researched, developed and built by AI Cybersecurity Engineers** (Claude by Anthropic through Claude Code, with code review, fixes and some checks and components built by OpenAI Codex), directed and approved by the human project owner. It has not been audited by an independent human security expert. The legal documents were drafted by an AI Cybersecurity Engineer and reviewed by a separate AI system acting as the project's legal reviewer; no human lawyer drafted or reviewed them. See [AI-DISCLOSURE.md](AI-DISCLOSURE.md).
>
> AI Cybersecurity Engineers are AI systems (Claude by Anthropic, through Claude Code, and OpenAI Codex) acting in a cyber security engineering role. They are not people, not registered or professional engineers, and provide no professional engineering or security service.

> **Pre-release.** Builds on the alpha, beta and release candidate (rc) channels are pre-release: they may be wrong, incomplete or unstable and are used 100% at your own risk. Only stable builds are full releases, and they too come with no warranty.

## Cite OpenVAPT

Using OpenVAPT in research, teaching or a report? Please cite it, with the version you used. Run `openvapt cite` (or `openvapt cite --format bibtex`) to print the citation for your exact build; every report also ends with a How to Cite block. The author is the group author "OpenVAPT"; do not add personal names. OpenVAPT has no DOI yet.

APA 7:

> OpenVAPT. (2026). OpenVAPT: An open academic vulnerability assessment tool (Version 0.1.0-alpha.2) [Computer software]. https://github.com/OpenVAPT/openvapt

BibTeX:

```bibtex
@software{openvapt_2026,
  author       = {{OpenVAPT}},
  title        = {{OpenVAPT: An Open Academic Vulnerability Assessment Tool}},
  year         = {2026},
  version      = {0.1.0-alpha.2},
  url          = {https://github.com/OpenVAPT/openvapt},
  note         = {Built by AI Cybersecurity Engineers. https://openvapt.com},
  license      = {LicenseRef-OpenVAPT-SAL-1.3}
}
```

Every other style (IEEE, Harvard, MLA, Chicago, Vancouver, RIS, CSL-JSON) is on https://openvapt.com/cite.html and in [CITING.md](CITING.md); GitHub's "Cite this repository" button reads [CITATION.cff](CITATION.cff). A test keeps these lines identical to what the website, the CLI and the reports print.

## Read and Accept Before Use

Before downloading or running OpenVAPT, read, study and understand the [EULA](EULA.md), [Disclaimer](DISCLAIMER.md), [Acceptable Use Policy](ACCEPTABLE_USE.md), [Licence](LICENSING.md), [Teaching With OpenVAPT](TEACHING.md) and [Citing OpenVAPT](CITING.md). By downloading, building or using it, you acknowledge, agree to and accept every statement below. The tool shows the same statements before every scan and continues only when you type `I ACCEPT`, or when you pass `--accept-terms` for automation, which counts as the same acceptance.

1. I have read, studied and understood the End User Licence Agreement, the Disclaimer, the Acceptable Use Policy, the Licence, the Teaching With OpenVAPT terms and Citing OpenVAPT.
2. I understand that OpenVAPT is an academic, non-commercial project made for learning, and that it is not a penetration test, an audit, a certification, a service or professional advice.
3. I will download and use OpenVAPT only for my own use, personal or business, and only on computers and servers that I own or control, or that my employer owns or controls and has authorised me to assess.
4. I will not sell OpenVAPT, include it in a product, or use it to provide services of any kind to anyone else, paid or unpaid.
5. I understand that automated results can be wrong or incomplete, and that a report without findings does not prove a system is secure.
6. I acknowledge, agree to and accept that I use OpenVAPT 100% at my own risk, and that I alone am responsible for every risk and every consequence, including damage, data loss, downtime, security incidents and legal liability.
7. I agree that OpenVAPT is a free gift from people who are not in business, provided as is, without any warranty, and that, to the fullest extent the law allows, the developers and contributors owe me no duty and accept no responsibility or liability of any kind, and I release them from every claim.
8. I am solely responsible for complying with all laws that apply to me wherever I am, including computer misuse, cyber security, data protection and export laws, such as the Computer Fraud and Abuse Act (United States), the Computer Misuse Act 1990 (United Kingdom), Directive 2013/40/EU (European Union) and the Computer Crimes Act 1997 (Malaysia).
9. I understand that OpenVAPT's code, documentation, website and legal texts were researched, developed, built and reviewed by AI Cybersecurity Engineers (AI systems, not people or registered engineers) under the direction of the project owner, may contain mistakes, and have not been audited by a human security expert or drafted or reviewed by a human lawyer.
10. I am at least 18 years old (or the age of majority where I live), or my parent or guardian has read these statements and accepts them for me in their own name; and where I act for an organisation, I am authorised to bind it.

Website: https://openvapt.com (generated from this repository; every check page cites its source file and line numbers). Every component, standard, source and AI tool used is credited in [CREDITS.md](CREDITS.md).

## Get OpenVAPT

### Build From Source

**Building from source is the recommended, most transparent way**: you run exactly the code you can read, and it needs nothing but Go (1.26 or newer; `go.mod` pins the 1.26.9 toolchain, which newer Go downloads automatically).

```bash
git clone https://github.com/OpenVAPT/openvapt.git && cd openvapt
go test ./...                                         # unit tests and simulated lab tests
CGO_ENABLED=0 go build -trimpath -o openvapt ./cmd/openvapt
./openvapt terms                                      # read the acknowledgements
./openvapt demo                                       # scan the simulated vulnerable lab (safe, in memory)
./openvapt learn                                      # the OpenVAPT Academy, offline
./openvapt scan --dry-run                             # preview every file, command and request
sudo ./openvapt scan                                  # assess this Linux machine; reports go to ~/openvapt-reports/<UTC time>/
```

**Vulnerability snapshot.** The repository embeds only a tiny test fixture in `internal/vulndb/data/`, so a plain source build has no advisory data: `HOST-CVE-001`, `HOST-CVE-002`, `HOST-CVE-003` and `WEB-CVE-001` then report Incomplete (never Pass), and `openvapt vulndb` prints `Fixture: true`. To match real advisories, generate the snapshot from the public OSV exports and the CISA KEV feed before building:

```bash
make vulndb                                           # downloads OSV and KEV data, writes internal/vulndb/data/snapshot.json.gz
make build                                            # embeds it
./openvapt vulndb                                     # shows the snapshot date and Fixture: false
```

Release builds run the same generator (see `docs/VULNDB.md`). Every report header shows the snapshot date and age; a snapshot older than 90 days is marked in the header and fails only the Low check `HOST-CVE-003`.

### One-Command Install

One command downloads the Linux binary for your CPU from the most stable release channel that has a release (Stable, then Release Candidate, then Beta, then Alpha; it warns and names the channel when that is a pre-release, and `--channel NAME` forces one), verifies its SHA-256 checksum (always) and its Sigstore signature (when `cosign` is installed), and installs it to `~/.local/bin` without root. Read [scripts/install.sh](scripts/install.sh) first. There are two ways to run it.

**Download Only** (the default) installs, verifies and prints the next steps. It scans nothing; you scan later with `openvapt scan --dry-run`, then `sudo openvapt scan`.

```bash
curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh
```

**Download and Scan** (`--run`) installs, verifies, then scans this machine in the same terminal. The scan still shows the acknowledgements and waits for you to type `I ACCEPT` (read from the terminal even when the script is piped; the installer never accepts for you, and with no terminal it refuses). It writes every report (HTML, JSON, SARIF, Markdown, signed) to a new folder `~/openvapt-reports/<UTC time>/` (mode 0700), then prints the severity summary, the exit code and what it means, every report path and how to open the HTML report.

```bash
curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh -s -- --run
```

Options: `--sudo` (with `--run`) runs only the scan with sudo for full coverage, `--out DIR` chooses a new report folder, `--open` opens `report.html` with `xdg-open` only in a desktop session, `--dry-run` previews what a scan would read and run without scanning, `--version vX.Y.Z` pins a release, `--dir DIR` chooses the install folder. A forced channel with no release fails and lists the channels that have one.

The installer downloads only over HTTPS with TLS 1.2 or newer, including redirects. To refuse installation unless the Sigstore signature is verified (instead of continuing with the checksum alone when `cosign` is missing), set `OPENVAPT_REQUIRE_SIGNATURE=1`:

```bash
curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | OPENVAPT_REQUIRE_SIGNATURE=1 sh
```

### Verify

**Optional verified binaries.** For machines without Go, each release publishes Linux binaries built only by GitHub Actions through the promotion workflow (promote.yml, after every channel gate passed), with `SHA256SUMS`, Sigstore signature bundles, build provenance, an SBOM and a source archive. See [docs/REPORT_SIGNING.md](docs/REPORT_SIGNING.md) for the `gh attestation verify` and `cosign verify-blob` commands. You can rebuild the same bytes yourself with `GOTOOLCHAIN=go1.26.9 make release VERSION=<tag>` using the same Go version, and compare checksums.

## Commands

| Command | Purpose |
|---|---|
| `openvapt scan` | Assess this machine; writes `report.html`, `report.json`, `report.sarif`, `report.md` |
| `openvapt demo [--lab vulnerable or hardened]` | Scan a simulated server, for learning |
| `openvapt checks [--json]` | List every check |
| `openvapt explain <ID>` | Full documentation for one check |
| `openvapt diff old.json new.json` | What was fixed, what is new, what is still open |
| `openvapt verify report.json [--key-id ID]` | Confirm a signed report was not edited |
| `openvapt cite [--format apa\|ieee\|harvard\|mla\|chicago\|bibtex\|ris\|csl\|cff] [--check ID] [--module ID]` | Print how to cite this exact version, a check or an Academy module |
| `openvapt terms` / `version` | Terms of use, version |
| `openvapt man` | Print the manual page: `openvapt man > openvapt.1`, then `man ./openvapt.1` |
| `openvapt completion bash\|zsh\|fish` | Print a shell completion script, for example `source <(openvapt completion bash)` |

Scan flags: `--out` (default: a new folder `~/openvapt-reports/<UTC time>/`, mode 0700, in the home folder of the user running the scan, which is root's under sudo), `--open` (opens `report.html` with `/usr/bin/xdg-open` only in a desktop session, never as root), `--format`, `--only`, `--skip`, `--baseline`, `--dry-run`, `--accept-terms`, `--no-sign`, `--quiet`, `--parallel` (1 to 32), `--timeout` (whole scan, for example `30m`), `--fail-on` (`critical`, `high`, `medium`, `low`, `info` or `none`; default `high`), `--suppress` (a suppression file, below).

### Suppressing Accepted Findings

`--suppress <file>` names a JSON list of accepted findings, in the spirit of the Grype and Trivy ignore files but stricter. No file is ever loaded unless you name it. Each entry has `id` (a check id, required), `target` (optional: an exact target or a glob such as `/etc/ssh/sshd_config.d/*`; empty means every target of that check), `reason` (required, non-empty), `expires` (required, `YYYY-MM-DD`, at most 365 days ahead) and `added_by` (optional). See [docs/suppress.sample.json](docs/suppress.sample.json).

A malformed file, an unknown key, an unknown check id, or an entry without a reason or expiry is refused with exit code 2 before any scanning starts. Expired entries are ignored and listed as a warning. Suppressions are visible, never silent: a suppressed finding keeps its Fail status and severity in every format, appears in a Suppressed Findings section of the HTML and Markdown reports with its reason and expiry, carries a SARIF `suppressions` entry of kind `external` with the reason as justification, and the report header states how many results were suppressed and the file's SHA-256. Suppressed findings do not count toward `--fail-on`; coverage gaps and errors still do. The file is read with the same bounded regular-file reader as reports (1 MiB cap).

Exit codes, for scripts and CI:

| Code | Meaning |
|---|---|
| 0 | Completed; no unsuppressed finding at or above the `--fail-on` severity, and no coverage gap |
| 2 | Invalid arguments or usage, including a rejected `--suppress` or `--baseline` file |
| 3 | Unsuppressed findings at or above the `--fail-on` severity (default: Critical or High) |
| 4 | Incomplete coverage: at least one check could not observe enough to decide |
| 5 | Internal error, a check ended with an error, or the scan was interrupted |
| 6 | The report could not be written |

Checked in order 5, 4, 3: an error or coverage gap is reported before findings, so a clean exit 0 means every selected check reached a verdict. `--fail-on none` never returns 3.

## What It Covers

307 checks in three domains and ten control categories mapped to CIS Controls v8 and NIST CSF 2.0: server (patching and lifecycle, accounts and password policy, SSH, sudo, file and key permissions, mount options, kernel hardening, mandatory access control, services, systemd service hardening, logging and auditing), network and data services (listening services rated by service identity and how they are bound, firewalls including IPv6, firewall rules compared with what is actually listening, Docker firewall bypass, exposed debugger and application server ports, Redis, MongoDB, PostgreSQL, MySQL, Memcached, Elasticsearch, NFS, Samba, DNS and mail configuration, admin ports, TLS versions, ciphers, keys and certificates), containers (Docker daemon, privileged containers, socket mounts, kubelet, etcd), known vulnerabilities (offline matching of OS packages and web libraries against OSV and CISA KEV data, with WordPress core inventoried and reported Incomplete because OSV publishes no WordPress feed, each match labelled with its matcher) and web apps (security headers, cookies, CORS, HTTPS, exposed files, logs, debug pages and admin tools, secrets and backups inside web roots on disk, PHP and WordPress hygiene), application stacks (Apache Tomcat Manager, AJP, users and sample apps; Node.js runtime lifecycle, inspector and production mode; Django and Flask debug, host and secret key settings, development servers) and deeper CMS checks (WordPress, Joomla and Drupal configuration permissions, debug output, file editor, automatic updates and version files). Run `openvapt checks` for the full list.

## What It Does Not Do

By design: no remote targets (enforced in `internal/scope`), no exploitation, no payloads, no brute force, no changes to the system, no data sent anywhere. It is not a penetration test and absence of findings is not proof of security.

## Repository Layout

```
cmd/openvapt          command-line interface
cmd/sitegen           builds the website from the code
internal/scope        loopback-only network guard (security boundary)
internal/sys          read-only system access; live, dry-run and fake implementations
internal/check        check definition and registry
internal/checks/      host/, network/, web/ checks and shared collectors
internal/engine       runs checks, redacts, builds the report
internal/redact       secret redaction
internal/report       HTML, JSON, SARIF, Markdown, diff
internal/sign         Ed25519 report signing
internal/lab          simulated vulnerable and hardened servers
scripts/install.sh    one-command installer (verifies checksum and signature, scans nothing)
site/                 website templates, content and assets
docs/                 architecture, threat model, decision records
```

## Standards

NIST SP 800-115 (methodology, minus the attack phase), CVSS v3.1 (severity), OWASP Top 10 2021 and ASVS 4.0.3, CWE, NIST SP 800-53 Rev. 5, SARIF 2.1.0 (report format). See https://openvapt.com/standards.html.

## Contributing, Security, Citation

- Bugs and ideas: GitHub Issues. Questions: GitHub Discussions. There is no email contact.
- Security flaws in OpenVAPT: GitHub Private Vulnerability Reporting, see [SECURITY.md](SECURITY.md).
- How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md). Governance: [GOVERNANCE.md](GOVERNANCE.md).
- How to cite: [CITATION.cff](CITATION.cff).

## Privacy

OpenVAPT and openvapt.com collect no data. See [PRIVACY.md](PRIVACY.md).

## Licence

OpenVAPT Source-Available Licence 1.3 (`LicenseRef-OpenVAPT-SAL-1.3`, file [LICENSE](LICENSE)): Own Use only, no services, no selling, credit required when you copy, quote, adapt or present OpenVAPT material. Source-available, not OSI open source. See [LICENSING.md](LICENSING.md).

## Citing OpenVAPT

Please cite OpenVAPT in any research paper, thesis, coursework, presentation, poster or academic project it helped, with the version you used. Ready-to-copy APA, IEEE, Harvard, MLA, Chicago, Vancouver, BibTeX, BibLaTeX, RIS and CSL-JSON citations are in [CITING.md](CITING.md); GitHub's "Cite this repository" button reads [CITATION.cff](CITATION.cff).

```
OpenVAPT. (2026). OpenVAPT: An open academic vulnerability assessment tool (Version 0.1.0-alpha.2) [Computer software]. https://github.com/OpenVAPT/openvapt
```

Names of other projects and products in this repository (for example Lynis, OpenVAS, ZAP, WordPress, Apache Tomcat, Node.js and Django) identify them only. Their owners do not sponsor, endorse or have any connection with OpenVAPT.
