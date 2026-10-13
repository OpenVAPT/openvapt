# OpenVAPT

An open academic project that shows, in full and in public, how a vulnerability assessment tool is designed, built, tested and released.

OpenVAPT runs read-only checks on the Linux machine it is installed on (and only that machine) to **identify** weaknesses in the server, its network exposure and its websites, **evaluate** them with CVSS v3.1 ratings, **propose fixes** with cited sources, and **verify** them. It writes a report to your own disk and is designed never to send data anywhere.

> **Academic. Non-commercial. Built by AI Cybersecurity Engineers. Open, source-available code. Free to download and use, for your own personal or business use, 100% at your own risk.**
> You may download and use OpenVAPT on computers and servers you own or control (or that your employer owns or controls and has authorised you to assess), for your own use. You may **not** sell it and you may **not** provide any service to anyone else with anything from or produced by OpenVAPT (no consulting, no scanning for clients, no hosted service, no reselling reports), paid or unpaid, even with their permission. The project itself is not a business and accepts no payments or donations. It comes as is, with no warranty, and the developers accept no responsibility for anything that happens.
>
> **All of OpenVAPT was researched, developed and built by AI Cybersecurity Engineers** (Claude by Anthropic through Claude Code, with code review and fixes by OpenAI Codex), directed and approved by the human project owner. It has not been audited by an independent human security expert. The legal documents were drafted by an AI Cybersecurity Engineer and reviewed by a separate AI system acting as the project's legal reviewer; no human lawyer drafted or reviewed them. See [AI-DISCLOSURE.md](AI-DISCLOSURE.md).
>
> AI Cybersecurity Engineers are AI systems (Claude by Anthropic, through Claude Code, and OpenAI Codex) acting in a cyber security engineering role. They are not people, not registered or professional engineers, and provide no professional engineering or security service.

> **Pre-release.** Builds on the alpha, beta and release candidate (rc) channels are pre-release: they may be wrong, incomplete or unstable and are used 100% at your own risk. Only stable builds are full releases, and they too come with no warranty.

## Read and Accept Before Use

Before downloading or running OpenVAPT, read, study and understand the [EULA](EULA.md), [Disclaimer](DISCLAIMER.md), [Acceptable Use Policy](ACCEPTABLE_USE.md) and [Licence](LICENSING.md). By downloading, building or using it, you acknowledge, agree to and accept every statement below. The tool shows the same statements before every scan and continues only when you type `I ACCEPT`, or when you pass `--accept-terms` for automation, which counts as the same acceptance.

1. I have read, studied and understood the End User Licence Agreement, the Disclaimer, the Acceptable Use Policy and the Licence.
2. I understand that OpenVAPT is an academic, non-commercial project made for learning, and that it is not a penetration test, an audit, a certification, a service or professional advice.
3. I will download and use OpenVAPT only for my own use, personal or business, and only on computers and servers that I own or control, or that my employer owns or controls and has authorised me to assess.
4. I will not sell OpenVAPT, include it in a product, or use it to provide services of any kind to anyone else, paid or unpaid.
5. I understand that automated results can be wrong or incomplete, and that a report without findings does not prove a system is secure.
6. I acknowledge, agree to and accept that I use OpenVAPT 100% at my own risk, and that I alone am responsible for every risk and every consequence, including damage, data loss, downtime, security incidents and legal liability.
7. I agree that OpenVAPT is a free gift from people who are not in business, provided as is, without any warranty, and that, to the fullest extent the law allows, the developers and contributors owe me no duty and accept no responsibility or liability of any kind, and I release them from every claim.
8. I am solely responsible for complying with all laws that apply to me, including the Computer Crimes Act 1997 and the Cyber Security Act 2024 in Malaysia, and the laws of my own country.
9. I understand that OpenVAPT's code, documentation, website and legal texts were researched, developed, built and reviewed by AI Cybersecurity Engineers (AI systems, not people or registered engineers) under the direction of the project owner, may contain mistakes, and have not been audited by a human security expert or drafted or reviewed by a human lawyer.

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
sudo ./openvapt scan --out ~/report                   # assess this Linux machine
```

### One-Command Install

One command downloads the Linux binary of the chosen release channel (Stable by default, or `--channel rc|beta|alpha` on test machines) for your CPU, verifies its SHA-256 checksum (always) and its Sigstore signature (when `cosign` is installed), and installs it to `~/.local/bin` without root. It scans nothing. Read [scripts/install.sh](scripts/install.sh) first; it is short.

```bash
curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh
```

To install and then start an interactive scan of this machine in the same command (the scan still shows the acknowledgements and waits for you to type `I ACCEPT`):

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh)" -- --run
```

Options: `--version vX.Y.Z` pins a release, `--dir DIR` chooses the folder. If the chosen channel has no release yet, the installer says so and lists the channels that have one.

The installer downloads only over HTTPS with TLS 1.2 or newer, including redirects. To refuse installation unless the Sigstore signature is verified (instead of continuing with the checksum alone when `cosign` is missing), set `OPENVAPT_REQUIRE_SIGNATURE=1`:

```bash
curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | OPENVAPT_REQUIRE_SIGNATURE=1 sh
```

### Verify

**Optional verified binaries.** For machines without Go, each release publishes Linux binaries built only by GitHub Actions through the promotion workflow (promote.yml, after every channel gate passed), with `SHA256SUMS`, Sigstore signature bundles, build provenance, an SBOM and a source archive. See [docs/REPORT_SIGNING.md](docs/REPORT_SIGNING.md) for the `gh attestation verify` and `cosign verify-blob` commands. You can rebuild the same bytes yourself with `make release VERSION=<tag>` using the same Go version, and compare checksums.

## Commands

| Command | Purpose |
|---|---|
| `openvapt scan` | Assess this machine; writes `report.html`, `report.json`, `report.sarif`, `report.md` |
| `openvapt demo [--lab vulnerable or hardened]` | Scan a simulated server, for learning |
| `openvapt checks [--json]` | List every check |
| `openvapt explain <ID>` | Full documentation for one check |
| `openvapt diff old.json new.json` | What was fixed, what is new, what is still open |
| `openvapt verify report.json [--key-id ID]` | Confirm a signed report was not edited |
| `openvapt terms` / `version` | Terms of use, version |

Scan flags: `--out`, `--format`, `--only`, `--skip`, `--baseline`, `--dry-run`, `--accept-terms`, `--no-sign`, `--parallel`. Exit code 3 means Critical or High findings exist.

## What It Covers

165 checks in three domains and ten control categories mapped to CIS Controls v8 and NIST CSF 2.0: server (patching and lifecycle, accounts and password policy, SSH, sudo, file and key permissions, mount options, kernel hardening, mandatory access control, services, systemd service hardening, logging and auditing), network and data services (listening services, firewalls including IPv6, firewall rules compared with what is actually listening, Docker firewall bypass, exposed application server ports, Redis, MongoDB, PostgreSQL, MySQL, Memcached, Elasticsearch, NFS, Samba, DNS and mail configuration, admin ports, TLS versions, ciphers, keys and certificates), containers (Docker daemon, privileged containers, socket mounts, kubelet, etcd), known vulnerabilities (offline matching of OS packages and web libraries against OSV and CISA KEV data) and web apps (security headers, cookies, CORS, HTTPS, exposed files, logs, debug pages and admin tools, secrets and backups inside web roots on disk, PHP and WordPress hygiene), application stacks (Apache Tomcat Manager, AJP, users and sample apps; Node.js runtime lifecycle, inspector and production mode; Django and Flask debug, host and secret key settings, development servers) and deeper CMS checks (WordPress, Joomla and Drupal configuration permissions, debug output, file editor, automatic updates and version files). Run `openvapt checks` for the full list.

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

OpenVAPT Source-Available Licence 1.1 (`LicenseRef-OpenVAPT-SAL-1.1`, file [LICENSE](LICENSE)): Own Use only, no services, no selling. Source-available, not OSI open source. See [LICENSING.md](LICENSING.md).

Names of other projects and products in this repository (for example Lynis, OpenVAS, ZAP, WordPress, Apache Tomcat, Node.js and Django) identify them only. Their owners do not sponsor, endorse or have any connection with OpenVAPT.
