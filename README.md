# OpenVAPT

An open academic project that shows, in full and in public, how a vulnerability assessment tool is designed, built, tested and released.

OpenVAPT runs read-only checks on the Linux machine it is installed on (and only that machine) to **identify** weaknesses in the server, its network exposure and its websites, **evaluate** them with CVSS v3.1 ratings, **propose fixes** with cited sources, and **verify** them. It writes a report to your own disk and never sends data anywhere.

> **Academic. Non-commercial. Open-source code. Free to download and use, for your own personal or business use, 100% at your own risk.**
> You may download and use OpenVAPT on computers and servers you own or control, for your own use. You may **not** sell it and you may **not** use it to provide services to anyone else, paid or unpaid. It comes as is, with no warranty, and the developers accept no responsibility for anything that happens.

## Read and Accept Before Use

Before downloading or running OpenVAPT, read, study and understand the [EULA](EULA.md), [Disclaimer](DISCLAIMER.md), [Acceptable Use Policy](ACCEPTABLE_USE.md) and [Licence](LICENSING.md). By downloading, building or using it, you acknowledge, agree to and accept every statement below. The tool shows the same statements before every scan and continues only when you type `I ACCEPT`.

1. I have read, studied and understood the End User Licence Agreement, the Disclaimer, the Acceptable Use Policy and the Licence.
2. I understand that OpenVAPT is an academic, non-commercial project made for learning, and that it is not a penetration test, an audit, a certification, a service or professional advice.
3. I will download and use OpenVAPT only for my own use, personal or business, and only on computers and servers that I own or control, or for which I have the owner's permission.
4. I will not sell OpenVAPT, include it in a product, or use it to provide services of any kind to anyone else, paid or unpaid.
5. I understand that automated results can be wrong or incomplete, and that a report without findings does not prove a system is secure.
6. I acknowledge, agree to and accept that I use OpenVAPT 100% at my own risk, and that I alone am responsible for every risk and every consequence, including damage, data loss, downtime, security incidents and legal liability.
7. I agree that the developers and contributors provide OpenVAPT as is, without any warranty, and accept no responsibility or liability of any kind, to the fullest extent the law allows.
8. I am solely responsible for complying with all laws that apply to me, including the Computer Crimes Act 1997 and the Cyber Security Act 2024 in Malaysia, and the laws of my own country.

Website: https://openvapt.com (generated from this repository; every check page cites its source file and line numbers).

## Quick Start

```bash
go test ./...
CGO_ENABLED=0 go build -trimpath -o openvapt ./cmd/openvapt
./openvapt demo                       # scan the simulated vulnerable lab server (safe, in memory)
./openvapt scan --dry-run             # list every file, command and request a real scan would use
sudo ./openvapt scan --out ~/report   # assess this Linux machine
```

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

56 checks in three domains: server (OS support, patches, SSH, accounts, sudo, file permissions, SUID, cron, kernel hardening, logging, audit, time), network (listening services, exposed databases, cleartext services, host firewall, TLS versions and certificates) and web apps (security headers, cookies, HTTPS redirect, exposed `.git`, `.env`, backups, phpinfo, directory listing, status pages, PHP settings, WordPress hygiene). Run `openvapt checks` for the full list.

## What It Does Not Do

No remote targets (enforced in `internal/scope`), no exploitation, no payloads, no brute force, no changes to the system, no data sent anywhere. It is not a penetration test and absence of findings is not proof of security.

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
