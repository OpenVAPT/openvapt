# Security Policy

## Reporting a Vulnerability in OpenVAPT

If you find a security flaw in OpenVAPT itself (for example a way around the loopback scope guard, a command that escapes the read-only allow-list, a secret that survives redaction, or a flaw in report signing), please report it privately through **GitHub Private Vulnerability Reporting**: open the repository's Security tab and choose "Report a vulnerability".

Please do not open a public issue for security flaws, and do not include real secrets or full reports.

There is no email channel. GitHub holds the report. We aim to publish a security advisory, credit the reporter if they wish, and disclose the details once a fix is released, normally within 90 days. This is a voluntary aim, not a promise or an obligation (see the EULA, No Support and No Obligation).

## Supported Versions

We intend to fix security flaws only in the latest minor release, on a voluntary basis and without any obligation.

## Code Built by AI Agents

OpenVAPT's code was researched, developed and built by AI agents (see AI-DISCLOSURE.md) and has not been audited by an independent human security expert. Independent review is especially welcome.

## Scope

This policy covers the OpenVAPT code and the openvapt.com website source. Findings that OpenVAPT reports about your own machine are not vulnerabilities in OpenVAPT; please fix them on your machine.
