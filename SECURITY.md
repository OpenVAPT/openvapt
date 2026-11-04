# Security Policy

## Reporting a Vulnerability in OpenVAPT

If you find a security flaw in OpenVAPT itself (for example a way around the loopback scope guard, a command that escapes the read-only allow-list, a secret that survives redaction, or a flaw in report signing), please report it privately through **GitHub Private Vulnerability Reporting**: open the repository's Security tab and choose "Report a vulnerability". Reports are welcome from anyone in any country, in any language; English gets the fastest reply.

Please do not open a public issue for security flaws, and do not include real secrets or full reports.

There is no email channel. GitHub holds the report. We aim to acknowledge a report within 7 days, to publish a security advisory, to credit the reporter if they wish, and to disclose the details once a fix is released, normally within 90 days. These are voluntary aims, not promises or obligations (see the EULA, No Support and No Obligation).

**Reporters without a GitHub account.** GitHub Private Vulnerability Reporting is at present the only channel. Whether a second, non-GitHub path will be offered, or GitHub is confirmed as the only channel, is an open owner decision; this policy will state the outcome. A machine-readable copy of this policy's contact details is published at https://openvapt.com/.well-known/security.txt (RFC 9116).

## Supported Versions

We intend to fix security flaws only in the latest minor release, on a voluntary basis and without any obligation. While no stable release exists, "latest minor release" means the most recent build on the most mature release channel (see https://openvapt.com/channels.html); a fix lands on main and reaches users through the next promoted build, never by patching an older pre-release.

## Code Built by AI Cybersecurity Engineers

OpenVAPT's code was researched, developed and built by AI Cybersecurity Engineers (see AI-DISCLOSURE.md) and has not been audited by an independent human security expert. Independent review is especially welcome.

## Scope

This policy covers the OpenVAPT code and the openvapt.com website source. Findings that OpenVAPT reports about your own machine are not vulnerabilities in OpenVAPT; please fix them on your machine.
