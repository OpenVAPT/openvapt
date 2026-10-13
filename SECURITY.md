# Security Policy

## Reporting a Vulnerability in OpenVAPT

If you find a security flaw in OpenVAPT itself (for example a way around the loopback scope guard, a command that escapes the read-only allow-list, a secret that survives redaction, or a flaw in report signing), please report it privately through **GitHub Private Vulnerability Reporting**: open the repository's Security tab and choose "Report a vulnerability".

Please do not open a public issue for security flaws, and do not include real secrets or full reports.

There is no email channel. GitHub holds the report; the project publishes a security advisory, credits the reporter if they wish, and discloses the details once a fix is released, normally within 90 days.

## Supported Versions

Only the latest minor release receives security fixes.

## Scope

This policy covers the OpenVAPT code and the openvapt.com website source. Findings that OpenVAPT reports about your own machine are not vulnerabilities in OpenVAPT; please fix them on your machine.
