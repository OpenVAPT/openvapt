# Contributing to OpenVAPT

Thank you for helping. OpenVAPT is an academic project, so clear explanations matter as much as working code.

## Ground Rules

- AI Cybersecurity Engineers (Claude, OpenAI Codex and any other) must follow [AGENTS.md](AGENTS.md), the AI Cybersecurity Engineer governance policy.
- Detection only. No exploit code, payloads, brute force or intrusive techniques will be accepted.
- This machine only. Never weaken `internal/scope` or the `internal/sys` allow-list.
- Read-only. Checks may only use the `sys.System` interface.
- Cite sources. Every check needs at least one public reference.
- Never paste real secrets, hostnames or full reports into issues or pull requests.

## Adding a Check

1. Create a file in `internal/checks/host`, `network` or `web`, modelled on an existing check.
2. Fill in every field: ID, Title, Severity, CVSS, Summary, Rationale, Detection, Fix, Verify, Refs, Standards.
3. Update `internal/lab/lab.go` so the vulnerable lab triggers it and the hardened lab passes it.
4. Run `make check` (format, vet, tests). The engine tests fail until both labs behave correctly.

## Commits and Pull Requests

- Sign off each commit under the Developer Certificate of Origin: `git commit -s`. See https://developercertificate.org/.
- Use Conventional Commits: `feat(web): add check for ...`, `fix(scope): ...`, `docs: ...`.
- Contributions are licensed under the OpenVAPT Source-Available Licence 1.3, and you grant the licensor a licence to relicense them (LICENSE, section 10). You also authorise the licensor to accept the EULA's protections for contributors on your behalf (LICENSE, section 10(d)). No payment or credit is owed.
- One topic per pull request. CI must be green.

## Reporting Bugs

Use the issue templates: Bug Report, False Positive, False Negative, New Check, Documentation, Factual Error, Teaching Feedback. Security flaws go through GitHub Private Vulnerability Reporting, never a public issue.

## Code of Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Release Heads

The promotion workflow treats a commit that changes only `CHANGELOG.md`, `CITATION.cff` or files under `release/` as a record commit, not a new release head, so a CHANGELOG-only commit never starts a new alpha on its own.
