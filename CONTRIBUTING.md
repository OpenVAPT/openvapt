# Contributing to OpenVAPT

Thank you for helping. OpenVAPT is an academic project, so clear explanations matter as much as working code.

## Ground Rules

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
- Contributions are licensed under the same terms as the project (LICENSE and ADDITIONAL-PERMISSION.md).
- One topic per pull request. CI must be green.

## Reporting Bugs

Use the issue templates: Bug, False Positive, False Negative, New Check, Documentation.

## Code of Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
