# ADR 0006: Generate the Website From the Code

Status: Accepted (2026-10-13)

## Decision
`cmd/sitegen` builds openvapt.com from the check registry and the source files, with line-accurate citations found by parsing the Go code and permalinks pinned to the build commit. Legal pages are rendered from the Markdown files in the repository.

## Consequences
Documentation cannot drift from behaviour. The site is static, so it needs no server-side code, database or cookies.
