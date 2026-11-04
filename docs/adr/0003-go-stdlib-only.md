# ADR 0003: Go With the Standard Library Only

Status: Accepted (2026-10-13)

## Decision
Write the tool in Go as one static binary with no third-party modules.

## Reasons
A single file is easy to verify and remove; no runtime to install on the server; the standard library covers HTTP, TLS, parsing and Ed25519; zero dependencies means no supply-chain or licence surprises, and every line in the binary is either ours or the Go project's.
