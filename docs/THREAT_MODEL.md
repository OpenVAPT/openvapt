# Threat Model (STRIDE)

The system under study is OpenVAPT itself: a binary run, often as root, on a production server.

| Threat | Example | Mitigation | Where |
|---|---|---|---|
| Spoofing | A malicious host name or /etc/hosts entry makes "localhost" point elsewhere | Only literal loopback IPs are accepted; names are never resolved; connected peer re-checked | `internal/scope` |
| Tampering | A modified binary is distributed | Releases built only in CI from signed tags, Sigstore signatures, SBOM and provenance; users verify before running | `.github/workflows/release.yml` |
| Tampering | A shared report is edited to hide findings | Optional Ed25519 signature over the full report; `openvapt verify` | `internal/sign` |
| Repudiation | Unclear which version produced a report | Version and commit embedded in every report | `internal/version` |
| Information disclosure | Secrets copied into evidence | Redaction of keys, tokens, URL credentials, hashes; values of cookies never recorded | `internal/redact` |
| Information disclosure | Reports readable by other users | Report files written 0600 in a 0700 folder | `internal/report/write.go` |
| Information disclosure | Data sent to a third party | No network code except loopback; proxies disabled; no telemetry | `internal/sys`, `internal/scope` |
| Denial of service | A scan overloads a production server | Bounded file walks, capped HTTP bodies, per-check timeouts, limited parallelism, fixed small path lists | `internal/sys`, `internal/engine` |
| Elevation of privilege | A check runs arbitrary commands as root | Exact command allow-list; php limited to `echo ini_get()`; minimal PATH and environment | `internal/sys/sys.go` |
| Misuse | The tool is pointed at someone else's server | Impossible without modifying the code; forbidden by licence, EULA and AUP | `internal/scope`, legal docs |

Residual risks: a user may modify the code (the licence and AUP forbid misuse); bugs in checks may produce wrong results (lab tests and public review reduce this).
