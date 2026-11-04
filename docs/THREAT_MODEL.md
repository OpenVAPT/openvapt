# Threat Model (STRIDE)

The system under study is OpenVAPT itself: a binary run, often as root, on a production server.

| Threat | Example | Mitigation | Where |
|---|---|---|---|
| Spoofing | A malicious host name or /etc/hosts entry makes "localhost" point elsewhere | Only literal loopback IPs are accepted; names are never resolved; connected peer re-checked | `internal/scope` |
| Tampering | A modified binary is distributed | Releases are built only by GitHub Actions when promote.yml calls release.yml after every channel gate passed (no tag push trigger); every asset is listed in SHA256SUMS, each binary has a Sigstore bundle, build provenance is attested and an SBOM is attached; the release is created as a draft and published only after every asset is re-verified against SHA256SUMS; users verify before running | `.github/workflows/promote.yml`, `.github/workflows/release.yml` |
| Tampering | The installer is served a modified binary over the network | HTTPS only with TLS 1.2 or newer, including redirects, for curl and wget; SHA-256 always checked; Sigstore identity pinned to release.yml on main when cosign is installed; `OPENVAPT_REQUIRE_SIGNATURE=1` refuses to install without cosign; `file://` accepted only with `OPENVAPT_ALLOW_FILE=1`, which exists for the installer's own offline tests | `scripts/install.sh` |
| Tampering | A shared report is edited to hide findings | Ed25519 signature (format `openvapt.sign/2`) over the canonical JSON of the report without its integrity block; `openvapt verify` decodes strictly (unknown fields, duplicate keys and letter case variants refused) and requires the file to match the canonical JSON byte for byte, with one trailing newline allowed | `internal/sign`, `internal/report/strict.go` |
| Tampering | Another local user replaces or reads the report signing key | Key folder must be a non-symlink directory owned by the effective user with mode 0700, key a regular non-symlink file owned by that user with mode 0600; new keys created exclusively without following symlinks; reports left unsigned when there is no per-user configuration folder, never keyed from a shared folder | `internal/sign` |
| Repudiation | Unclear which version produced a report | Version and commit embedded in every report | `internal/version` |
| Information disclosure | Secrets copied into evidence | Redaction of keys, tokens, URL credentials, hashes; values of cookies never recorded | `internal/redact` |
| Information disclosure | Reports readable by other users | Report files written 0600 in a 0700 folder | `internal/report/write.go` |
| Information disclosure | Data sent to a third party | No network code except loopback; proxies disabled; no telemetry | `internal/sys`, `internal/scope` |
| Denial of service | A scan overloads a production server | Bounded file walks, capped HTTP bodies, per-check timeouts, limited parallelism, fixed small path lists | `internal/sys`, `internal/engine` |
| Denial of service | A FIFO, device or symlink planted in a scanned path stalls the scan or redirects a read | Files opened read-only with O_NONBLOCK, and with O_NOFOLLOW where a symlink must not be followed; every check runs under its own timeout (90 seconds by default) | `internal/sys/open_unix.go`, `internal/engine` |
| Elevation of privilege | A check runs arbitrary commands as root | Exact command allow-list; php limited to `echo ini_get()`; minimal PATH and environment | `internal/sys/sys.go` |
| Misuse | The tool is pointed at someone else's server | Impossible without modifying the code; forbidden by licence, EULA and AUP | `internal/scope`, legal docs |

Residual risks: a user may modify the code (the licence and AUP forbid misuse); bugs in checks may produce wrong results (lab tests and public review reduce this).
