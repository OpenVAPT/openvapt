# Architecture

```
            +-------------------- cmd/openvapt (CLI) --------------------+
            | scan | demo | checks | explain | diff | verify | terms     |
            +----------------------------+-------------------------------+
                                         |
                              internal/engine (runner)
              selects checks, runs in parallel with timeouts, recovers
              panics, redacts (internal/redact), builds the report
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
  internal/checks/host        internal/checks/network          internal/checks/web
         \______________ internal/checks/collect (shared readers) ______/
                                         |
                              sys.System (read-only interface)
           +------------------+----------------------+------------------+
           |                  |                      |                  |
       sys.Live          sys.Recorder            sys.Fake          (nothing else)
   real machine        --dry-run printer     tests + internal/lab
           |
   internal/scope.Dialer: every HTTP/TLS connection must be to 127.0.0.0/8 or ::1
                                         |
                    internal/report -> report.html/json/sarif/md (local disk, 0600)
                    internal/sign   -> optional Ed25519 signature (local key)
```

## Data Flow

1. The user runs `openvapt scan`, accepts the terms, and the engine selects checks.
2. Each check reads what it needs through `sys.System`. The live implementation only reads files, runs allow-listed read-only commands, and talks to 127.0.0.1.
3. Results are redacted, sorted and summarised into a `report.Report`.
4. The report is written to the local disk and optionally signed. Nothing leaves the machine.

## Why These Choices

See the decision records in `docs/adr/`.
