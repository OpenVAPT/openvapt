# ADR 0007: Release Channels Decided by Evidence Gates

Status: Accepted (2026-10-13); recorded 2026-10-14. Policy text: AGENTS.md section 5; code: `internal/channels`, `cmd/channel`, `.github/workflows/promote.yml`.

## Decision
One codebase moves through four channels, alpha, beta, release candidate and stable. A build is promoted only when every gate for the next channel passes: green CI on the exact commit; for beta, the full lab suite, 7 days on alpha and an AI legal review record for that exact version with no open High risk; for rc, the installer end to end test, signing with provenance and an SBOM, and 7 days on beta; for stable, 14 days on rc and a legal record for the stable candidate itself with `public_launch_approved` true. Promotions are decided by CI and AI Cybersecurity Engineers without a per-step owner approval, and every promotion appends evidence to `release/channels.json`, which is never edited or rewritten.

## Reason
The owner is the only human and cannot inspect every build. Gates turn release decisions into checkable evidence instead of judgement, and timers give each channel real exposure before the next. The legal record per version keeps the public statements true for the exact text a user downloads. Pre-release labelling on every build and page keeps "100% at your own risk" honest while nothing is stable.

## Consequences
No build can skip a channel, and a failed gate stops promotion with a stated reason. The AI legal reviewer must review each candidate version before it moves up, which costs a review per promotion. `release/legal-review.json` is written only by the AI legal reviewer and, since 2026-10-14, names accepted High risks and hashes the documents it covers. Faking, backdating or weakening a gate is forbidden (AGENTS.md 5.5).
