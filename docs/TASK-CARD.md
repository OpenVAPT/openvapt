# Task Card Template

Use one Task Card for every change of tier T1 or higher (AGENTS.md section 11, GOVERNANCE-CONTROL-ASSURANCE.md). Copy this template into the task record. Records never contain secrets, private hostnames, personal data or the owner's identity (AGENTS.md 9.4).

## Card

| Field | Entry |
|---|---|
| Card Id | |
| Date | YYYY-MM-DD |
| Goal | One sentence: what changes and why. |
| User Served | Who benefits (server administrator on their own server, teacher, student, researcher) and what they can now do. |
| Risk Tier | T0, T1, T2 or T3 (GCA G5). When unsure, use the higher tier. Only the owner may lower a T2 or T3. |
| Steward | The coordinating run. |
| Builder | Model and run (for example Claude, or Codex `gpt-6-sol` in its own worktree with stdin closed). |
| Verifier | A different, fresh-context run. T2 and T3: a different model family, or "same-family review" under the GCA A1 rule 4 fallback. |
| Owner Approval | T3 and AGENTS.md section 3 only: date and one-line summary of the owner's approval in chat. Otherwise "Not required". |

## Mission Check

Answer each line Yes, No or Not Affected. Any No stops the work and goes to the AI legal reviewer.

| # | Invariant | Result |
|---|---|---|
| I1 | Scans only the machine it runs on (literal loopback addresses only) | |
| I2 | Read-only, detection only, no exploit code, changes nothing on the scanned machine | |
| I3 | Collects, stores and sends no data, from the tool or the website | |
| I4 | Own use and free Teaching only: no selling, no services, no business use, no payments or donations | |
| I5 | Described as academic, free, source-available and non-commercial; never "open source", "non-profit", a business or a product | |
| I6 | Every claim true, sourced and reproducible; no safety absolutes | |
| I7 | Honest AI disclosure: built by AI Cybersecurity Engineers; reviews called "AI-reviewed"; no human review claimed | |

## File Lease

One Builder per path. List every path this card may change; anything outside the lease needs a new or amended card.

| Path | Leased To | Until |
|---|---|---|
| | | |

## Definition of Done

Copy the rows from GCA A3 that apply (Check, Code, Public Text, UI, Academy, Release) and tick each when its evidence is attached.

- [ ] 
- [ ] Full CI green (`gofmt -l .`, `go vet ./...`, `go test ./...`, website build)
- [ ] CHANGELOG.md updated where the change is notable

## Required Lenses

Tick the review lenses this card needs (GCA G4) and name who ran each.

| Lens | Required | Run By | Result |
|---|---|---|---|
| Security | | | |
| VAPT Standards | | | |
| QA | | | |
| UX and Accessibility | | | |
| Education | | | |
| Facts and Sources | | | |
| Privacy | | | |
| Claims | | | |
| Supply Chain | | | |
| Terminology | | | |
| AI Legal Reviewer (Guardian) | T2 and T3 | | |

## Evidence

Evidence classes (GCA A2): E1 automated test or CI run id; E2 reproducible command output; E3 browser screenshot; E4 primary-source citation with lookup date; E5 reasoned review. T2 and T3 items need E1, E2 or E4; E5 alone never closes them.

| Claim or Check | Class | Reference |
|---|---|---|
| | | |

## Result

| Field | Entry |
|---|---|
| Commit | Hash, with a `Co-Authored-By` trailer naming the real model. |
| Verifier Report | Reference. |
| Findings | Opened, closed on evidence, or carried forward. |
| Residual Risk | None, or the risk and who accepted it (the owner for any High). |
