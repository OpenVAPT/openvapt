# ADR 0009: Single Owner and Project Continuity

Status: Accepted (2026-10-13); recorded 2026-10-14. Related: GOVERNANCE-CONTROL-ASSURANCE.md A9 (single points of failure), legal risk register item 1, EULA section 23, LICENSE sections 2 and 10.

## Decision
OpenVAPT is run by one human owner, who is the licensor in law under the project name and whose identity is not published. Every AI Cybersecurity Engineer acts under that owner's chat approvals. The owner accepted the resulting entity risk on 2026-10-13 rather than forming a company. Continuity is provided by design, not by a second person: the full source, history, tests, documents and release evidence are public on GitHub; EULA section 23 and LICENSE section 10 already allow the project to be transferred to another person or a body formed to look after it; contributors grant a relicensing licence so a successor can keep the project whole.

## Reason
Forming an entity costs money and identity disclosure that the owner chose not to accept at this stage. Public history means that, if the owner stops, anyone may still read, study, build and use every released copy under the licence that travels with it (LICENSE section 12), and nothing a user depends on (no service, no server, no key) needs the owner to keep running.

## Consequences
Two single points of failure remain and are recommended as owner decisions, not taken by AI Cybersecurity Engineers (AGENTS.md 3.9, 3.10, 3.12): (1) add a second owner to the GitHub organisation, or a documented recovery route, so that loss of one account does not freeze the repository, releases and the security reporting channel; (2) deposit the repository with Software Heritage (a free, public archive that accepts a public repository URL), so the full history is kept independently of GitHub and of the owner. Both are recorded here as open on 2026-10-14. Until decided, the public Git history and the signed releases are the only continuity mechanism, and documents say so plainly rather than promising permanence.
