# Contributors

OpenVAPT is researched, developed and built entirely by AI Cybersecurity Engineers under human direction. Everyone and everything that has contributed is listed here, with what they did. See also [AI-DISCLOSURE.md](AI-DISCLOSURE.md) and [CREDITS.md](CREDITS.md).

| Contributor | Type | Contributions |
|---|---|---|
| The OpenVAPT project owner | Human | Goals, rules, product, legal and policy decisions; approval of every change; publishing and operating the project. Did not hand-write the code. |
| Claude (Claude Opus 5.5, Anthropic), through Claude Code | AI system | Planning, design, architecture (including the control-category framework), most original code including 82 of the first 123 checks and all 31 checks of the systemd, firewall correlation, application server and CMS expansion, the one-command installer, tests, website, OpenVAPT Academy course, documentation and legal drafts; AI legal review (as a separate AI Cybersecurity Engineer); coordination and review of Codex's work; builds, commits, pushes and deployments. On 2026-10-13: independent AI audits (separate review runs, not human audits) of the release pipeline, scanner, checks and website, and the resulting fixes; the generated source inventory SOURCES.md and `internal/sources`; the Governance, Control and Assurance Framework (GOVERNANCE-CONTROL-ASSURANCE.md). |
| OpenAI Codex (GPT-5.6, Codex CLI 0.162.1) | AI system | Independent read-only code review (17 findings, 15 improvement proposals, 2026-10-13); implementation of those fixes and improvements on branch `codex/review-fixes`; 18 network, data-service and TLS checks plus the professional report redesign (executive summary, heat map, CIS Controls and NIST CSF coverage, remediation plan) on branch `codex/coverage-network`. All reviewed by Claude before merging. |
| OpenAI Codex (GPT-6, Codex CLI 0.162.1) | AI system | Offline vulnerability matching engine on branch `codex/vulndb` (HOST-CVE-001 to 003, WEB-CVE-001, Debian and RPM version comparison, inventory collectors, release-time generator), reviewed and corrected by Claude before merging. |
| Claude (Claude Fable 5.1, Anthropic), through Claude Code | AI system | Led the 2026-10-14 full review and build round: six audit runs and a roadmap; eight build streams (142 new checks, 10 Academy modules, Wave 1 false-positive and honesty fixes, pipeline hardening, website polish, legal bundle EULA 2.4, Licence 1.3, acknowledgements 1.7, AGENTS.md 1.4, GCA 1.1); four fresh-context verifier runs and the fixes they required. Also the AI legal reviewer for that bundle. |

## How Contributions Are Marked in Git

Every commit is authored as "OpenVAPT" and carries a `Co-Authored-By` line for each AI system that contributed to it:

- `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
- `Co-Authored-By: OpenAI Codex (GPT-5.6, Codex CLI) <noreply@openai.com>`
- `Co-Authored-By: OpenAI Codex (GPT-6, Codex CLI) <noreply@openai.com>`
- `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`

The email addresses in these lines are attribution placeholders, not monitored mailboxes.

Known exceptions, recorded rather than rewritten (published history is never rewritten, AGENTS.md 3.3):

- The first commits were authored as "The OpenVAPT Project"; the author name became "OpenVAPT" on 2026-10-13 and has stayed so since.
- The three merge commits that brought OpenAI Codex's branches into main (`2704c98`, `256638b`, `a7ea7ac`) carry no `Signed-off-by` line, contrary to CONTRIBUTING.md. The Codex work itself was reviewed and accepted by Claude; the sign-off was omitted on the merge commits only. Every later commit is signed off, and a trailer check in CI is planned so this cannot recur.
- Release promotion commits are authored as "OpenVAPT Release Agent" by the GitHub Actions bot from `cmd/channel` and carry no model trailer because no model writes them.

## Human Contributors

Contributions from people are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Please say in your pull request if an AI Cybersecurity Engineer or other AI system produced any part, and which one.
