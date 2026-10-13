# AI Disclosure

**OpenVAPT is researched, developed and built entirely by AI Cybersecurity Engineers under human direction.** This file states, as precisely and honestly as we can, who and what produced it.

## What "AI Cybersecurity Engineer" Means

AI Cybersecurity Engineers are AI systems (Claude by Anthropic, through Claude Code, and OpenAI Codex) acting in a cyber security engineering role. They are not people, not registered or professional engineers, and provide no professional engineering or security service. The name describes the role the AI systems play in this project. It is not a job title, qualification, licence or registration, and no human engineer, registered engineer or professional service was involved in building OpenVAPT.

## Summary

| Question | Answer |
|---|---|
| Who wrote the code? | AI systems. No human hand-wrote the code. |
| Who wrote the documentation, website, course and legal drafts? | AI systems. |
| What did the human owner do? | Set the goals and rules, made every product and policy decision, answered the AI's questions, approved what was built, published and deployed, and owns and runs the project. |
| Has a human security expert audited the code? | No. |
| Has a human lawyer drafted or reviewed the legal documents? | No. The legal documents were drafted by an AI Cybersecurity Engineer and reviewed by a separate AI system acting as the project's legal reviewer (an AI lawyer). No human lawyer drafted or reviewed them, and they are not lawyer-approved. If you need legal advice, get your own. |
| How can I see which commits were made by AI Cybersecurity Engineers? | All of them are. Each commit made by an AI system carries a `Co-Authored-By` line naming it. Release promotion commits are made by the GitHub Actions bot from `cmd/channel` and carry no model trailer. |

## AI Systems Used

| System | Provider | Interface and Version | Role |
|---|---|---|---|
| Claude Opus 5.5 (model id `claude-opus-5-5`) | Anthropic | Claude Code (desktop app), October 2026 | Planned, designed and architected the system; wrote and tested most of the code (Codex wrote the parts listed in its row); wrote the website, course (Academy), documentation and legal drafts; built, committed, pushed and deployed; coordinated the other AI systems; verified their output. On 2026-10-13 it also ran independent AI audits (separate review runs, not human audits) of the release pipeline, the scanner, the checks and the website and fixed what they found; generated the source inventory SOURCES.md (from `internal/sources`); and drafted the Governance, Control and Assurance Framework adopted by the owner. |
| Claude (same model, as a separate AI system) | Anthropic | Claude Code sub-agent | Acts as the project's legal reviewer (an AI lawyer focused on Malaysian technology law and source-available licensing): reviewed, audited and rewrote the legal documents; produced findings and replacement clauses that were then applied. This is an AI review, not legal advice. |
| GPT-5.6 (model id `gpt-5.6-sol`) | OpenAI | Codex CLI 0.162.1 | Performed an independent read-only code review (17 findings, 15 improvement proposals) and implemented the fixes; later built 18 network, data-service and TLS checks and the professional report redesign to Claude's specification. Each piece of work was done on a separate branch and reviewed by Claude before merging. |
| GPT-6 (model id `gpt-6-sol`) | OpenAI | Codex CLI 0.162.1 | Built the offline vulnerability matching engine (version comparison, inventory, matching, generator, four checks) to Claude's specification, on a separate branch. Claude reviewed it and corrected a factual error in the test data before merging. |
| Claude Fable 5.1 (model id `claude-fable-5-1`) | Anthropic | Claude Code sub-agent, October 2026 | Acted as the project's AI legal reviewer and governance editor on 2026-10-14: applied the owner-approved legal bundle (EULA 2.4, Licence 1.3, acknowledgements 1.7, AGENTS.md 1.4, GCA 1.1, Disclaimer 1.7), the risk register and decision records, and the self-describing legal review record. A second Fable 5.1 run in a fresh context verified the bundle on 2026-10-14 (docs/audit/review-2026-10-14/13-verify-legal.md) under AGENTS.md 6.2. An AI review, not legal advice. |

The OpenAI Codex CLI is also configured on the owner's computer for image generation, but no AI-made images are used in OpenVAPT. The logo (`site/static/assets/icon.svg`) is a small SVG written by Claude.

## What This Means for You

- Code and text built by AI Cybersecurity Engineers can contain mistakes, including security mistakes, false statements and legal errors. Treat everything in OpenVAPT as unverified until you have checked it yourself.
- The code is public so that anyone can review it. Independent human review is very welcome (see SECURITY.md and CONTRIBUTING.md).
- Copyright may not exist in some parts built by AI Cybersecurity Engineers under the laws of some countries. The licence applies to the extent rights exist; the EULA's promises apply to the whole Software.
- You use OpenVAPT 100% at your own risk, as stated in the EULA and Disclaimer.

## How the Work Was Checked

- Every check is tested against a simulated vulnerable server (it must fail) and a simulated hardened server (it must pass).
- Continuous integration runs formatting, `go vet`, unit and lab tests with the race detector, staticcheck, gosec, govulncheck, Linux builds, the website build, and checks that the website collects no data and publishes no email address.
- Every factual statement about the server (logging off, DNS query logging off, hosting provider, certificate issuer) was checked on the live server by Claude on 2026-10-13 before being written into the Privacy Policy.
- These checks reduce, but do not remove, the risk of mistakes.

## How OpenVAPT Is Governed, Controlled and Assured

OpenVAPT follows a written framework, GOVERNANCE-CONTROL-ASSURANCE.md in the source repository, which is part of the rules in AGENTS.md. In plain English:

- **Governance (who decides).** One human owner makes every product and policy decision and approves every sensitive change in chat. Everyone else in the process is an AI system. A separate AI system acting as the legal reviewer decides what may be said in public and in the legal documents.
- **Control (what is allowed).** Changes are sorted into risk tiers. Higher tiers need more checks before they are merged or released. Some controls are built into the code and the automated tests; others are written rules. The framework marks each control as existing, partial or planned, so nothing is claimed that is not yet built.
- **Assurance (how it is checked).** Work is checked by a separate AI review run that starts fresh, without the author's reasoning. For sensitive changes, Claude and OpenAI Codex check each other's work where Codex is available; when it is not, the record says so. A finding is closed only on evidence such as a test result or a cited source.
- **What this is not.** All of this is AI review plus one human owner. It is AI-reviewed, not human-reviewed: no human security expert or human lawyer has reviewed OpenVAPT, and no external or human assessment has been made against any standard. Independent human review is welcome.

## Contributions

Human or AI contributions are welcome under CONTRIBUTING.md. If you use an AI system to produce a contribution, say so in the pull request and name it.
