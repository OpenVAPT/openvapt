# AI Disclosure

**OpenVAPT is entirely AI-generated.** This file states, as precisely and honestly as we can, who and what produced it.

## Summary

| Question | Answer |
|---|---|
| Who wrote the code? | AI systems. No human hand-wrote the code. |
| Who wrote the documentation, website, course and legal drafts? | AI systems. |
| What did the human owner do? | Set the goals and rules, made every product and policy decision, answered the AI's questions, approved what was built, published and deployed, and owns and runs the project. |
| Has a human security expert audited the code? | No. |
| Has a human lawyer reviewed the legal documents? | No, not yet. An AI system reviewed them in the role of a legal reviewer. A licensed Malaysian advocate and solicitor review is planned before the public launch. |
| How can I see which commits were AI-generated? | All of them are. Each commit made by an AI system carries a `Co-Authored-By` line naming it. |

## AI Systems Used

| System | Provider | Interface and version | Role |
|---|---|---|---|
| Claude Opus 5.5 (model id `claude-opus-5-5`) | Anthropic | Claude Code (desktop app), October 2026 | Planned, designed, architected, wrote and tested all code; wrote the website, course (Academy), documentation and legal drafts; built, committed, pushed and deployed; coordinated the other AI systems; verified their output. |
| Claude (same model, as a separate sub-agent) | Anthropic | Claude Code sub-agent | Reviewed and audited all legal documents in the role of a technology lawyer focused on Malaysian law; produced findings and replacement clauses that were then applied. This is an AI review, not legal advice. |
| GPT-5.6 (model id `gpt-5.6-sol`) | OpenAI | Codex CLI 0.162.1 | Performed an independent read-only code review (17 findings, 15 improvement proposals), then implemented fixes and improvements on a separate branch, which Claude reviewed before merging. |

The OpenAI Codex CLI is also configured on the owner's computer for image generation, but no AI-generated images are used in OpenVAPT. The logo (`site/static/assets/icon.svg`) is a small SVG written by Claude.

## What This Means for You

- AI-generated code and text can contain mistakes, including security mistakes, false statements and legal errors. Treat everything in OpenVAPT as unverified until you have checked it yourself.
- The code is public so that anyone can review it. Independent human review is very welcome (see SECURITY.md and CONTRIBUTING.md).
- Copyright may not exist in some AI-generated parts under the laws of some countries. The licence applies to the extent rights exist; the EULA's promises apply to the whole Software.
- You use OpenVAPT 100% at your own risk, as stated in the EULA and Disclaimer.

## How the Work Was Checked

- Every check is tested against a simulated vulnerable server (it must fail) and a simulated hardened server (it must pass).
- Continuous integration runs formatting, `go vet`, unit and lab tests with the race detector, staticcheck, gosec, govulncheck, Linux builds, the website build, and checks that the website collects no data and publishes no email address.
- Every factual statement about the server (logging off, DNS query logging off, hosting provider, certificate issuer) was checked on the live server by Claude on 2026-10-13 before being written into the Privacy Policy.
- These checks reduce, but do not remove, the risk of mistakes.

## Contributions

Human or AI contributions are welcome under CONTRIBUTING.md. If you use an AI system to produce a contribution, say so in the pull request and name it.
