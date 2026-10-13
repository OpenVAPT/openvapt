# Disclaimer

Version 1.1, effective 2026-10-13. This disclaimer is a draft pending review by a Malaysian advocate and solicitor.

**In one sentence:** OpenVAPT is academic, non-commercial, open-source code, free to download and use for your own personal or business use, which you may not sell or use to provide services, and which you use 100% at your own risk.

## 1. Academic, Non-Commercial Project

OpenVAPT is an academic, non-commercial project made for learning. It shows, in public, how a vulnerability assessment tool can be designed, built and tested. Its code is open for anyone to read, study and review. It is free to download and use for your own personal or business use. It may not be sold or used to provide services to anyone else.

## 2. Not a Service, Not Advice, Not Certification

- OpenVAPT is **not** a penetration testing service, a vulnerability assessment service, a managed security service, a cyber security service under any law, an audit, a compliance assessment or a certification.
- The project does not offer, sell or perform any service, and does not give advice to any individual or organisation, privately or publicly. Answers in public GitHub discussions are voluntary, general and not advice.
- Nothing on the website, in the software, in a report or in the documentation is professional, legal, security or compliance advice. Consult a qualified, licensed professional for decisions about your systems.
- No seal, badge, score or certificate is issued, and a report must never be presented as one.

## 3. What OpenVAPT Does and Does Not Do

- It runs automated, read-only checks on **the machine it is installed on only**. It cannot be pointed at other machines.
- It reads system files (some only readable by root), runs a short list of read-only commands, and sends ordinary GET requests to the websites your machine serves, through 127.0.0.1.
- It does not exploit, attack, brute-force, change configuration, install anything, restart services or send data off the machine.
- Even read-only activity uses CPU, memory, disk and network resources and generates requests that may appear in your own logs or trigger your own security tools. Test it on a non-production system first.

## 4. Results Can Be Wrong or Incomplete

- Automated checks produce **false positives** (reported problems that are not real) and **false negatives** (real problems that are missed).
- **Absence of findings is not proof of security.** Many weaknesses, including application logic flaws, injection flaws, access control errors and business rule errors, require manual testing by qualified people.
- Severity ratings are representative CVSS v3.1 values for a typical internet-facing server; your real risk depends on your environment.
- End-of-life and version tables are dated and become outdated; a release newer than the table may not be recognised.
- Secret redaction is pattern-based and may miss secrets. Review every report before you share it.

## 5. How OpenVAPT Is Made (AI-Assisted Development)

In the interest of full transparency: OpenVAPT is developed by the project owner with substantial help from **AI coding assistants**. To date, the design, code, tests, documentation, website and these legal drafts were produced by **Claude** (by Anthropic, used through Claude Code) under the direction and review of the project owner, who makes every decision. AI-generated work can contain mistakes, including security mistakes, which is one more reason the code is public for review and why you use it at your own risk. Commits made with AI assistance are marked with a `Co-Authored-By` line in the Git history.

## 6. Use at Your Own Risk, 100%

You use OpenVAPT **entirely at your own risk**. You alone carry every risk and every consequence of downloading, building, running or relying on it, including damage to systems, data loss, downtime, service disruption, triggering security alerts, security incidents, missed vulnerabilities, regulatory consequences and legal liability. The developers and contributors accept **no responsibility or liability** for any of them, to the fullest extent the law allows.

## 7. No Warranty

The software, website and documentation are provided **"as is"** and "as available", without warranty of any kind, express or implied, including accuracy, completeness, reliability, security, fitness for a particular purpose, merchantability and non-infringement.

## 8. Your Legal Responsibility

You are solely responsible for having the right to run OpenVAPT on a machine, for following your organisation's policies, and for complying with all laws that apply to you, including in Malaysia the Computer Crimes Act 1997, the Cyber Security Act 2024 and the Personal Data Protection Act 2010, and the laws of your own country. Never run it on a machine you do not own or control without the owner's permission.

## 9. Anonymous Operator

The person who runs the project currently chooses not to be named publicly. This does not change any statement in this disclaimer or in the EULA. Contact is through GitHub only.

## 10. Third-Party Names and Links

References to OWASP, NIST, FIRST (CVSS), MITRE (CWE, ATT&CK), CIS, Anthropic, GitHub, Let's Encrypt, vendors and standards bodies are for citation and transparency only and do not imply endorsement by or of them. Trademarks belong to their owners. Linked external websites are outside our control.

## 11. Legal Review Status

These documents are drafts written in good faith and are awaiting review by a Malaysian advocate and solicitor before the public launch at openvapt.com. Their wording may change; every version is dated and kept in the public Git history.
