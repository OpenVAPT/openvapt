# Disclaimer

Version 1.5, effective 2026-10-13. This disclaimer was drafted by an AI Cybersecurity Engineer and reviewed by a separate AI system acting as the project's legal reviewer; no human lawyer drafted or reviewed it (see section 12).

**In one sentence:** OpenVAPT is academic, non-commercial, open, source-available code built by AI Cybersecurity Engineers, free to download and use for your own personal or business use, which you may not sell or use to provide any service, and which you use 100% at your own risk.

## 1. Academic, Non-Commercial Project

OpenVAPT is an academic, non-commercial project made for learning. It shows, in public, how a vulnerability assessment tool can be designed, built and tested. Its code is open for anyone to read, study and review. It is free to download and use for your own personal or business use. It may not be sold, and nothing from or produced by it may be used to provide services to anyone else. The project is not a business and accepts no payments or donations.

## 2. Not a Service, Not Advice, Not Certification

- OpenVAPT is **not** a penetration testing service, a vulnerability assessment service, a managed security service, a cyber security service under any law, an audit, a compliance assessment or a certification.
- The project does not offer, sell or perform any service, and does not give advice to any individual or organisation, privately or publicly. Answers in public GitHub discussions are voluntary, general and not advice.
- Nothing on the website, in the software, in a report or in the documentation is professional, legal, security or compliance advice. Consult a qualified, licensed professional for decisions about your systems.
- No seal, badge, score or certificate is issued, and a report must never be presented as one.

## 3. What OpenVAPT Does and Does Not Do

- It runs automated, read-only checks on **the machine it is installed on only**. In its unmodified form it is designed so that it cannot be pointed at other machines; the scope guard is in `internal/scope`.
- It reads system files (some only readable by root), including service unit files and application configuration files that can contain secrets, for pattern matching only; runs a short allow-list of read-only commands (for example `sshd -T` or `node --version`); and sends ordinary GET requests to the websites your machine serves, through loopback addresses (127.0.0.0/8 and ::1).
- It is designed not to exploit, attack, brute-force, change configuration, install anything, restart services or send data off the machine. Software can contain mistakes, so this is a design goal, not a guarantee.
- Even read-only activity uses CPU, memory, disk and network resources and generates requests that may appear in your own logs or trigger your own security tools. Test it on a non-production system first.

## 4. Results Can Be Wrong or Incomplete

- Automated checks produce **false positives** (reported problems that are not real) and **false negatives** (real problems that are missed).
- **Absence of findings is not proof of security.** Many weaknesses, including application logic flaws, injection flaws, access control errors and business rule errors, require manual testing by qualified people.
- Severity ratings are representative CVSS v3.1 values for a typical internet-facing server; your real risk depends on your environment.
- End-of-life and version tables are dated and become outdated; a release newer than the table may not be recognised.
- Secret redaction is pattern-based and may miss secrets. Review every report before you share it.

- **Pre-release builds.** Builds published on the alpha, beta and release candidate (rc) channels are pre-release. They are unfinished, may be wrong, incomplete or unstable, may change or be withdrawn at any time, and are used 100% at your own risk. Only a build published on the stable channel is a full release, and it too is provided as is, without any warranty.

## 5. Built by AI Cybersecurity Engineers

In full transparency: AI Cybersecurity Engineers are AI systems (Claude by Anthropic, through Claude Code, and OpenAI Codex) acting in a cyber security engineering role. They are not people, not registered or professional engineers, and provide no professional engineering or security service. **All of OpenVAPT was researched, developed and built by AI Cybersecurity Engineers**, including its design, code, tests, documentation, website, course material and these legal drafts. The human project owner directs the work, makes every decision and approves what is published, but has not hand-written the code. Claude (by Anthropic, used through Claude Code) produced the work; OpenAI Codex reviewed the code and proposed and implemented fixes; Claude also reviewed the legal documents as the project's legal reviewer (an AI lawyer). Details are in `AI-DISCLOSURE.md`. **No independent human security expert has audited the code, and no human lawyer has drafted or reviewed these documents.** Work built by AI Cybersecurity Engineers can contain mistakes, including security and legal mistakes, which is one more reason the code is public for review and why you use it at your own risk. Commits made with AI assistance are marked with a `Co-Authored-By` line. Because it was built by AI Cybersecurity Engineers, copyright may not exist in some parts under the laws of some countries.

## 6. Use at Your Own Risk, 100%

You use OpenVAPT **entirely at your own risk**. You alone carry every risk and every consequence of downloading, building, running or relying on it, including damage to systems, data loss, downtime, service disruption, triggering security alerts, security incidents, missed vulnerabilities, regulatory consequences and legal liability. The developers and contributors accept **no responsibility or liability** for any of them, to the fullest extent the law allows.

## 7. No Warranty

The software, website and documentation are provided **"as is"** and "as available", without warranty of any kind, express or implied, including accuracy, completeness, reliability, security, fitness for a particular purpose, merchantability and non-infringement.

## 8. Your Legal Responsibility

You are solely responsible for having the right to run OpenVAPT on a machine, for following your organisation's policies, and for complying with all laws that apply to you, including in Malaysia the Computer Crimes Act 1997, the Cyber Security Act 2024 and the Personal Data Protection Act 2010, and the laws of your own country. Never run it on a machine that you or your employer do not own or control, and never run it on a client's or customer's machine, even with their permission.

## 9. The Operator

OpenVAPT is run by its project owner, who publishes the project and holds its rights under the name OpenVAPT. Contact is through GitHub only.

## 10. Third-Party Names and Links

References to OWASP, NIST, FIRST (CVSS), MITRE (CWE, ATT&CK), CIS, Anthropic, OpenAI, GitHub, Let's Encrypt, vendors and standards bodies, and names of other tools and products such as Linux, Lynis, OpenSCAP, OpenVAS, Nuclei, Trivy, ZAP, Apache Tomcat, Node.js, Django, Flask, WordPress, Joomla and Drupal, are used only to identify them, for citation, comparison and transparency. OpenVAPT is not affiliated with, sponsored or endorsed by any of them, and no endorsement of them is intended. Trademarks belong to their owners. Linked external websites are outside our control. "OpenVAPT" is not a registered trademark, and no report, product or service may be presented as approved, certified or endorsed by OpenVAPT.

## 11. A Free Gift, Not a Business

OpenVAPT is given free of charge, as a gift, by a project that is not a business, does not trade, and accepts no payment or donation. Giving it creates no supplier, advisory, professional or other relationship and no duty of care, support or update. To the fullest extent the law allows, every exclusion in this Disclaimer applies, and any part that goes further than the law allows is read down, not removed. This Disclaimer forms part of the EULA, which is governed by the laws of Malaysia.

## 12. How These Documents Were Reviewed

These documents were drafted by an AI Cybersecurity Engineer in good faith and reviewed by a separate AI system acting as the project's legal reviewer (an AI lawyer). No human lawyer drafted or reviewed them, and they are not approved by any human lawyer. They are not legal advice to you; if you need legal advice, consult your own qualified lawyer. Their wording may change; every version is dated and kept in the public Git history.
