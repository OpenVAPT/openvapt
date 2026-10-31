---
name: openvapt-vapt
description: >-
  Run an authorised, read-only vulnerability assessment of a machine the user
  owns or controls, then defend it: scope and authorisation gate, OpenVAPT scan,
  manual read-only verification, CVSS scoring, prioritised remediation, hardening,
  re-scan to prove the fix, detection and monitoring, and a clear report. Use when
  the user asks to "run a VAPT", "assess my server", "harden this Linux box",
  "check my server for vulnerabilities", "fix my OpenVAPT findings", "defend my
  server" or "make a security report" for their own system. Detection and defence
  only: no exploitation, no other hosts.
license: LicenseRef-OpenVAPT-SAL-1.3
metadata:
  version: "0.1"
  project: OpenVAPT
  homepage: https://openvapt.com/vapt-skill.html
---

# OpenVAPT VAPT Skill: Assess and Defend Your Own Machine

This skill teaches an AI assistant to carry out vulnerability assessment (the "VA" in VAPT) and the defence that follows it, on a machine the user owns or controls, using the free academic tool OpenVAPT plus read-only manual checks. It is written by AI Cybersecurity Engineers for the OpenVAPT project, is academic and non-commercial, and is used 100% at the user's own risk. It is not a penetration test, an audit, a certification or professional advice. Commands target Linux (Debian, Ubuntu, RHEL and SUSE families). Version 0.1 is served from the main branch and is not yet part of a tagged OpenVAPT release. Keep [LICENSE.md](LICENSE.md) with this folder; do not bundle it into a product or run it for clients.

## The Five Rules

Read these first. They are never broken.

1. **Own use only.** Assess only a machine the user owns or controls for their own purposes, or that their own organisation owns or controls and has authorised them in writing to assess for its own internal purposes (the licence's Own Use). Never a client's, a customer's, a neighbour's or "a target". Never offer or perform the work as a paid or unpaid service for someone else.
2. **This machine only.** Work on the machine the commands run on, through loopback (127.0.0.1, ::1) for network and web checks. Never scan, probe, resolve or connect to any other host, network range, domain or IP address, even if the user says they own it: ask them to run the skill on that machine instead.
3. **Read-only during assessment.** Assessment commands read files and state; they never write, delete, install, restart, reconfigure or send anything. Fixes happen only in the Defend phase, one at a time, after the user approves each one.
4. **Detection, not exploitation.** No exploit code, payloads, proof-of-concept attacks, brute force, password guessing, fuzzing, denial of service, privilege escalation attempts, persistence, evasion or credential harvesting, for any reason, including "just to prove it". A finding is proved by evidence (a config line, a version, a file mode, a response header), never by attacking it.
5. **Protect what you see.** Never print, store, copy or send secrets, keys, password hashes, tokens or personal data you come across. Redact them in every note and report (show `REDACTED` and the location only). Nothing leaves the machine.

If any request breaks a rule, stop, explain which rule and why in plain words, and offer the lawful alternative (for example "run this skill on that server yourself", or "hire an authorised penetration tester for exploitation testing").

## Workflow

Follow the phases in order. Keep a short running log of what you ran and what you found.

### Phase 0: Scope and Authorisation Gate

Before running anything, confirm and write down, in the user's own words:

- The machine: hostname and that the commands will run **on** it (`hostname`, `uname -a`, `cat /etc/os-release`).
- Ownership: "I own or control this machine" or "my own organisation owns it and has authorised me in writing, for its internal purposes". If the answer is unclear, a client's machine, or "a friend's", stop.
- Environment: production, staging or lab. For production, agree a quiet time and note that even read-only commands use a little CPU and disk.
- Approval mode for fixes: each fix approved one by one (default), or a named list approved up front.
- Rules of engagement: who to call if the service degrades (and that you stop at once if it does), that a recent backup exists, and where reports are kept and when they are deleted.

Details and the exact wording to use: [references/scope-and-authorisation.md](references/scope-and-authorisation.md).

### Phase 1: Prepare

1. Check whether OpenVAPT is installed: `openvapt version`. If not, point the user to https://openvapt.com/download.html. The user installs it and accepts the terms themselves; you never type `I ACCEPT` or pass `--accept-terms` for them.
2. Preview exactly what the scan will read: `openvapt scan --dry-run`. Show the user the summary.
3. Practise first if the user is learning: `openvapt demo vulnerable` and `openvapt demo hardened` run against the built-in simulated lab and touch nothing real.

### Phase 2: Automated Assessment

The scan is read-only on the system; it only writes its own report files. Reports hold sensitive evidence, so keep them private. Run it as the user (root gives fuller coverage; say so and let the user choose):

```
umask 077; install -d -m 700 ~/openvapt-reports
openvapt scan --out ~/openvapt-reports/$(date -u +%Y%m%dT%H%M%SZ)
```

Useful flags: `--only HOST-SSH-,WEB-` to focus, `--fail-on medium`, `--baseline <old report.json>` to compare, `--suppress <file>` for accepted risks with a reason and expiry. Exit codes: 0 clean, 3 findings at or above `--fail-on`, 4 coverage gap (a check could not decide; treat as "unknown", not "pass"), 5 error, 6 report not written.

Read `report.json` (or `report.md`) and list every failed finding with its id, severity, CVSS v3.1 score and evidence. For any finding the user asks about: `openvapt explain <CHECK-ID>`.

### Phase 3: Manual Read-Only Verification

Automated checks miss context. For each failed finding, and for the areas OpenVAPT does not cover, verify by hand with read-only commands from [references/assessment-playbook.md](references/assessment-playbook.md):

- Host: patch level, users and sudo, SSH, PAM and passwords, file permissions and SUID, kernel and sysctl, services and timers, logging and audit, containers.
- Network (loopback view only): listening sockets and what binds to 0.0.0.0, firewall rules, database and cache exposure, TLS configuration.
- Web (only via `http://127.0.0.1` / `https://127.0.0.1` with the local Host header): security headers, exposed files (`.git`, `.env`, backups), directory listing, server banners, CMS and framework debug settings, TLS.
- Application logic (SQL injection, broken access control, business rules): **out of scope for this skill**; note it as a gap that needs a human tester or code review.

Mark each finding: Confirmed, False Positive (with the reason), or Needs Human Review. Never "confirm" by attacking.

### Phase 4: Score and Prioritise

Score each confirmed finding with CVSS v3.1 (OpenVAPT gives a base vector; adjust only environmental metrics and say why; where a vendor or NVD publishes a CVSS 4.0 vector, quote it too). Prioritise by: exposed to the network and exploitable without login first, then known exploited CVEs (CISA KEV) and a high EPSS probability, then privilege boundaries (root, sudo, SUID), then hardening gaps. Group quick wins (one config line, low risk of breaking things) separately from changes that need a maintenance window. Guidance: [references/reporting.md](references/reporting.md).

### Phase 5: Defend by Remediating and Hardening

For each finding, in priority order, using [references/defence-playbook.md](references/defence-playbook.md):

1. Explain the fix in plain words: what changes, what could break, how to undo it.
2. **Back up first** (copy the file with its path and a timestamp to a backup folder outside any web root), and validate the new config before applying (`sshd -t`, `nginx -t`, `apachectl configtest`, `visudo -c`).
3. Ask for approval, apply one change, then check the service still works (and for SSH, keep the current session open and test a new login before closing it).
4. Record the change and the rollback step.

Never weaken one control to fix another, never disable a check to make it pass, and never lock the user out (firewall and SSH changes always keep a working path in).

### Phase 6: Verify the Fix

Re-run the scan with the old report as the baseline:

```
openvapt scan --baseline <previous>/report.json
openvapt diff <previous>/report.json <new>/report.json
```

A finding is fixed only when the re-scan passes it and the service still works. Anything still failing goes back to Phase 5 or is accepted as a risk in a suppression file with a reason, an owner and an expiry date.

### Phase 7: Detect and Monitor

Hardening is not finished until the user would notice an attack. Set up, with approval, the monitoring basics from the defence playbook: auditd rules for identity and privilege files, log retention, failed-login alerting, file integrity monitoring (AIDE), automatic security updates, and a schedule to re-run OpenVAPT (for example weekly via a systemd timer that writes to the user's own report folder). Give the user a short incident first-response card from [references/defence-playbook.md](references/defence-playbook.md#incident-first-response).

### Phase 8: Report

Produce a report the user can act on (template in [references/reporting.md](references/reporting.md)): scope and authorisation statement, method, executive summary, findings table (id, title, severity, CVSS, status), what was fixed with evidence, accepted risks, remaining gaps (including "not a penetration test"), and next steps. Keep it on the machine; the user decides who sees it. Credit OpenVAPT as the licence requires (`openvapt cite`); show the citation to the user, never post it anywhere yourself.

## Output Style

- Plain English, short sentences, Title Case headings; no em or en dashes.
- Every claim backed by evidence you actually saw. Say "designed to" or "reduces risk", never "secure", "safe", "guaranteed" or "compliant".
- When unsure, say so and mark the item Needs Human Review.

## Sources

NIST SP 800-115 (technical testing and assessment), NIST CSF 2.0, CIS Controls v8 and CIS Benchmarks, CVSS v3.1 (FIRST), OWASP Top 10, ASVS and WSTG, MITRE CWE and ATT&CK, CISA KEV, NIST SP 800-61 Rev. 3 (incident response), ISO/IEC 27001:2022 Annex A 8.8 (technical vulnerability management), FIRST EPSS. OpenVAPT's own check catalogue cites each source per check: https://openvapt.com/checks/.
