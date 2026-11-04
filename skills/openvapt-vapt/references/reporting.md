# Scoring, Prioritising and Reporting

## Scoring With CVSS

OpenVAPT gives each check a base vector. Keep the base score; adjust only the environmental metrics (Confidentiality, Integrity and Availability Requirements, and Modified Attack Vector when, for example, a service is reachable only on loopback) and write one line on why. Severity bands: 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical. Calculator: https://www.first.org/cvss/calculator/3.1. CVSS 4.0 (FIRST, 2023) is now published by NVD and many vendors; when a 4.0 vector exists for a CVE, quote it next to the 3.1 score rather than replacing it. EPSS (FIRST) gives the probability that a CVE is exploited in the next 30 days; use it with the CISA KEV catalogue to rank CVEs.

## Remediation Deadlines

ISO/IEC 27001:2022 Annex A 8.8 expects timely remediation. Suggest, and let the user set: Critical within 7 days, High within 30 days, Medium within 90 days, Low at the next maintenance window. Anything in CISA KEV is treated as Critical. Record the agreed date with each finding.

## Priority Order

1. Reachable from the network without login (exposed database, admin panel, debug mode, `.git` or `.env` served).
2. Known exploited vulnerabilities (in the CISA KEV catalogue, or a high EPSS score) and end-of-life software.
3. Privilege boundaries: extra root accounts, broad sudo, SUID, docker group, root containers.
4. Authentication strength: SSH passwords, no lockout, weak password policy.
5. Hardening and defence in depth: sysctl, headers, banners, permissions.
6. Detection gaps: logging, audit, monitoring.

Within each band, put quick wins (one line, low break risk) first.

## Finding Record

```
ID:          <OpenVAPT check id, or MANUAL-<area>-<n>>
Title:       <Title Case>
Status:      Confirmed | False Positive | Needs Human Review | Fixed | Accepted Risk
Severity:    <band> (CVSS 3.1 <score>, <vector>)
Evidence:    <file:line or command and the relevant output, secrets REDACTED>
Impact:      <one or two plain sentences>
Fix:         <the change>
Rollback:    <how to undo>
Due:         <agreed remediation date>
Verified:    <re-scan result, date>
References:  <CWE, CIS, OWASP, vendor advisory>
```

## Report Template

```
# Vulnerability Assessment and Hardening Report: <hostname>

## Scope and Authorisation
<scope record from Phase 0>

## Method
OpenVAPT <version> automated read-only scan, manual read-only verification (playbook areas covered),
CVSS v3.1 scoring. Based on NIST SP 800-115 assessment techniques. Not a penetration test.

## Executive Summary
<3 to 5 sentences: overall state, the most important risks, what was fixed, what remains>

## Findings
| ID | Title | Severity | CVSS | Status |
|----|-------|----------|------|--------|

## Fixed in This Engagement
<each fix with evidence from the re-scan and the openvapt diff output>

## Accepted Risks
<id, reason, owner, expiry date>

## Gaps and Limitations
Application logic, authentication flows and other hosts were not tested. Automated checks can miss
issues and can be wrong. This report reflects the machine at the time of the scan only.

## Next Steps
<prioritised list with suggested dates; re-assessment schedule>

## Credit
<output of `openvapt cite`>
```

## Wording Rules

Say "reduces the risk of", "designed to", "no finding at the time of the scan". Never say secure, safe, compliant, certified, guaranteed or "passed a penetration test". Keep the report on the machine; the user decides who may read it, because a vulnerability report is sensitive.
