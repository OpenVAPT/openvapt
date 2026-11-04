# ADR 0001: Scan Only the Local Machine

Status: Accepted (2026-10-13)

## Context
Scanning remote hosts is useful for teaching networking, but turns the tool into something that can be aimed at systems the user does not own, which is unlawful without authorisation in most countries (for example the Computer Fraud and Abuse Act in the United States, the Computer Misuse Act 1990 in the United Kingdom, or the Computer Crimes Act 1997 s.3 in Malaysia).

## Decision
Every network connection goes through `scope.Dialer`, which accepts only literal loopback addresses. There is no option to disable it. Network exposure is assessed from inside the machine (kernel socket tables, firewall rules, loopback TLS handshakes).

## Consequences
The tool cannot observe what a remote attacker sees through upstream firewalls or NAT; the report states this limitation. DNS-based checks are not implemented.
