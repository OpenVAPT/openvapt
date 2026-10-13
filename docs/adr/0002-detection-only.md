# ADR 0002: Detection Only, No Exploitation

Status: Accepted (2026-10-13)

## Decision
OpenVAPT implements the planning, discovery, analysis and reporting phases of NIST SP 800-115 and omits the attack phase. No exploit code, payloads, brute force or denial-of-service techniques are included.

## Consequences
Safe to run on production; lower dual-use and export-control concern; cannot demonstrate real impact the way a penetration test can, which every report says.
