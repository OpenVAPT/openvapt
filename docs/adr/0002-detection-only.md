# ADR 0002: Detection Only, No Exploitation

Status: Accepted (2026-10-13)

## Decision
OpenVAPT implements the Planning, Discovery and Reporting phases of the four-phase NIST SP 800-115 methodology (Planning, Discovery, Attack, Reporting) and omits the Attack phase; analysis of findings happens within Discovery. No exploit code, payloads, brute force or denial-of-service techniques are included.

## Consequences
Safe to run on production; lower dual-use and export-control concern; cannot demonstrate real impact the way a penetration test can, which every report says.
