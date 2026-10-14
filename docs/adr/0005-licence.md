# ADR 0005: Source-Available Licence Limited to Own Use

Status: Accepted (2026-10-13). Current version: 1.3 (2026-10-14); see the amendments below and LICENSE section 15. Supersedes the earlier decision to use PolyForm Noncommercial 1.0.0 with an OpenVAPT Additional Permission.

## Decision
The OpenVAPT Source-Available Licence 1.0 (`LicenseRef-OpenVAPT-SAL-1.0`), a self-contained licence whose only grants are reading and study, Own Use, modification for Own Use or contribution, and free sharing of complete copies. Providing any service, paid or unpaid, selling and other commercial activity are not licensed for anyone. The EULA and Acceptable Use Policy are conditions of the licence.

Amendment (2026-10-13): version 1.1 (`LicenseRef-OpenVAPT-SAL-1.1`) adds the Teaching With OpenVAPT terms. Version 1.0 remains the licence of release v0.1.0-alpha.1. See LICENSE section 15.

Amendment (2026-10-13): version 1.2 (`LicenseRef-OpenVAPT-SAL-1.2`) adds the definitions of OpenVAPT Material and Credit and a reasonable-manner Credit condition (section 5.4) for copying, quoting, sharing, adapting or presenting OpenVAPT Material; citation for ideas, facts and Own Use is requested, not required. Canonical citations are in CITING.md.

Amendment (2026-10-14): version 1.3 (`LicenseRef-OpenVAPT-SAL-1.3`) adds DISCLAIMER.md to the documents that travel with shared copies (section 3.4) and section 10(d), by which contributors authorise the licensor to accept the EULA's contributor protections on their behalf. Section 15 now names the commit that introduced each version. Approved by the owner in chat on 2026-10-14.

## Reason
PolyForm Noncommercial on its own permits unpaid noncommercial services by people who never accepted the EULA. Placing the services ban in the licence itself closes that gap. The change was made before any release, when all code had been built by AI Cybersecurity Engineers for the owner, so relicensing cost nothing.

## Consequences
The code is fully public but the project is described as source-available rather than OSI open source. Contributors grant the licensor a licence to relicense, so the project can later move to a company limited by guarantee. Permissive dependencies remain compatible.
