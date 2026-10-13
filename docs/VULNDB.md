# Offline Vulnerability Snapshot

The embedded snapshot is a small, hand-written test fixture. Its advisory ranges are illustrative and do not represent a complete security feed. Every scan prints the snapshot date, fixture status and a reminder that outdated data misses newer vulnerabilities.

The release pipeline can run cmd/vulndbgen with -out, -ecosystems and -packages. Runtime scans use only the embedded gzip file and never access the network. The generator reads OSV ecosystem export ZIPs and the CISA KEV JSON feed. The default package list is in vulndb-packages.txt.

Sources and licence metadata: OSV ecosystem exports at https://osv-vulnerabilities.storage.googleapis.com/ - check source. CISA KEV at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json - check source. These labels avoid assuming a licence not stated by the fetched records.

Matching uses exact binary package names. OSV advisories that name only a source package may be missed. Web discovery is bounded to configured document roots and recognizes composer.lock, package-lock.json versions 1 through 3, wp-includes/version.php, and a best-effort jQuery header. Missing lockfiles or truncated reads make coverage incomplete.

## Severity and KEV Rules in the Generator

- KEV status is set when the record's ID, any alias or any `upstream` identifier is in the CISA KEV feed. Debian records (DEBIAN-CVE-*) name their CVE only in `upstream`.
- Severity uses the first valid CVSS v3 vector. Without one, a CVSS v4.0 vector is rated conservatively without the official macrovector table, rounding up so nothing is under-rated: critical when the attack is network, low complexity, no attack requirements, no privileges, no user interaction and the vulnerable system impact is High; high when any vulnerable or subsequent system impact is High; otherwise left out. An unparsable v4 vector is rated high so it is kept. Only CVSS v3 fills the score and vector fields.
- Without any CVSS vector, an Ubuntu priority of critical or high is used as the severity; medium, low and negligible are left out.

## Generator Limits

Downloads are HTTPS only, including redirects, streamed to temporary files with a 1 GiB cap per file (checked against Content-Length first, then while copying), with a 15 minute timeout. Ecosystems are processed one at a time and only one export is kept on disk. A record over 4 MiB, more than 2,000,000 records or more than 8 GiB of uncompressed records in one export is an error. Parse failures are counted and reported per ecosystem, and more than 1% fails the build.
