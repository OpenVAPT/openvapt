# Offline Vulnerability Snapshot

The embedded snapshot is a small, hand-written test fixture. Its advisory ranges are illustrative and do not represent a complete security feed. Every scan prints the snapshot date, fixture status and a reminder that outdated data misses newer vulnerabilities.

The release pipeline can run cmd/vulndbgen with -out, -ecosystems and -packages. Runtime scans use only the embedded gzip file and never access the network. The generator reads OSV ecosystem export ZIPs and the CISA KEV JSON feed. The default package list is in vulndb-packages.txt.

Sources and licence metadata: OSV ecosystem exports at https://osv-vulnerabilities.storage.googleapis.com/ - check source. CISA KEV at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json - check source. These labels avoid assuming a licence not stated by the fetched records.

Matching uses exact binary package names. OSV advisories that name only a source package may be missed. Web discovery is bounded to configured document roots and recognizes composer.lock, package-lock.json versions 1 through 3, wp-includes/version.php, and a best-effort jQuery header. Missing lockfiles or truncated reads make coverage incomplete.
