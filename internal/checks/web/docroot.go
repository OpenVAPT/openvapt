package web

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Sensitive file name patterns that should never sit inside a web root.
var sensitiveNames = []struct{ pattern, why string }{
	{".env", "environment secrets"}, {".env.*", "environment secrets"}, {"*.sql", "database dump"}, {"*.sql.gz", "database dump"},
	{"*.bak", "backup copy"}, {"*.old", "backup copy"}, {"*.orig", "backup copy"}, {"*~", "editor backup"},
	{"*.swp", "editor swap file"}, {"backup*.zip", "backup archive"}, {"backup*.tar.gz", "backup archive"}, {"backup*.tgz", "backup archive"},
	{"*dump*.tar.gz", "database dump archive"}, {"*dump*.tgz", "database dump archive"}, {"*dump*.zip", "database dump archive"},
	{"id_rsa", "SSH private key"}, {"id_ed25519", "SSH private key"}, {"id_ecdsa", "SSH private key"},
	{"*key*.pem", "private key"}, {"*priv*.pem", "private key"}, {"*.key", "private key"}, {"*.p12", "key store"}, {"*.pfx", "key store"}, {"wp-config.php.*", "WordPress config copy"},
}

// reviewNames are files that are often legitimate inside a web root (a
// published certificate chain, a downloadable release archive) but deserve a
// look, because the same names also carry private keys and site backups.
// They are rated Medium by WEB-DOC-003, not High by WEB-DOC-001 (C-09).
var reviewNames = []struct{ pattern, why string }{
	{"*.pem", "certificate or key material; confirm it holds no private key"}, {"*.crt", "certificate; confirm the key is not beside it"},
	{"*.tar.gz", "archive; confirm it is a published download, not a site backup"}, {"*.tgz", "archive; confirm it is a published download, not a site backup"},
	{"*.tar", "archive; confirm it is a published download, not a site backup"}, {"*.7z", "archive; confirm it is a published download, not a site backup"},
}

// downloadFolder reports a path under a folder whose purpose is publishing
// files, where archives are expected.
func downloadFolder(path string) bool {
	l := strings.ToLower(path)
	for _, d := range []string{"/download/", "/downloads/", "/releases/", "/dist/", "/.well-known/"} {
		if strings.Contains(l, d) {
			return true
		}
	}
	return false
}

func review(name string) (string, bool) {
	if _, hi := sensitive(name); hi {
		return "", false
	}
	for _, s := range reviewNames {
		if ok, _ := filepath.Match(s.pattern, name); ok {
			return s.why, true
		}
	}
	return "", false
}

func sensitive(name string) (string, bool) {
	for _, s := range sensitiveNames {
		if ok, _ := filepath.Match(s.pattern, name); ok {
			return s.why, true
		}
	}
	return "", false
}

func init() {
	check.Register(&check.Check{
		ID: "WEB-DOC-001", Title: "Secrets or Backups Stored Inside a Web Root", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Summary:   "Looks on disk inside each web document root for environment files, database dumps, backups, archives and private keys.",
		Rationale: "Anything inside a document root may be downloadable, now or after a configuration change. Dumps, backups and keys there are a leading cause of data breaches; finding them on disk catches files the URL checks cannot guess.",
		Detection: "Reads document roots from the local Apache, nginx and LiteSpeed configuration, walks each one (metadata only, up to 50000 files, symlinks not followed) and matches file names such as .env, *.sql, *.bak, backup*.tar.gz, id_rsa, *key*.pem and *.key. File contents are never read. Plain archives and certificates (*.tar.gz, *.pem) are reviewed separately at Medium by WEB-DOC-003, because they are often published on purpose.",
		Fix:       "Move each listed file outside the document root (for example to a 700 folder in the account's home), delete what is not needed, and rotate any secret or key that was exposed. Keep backups in a dedicated location outside every web root.",
		Verify:    "Re-run this check; no files should be listed.",
		Refs:      []check.Ref{refWSTGConf04, {Title: "OWASP Secrets Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}},
		Standards: check.Standards{CWE: []string{"CWE-530", "CWE-538", "CWE-312"}, OWASP: []string{"A05:2021"}, ASVS: []string{"12.5.1"}, WSTG: []string{"WSTG-CONF-04"}, NIST: []string{"SC-28", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			roots := collect.DocRoots(ctx, s)
			if len(roots) == 0 {
				return []check.Result{check.SkipR("web roots", "No document roots found in the local web server configuration")}
			}
			var out []check.Result
			for _, root := range roots {
				w, err := s.Walk(ctx, root, 50000)
				if err != nil && len(w.Files) == 0 {
					continue
				}
				var hits []string
				for _, f := range w.Files {
					if why, ok := sensitive(filepath.Base(f.Path)); ok {
						hits = append(hits, f.Path+" ("+why+")")
					}
				}
				switch {
				case len(hits) > 0:
					if len(hits) > 30 {
						hits = append(hits[:30], fmt.Sprintf("... and %d more", len(hits)-30))
					}
					out = append(out, check.FailR(root, fmt.Sprintf("%d sensitive file(s) inside the web root", len(hits)), hits...))
				case !w.Complete:
					out = append(out, check.IncompleteR(root, "Web root could not be fully walked"))
				default:
					out = append(out, check.PassR(root, fmt.Sprintf("No sensitive files among %d checked", len(w.Files))))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("web roots", "Document roots could not be read")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "WEB-DOC-003", Title: "Archives or Certificates Inside a Web Root", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Lists archives (*.tar.gz, *.tgz, *.tar, *.7z) and certificate files (*.pem, *.crt) inside each web document root for review, outside download folders.",
		Rationale: "A tarball inside a web root is often a site or database backup left after a migration, and a .pem file sometimes carries the private key next to the certificate. Both are downloadable by anyone who guesses the name. But download sites publish archives on purpose and public certificates are harmless, so this is a Medium review item, not a High finding; names that clearly mean backup, dump or key are rated High by WEB-DOC-001.",
		Detection: "Walks each document root (metadata only, up to 50000 files, symlinks not followed) and lists files matching the archive and certificate patterns that WEB-DOC-001 does not already rate High. Files under /download/, /downloads/, /releases/, /dist/ or /.well-known/ are noted as expected publications and do not fail. File contents are never read.",
		Fix:       "Confirm each file is meant to be public. Move backups and anything holding a private key outside the document root, rotate any exposed key, and keep published downloads in a dedicated folder such as /downloads/.",
		Verify:    "Re-run this check; only files you have confirmed as intended downloads should remain, in a download folder.",
		Refs:      []check.Ref{refWSTGConf04, {Title: "OWASP Secrets Management Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}},
		Standards: check.Standards{CWE: []string{"CWE-538", "CWE-552"}, OWASP: []string{"A05:2021"}, ASVS: []string{"12.5.1"}, WSTG: []string{"WSTG-CONF-04"}, NIST: []string{"SC-28", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			roots := collect.DocRoots(ctx, s)
			if len(roots) == 0 {
				return []check.Result{check.SkipR("web roots", "No document roots found in the local web server configuration")}
			}
			var out []check.Result
			for _, root := range roots {
				w, err := s.Walk(ctx, root, 50000)
				if err != nil && len(w.Files) == 0 {
					continue
				}
				var hits, expected []string
				for _, f := range w.Files {
					why, ok := review(filepath.Base(f.Path))
					if !ok {
						continue
					}
					if downloadFolder(f.Path) {
						expected = append(expected, f.Path+" (in a download folder, expected)")
						continue
					}
					hits = append(hits, f.Path+" ("+why+")")
				}
				switch {
				case len(hits) > 0:
					if len(hits) > 30 {
						hits = append(hits[:30], fmt.Sprintf("... and %d more", len(hits)-30))
					}
					out = append(out, check.FailR(root, fmt.Sprintf("%d archive or certificate file(s) inside the web root to review", len(hits)), append(hits, expected...)...))
				case !w.Complete:
					out = append(out, check.IncompleteR(root, "Web root could not be fully walked"))
				default:
					out = append(out, check.PassR(root, fmt.Sprintf("No archives or certificates to review among %d files", len(w.Files)), expected...))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("web roots", "Document roots could not be read")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "WEB-DOC-002", Title: "Web Root Files Writable by Other Users", Domain: check.DomainWeb,
		Severity: check.High, Category: check.CatAccess, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
		Summary:   "Looks for world-writable files inside web document roots.",
		Rationale: "A world-writable PHP or HTML file lets any local user, or any other compromised site on the same server, plant a web shell or inject malware into pages served to visitors.",
		Detection: "Walks each document root (metadata only, up to 50000 files, symlinks not followed) and lists regular files with the 'other write' permission bit.",
		Fix:       "chmod o-w <file> for each listed file (find <docroot> -type f -perm -0002 -exec chmod o-w {} +). Use 644 for files and 755 for folders, owned by the site account, and grant the web server write access only to upload folders.",
		Verify:    "find <docroot> -type f -perm -0002  should print nothing.",
		Refs:      []check.Ref{{Title: "OWASP WSTG-CONF-09, Test File Permission", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission/"}},
		Standards: check.Standards{CWE: []string{"CWE-732"}, OWASP: []string{"A05:2021"}, WSTG: []string{"WSTG-CONF-09"}, NIST: []string{"AC-3", "AC-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			roots := collect.DocRoots(ctx, s)
			if len(roots) == 0 {
				return []check.Result{check.SkipR("web roots", "No document roots found in the local web server configuration")}
			}
			var out []check.Result
			for _, root := range roots {
				w, err := s.Walk(ctx, root, 50000)
				if err != nil && len(w.Files) == 0 {
					continue
				}
				var bad []string
				for _, f := range w.Files {
					if f.Mode.Perm()&0o002 != 0 {
						bad = append(bad, fmt.Sprintf("%04o %s", f.Mode.Perm(), f.Path))
					}
				}
				switch {
				case len(bad) > 0:
					if len(bad) > 30 {
						bad = append(bad[:30], fmt.Sprintf("... and %d more", len(bad)-30))
					}
					out = append(out, check.FailR(root, fmt.Sprintf("%d world-writable file(s) in the web root", len(bad)), bad...))
				case !w.Complete:
					out = append(out, check.IncompleteR(root, "Web root could not be fully walked"))
				default:
					out = append(out, check.PassR(root, "No world-writable files"))
				}
			}
			if len(out) == 0 {
				return []check.Result{check.SkipR("web roots", "Document roots could not be read")}
			}
			return out
		},
	})

	check.Register(&check.Check{
		ID: "WEB-COR-001", Title: "Cross-Origin Resource Sharing Allows Any Origin With Credentials", Domain: check.DomainWeb,
		Severity: check.Medium, Category: check.CatWebApp, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
		Summary:   "Checks the home page's CORS headers for a wildcard origin combined with credentials, or an origin of null.",
		Rationale: "A permissive CORS policy can let any website read responses on behalf of a logged-in visitor, exposing personal data and tokens.",
		Detection: "Reads Access-Control-Allow-Origin and Access-Control-Allow-Credentials on each site's home page. '*' with credentials true, or 'null', fails. Origin reflection needs crafted requests and is outside this read-only check.",
		Fix:       "Return Access-Control-Allow-Origin only for an explicit allow-list of trusted origins, never '*' or 'null' together with credentials, and add Vary: Origin.",
		Verify:    "curl -sI https://<site>/ | grep -i access-control",
		Refs:      []check.Ref{{Title: "OWASP WSTG-CLNT-07, Testing Cross Origin Resource Sharing", URL: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/"}, refMDN("Access-Control-Allow-Origin")},
		Standards: check.Standards{CWE: []string{"CWE-942"}, OWASP: []string{"A05:2021", "A01:2021"}, ASVS: []string{"14.5.3"}, WSTG: []string{"WSTG-CLNT-07"}, NIST: []string{"AC-4", "CM-6"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				o := strings.TrimSpace(st.Home.Header.Get("Access-Control-Allow-Origin"))
				cred := strings.EqualFold(strings.TrimSpace(st.Home.Header.Get("Access-Control-Allow-Credentials")), "true")
				if o == "null" || (o == "*" && cred) {
					return check.FailR(st.Name, "Permissive CORS policy", "Access-Control-Allow-Origin: "+o, fmt.Sprintf("Access-Control-Allow-Credentials: %v", cred))
				}
				return check.PassR(st.Name, "No permissive CORS policy on the home page")
			})
		},
	})

	check.Register(&check.Check{
		ID: "WEB-SEC-001", Title: "No security.txt Contact File", Domain: check.DomainWeb,
		Severity: check.Info, Category: check.CatWebApp, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		Summary:   "Checks whether each site publishes /.well-known/security.txt (RFC 9116).",
		Rationale: "security.txt tells researchers how to report a vulnerability. Without it, reports may go unheard or be disclosed publicly instead.",
		Detection: "Requests /.well-known/security.txt and looks for a Contact: field. This is informational and does not affect the risk summary.",
		Fix:       "Publish /.well-known/security.txt with at least Contact: and Expires: fields (see securitytxt.org).",
		Verify:    "curl -s https://<site>/.well-known/security.txt",
		Refs:      []check.Ref{{Title: "RFC 9116, A File Format to Aid in Security Vulnerability Disclosure", URL: "https://www.rfc-editor.org/rfc/rfc9116.html"}},
		Standards: check.Standards{CWE: []string{"CWE-1188"}, NIST: []string{"RA-5(11)"}},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			return ForEachSite(ctx, s, func(st Site) check.Result {
				r, err := st.Get(ctx, s, "/.well-known/security.txt")
				if err == nil && r.Status == 200 && strings.Contains(strings.ToLower(r.Body), "contact:") {
					return check.PassR(st.Name, "security.txt is published")
				}
				return check.FailR(st.Name, "No /.well-known/security.txt with a Contact field")
			})
		},
	})
}
