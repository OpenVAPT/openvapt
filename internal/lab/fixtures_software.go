package lab

import "github.com/openvapt/openvapt/internal/sys"

// Fixtures added by the software stream (2026-10-14): archives and
// certificates inside the web root (WEB-DOC-003), and the Debian default
// status.conf that limits /server-status to local clients on the hardened
// server (WEB-EXP-006 nuance).
func init() {
	Register(func(f *sys.Fake) {
		// A site tarball and a certificate dropped in the web root after a
		// migration; a public download archive is expected and not flagged.
		for _, p := range []string{"/var/www/shop/shop-2026.tar.gz", "/var/www/shop/cert.pem", "/var/www/shop/downloads/catalogue.tar.gz"} {
			f.Infos[p] = sys.FileInfo{Path: p, Mode: 0o644}
		}
	}, func(f *sys.Fake) {
		f.Files["/etc/apache2/mods-enabled/status.conf"] = "<IfModule mod_status.c>\n  <Location /server-status>\n    SetHandler server-status\n    Require local\n  </Location>\n</IfModule>\n"
		f.Infos["/var/www/shop/downloads/catalogue.tar.gz"] = sys.FileInfo{Path: "/var/www/shop/downloads/catalogue.tar.gz", Mode: 0o644}
	})
}
