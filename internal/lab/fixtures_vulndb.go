package lab

import (
	"encoding/json"
	"time"

	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
	"github.com/openvapt/openvapt/internal/vulndb"
)

// labSnapshot is the advisory data the simulated servers are matched
// against. It is illustrative test data (the ranges are plausible, not
// authoritative) and is carried inside the lab, so the lab behaves the same
// whether the binary embeds the tiny fixture or a generated release
// snapshot. generated sets the snapshot date: an old date makes HOST-CVE-003
// fail on the vulnerable server.
func labSnapshot(generated string) string {
	adv := func(id, cve, sev string, kev bool, eco, pkg, fixed string) vulndb.Advisory {
		return vulndb.Advisory{ID: id, Aliases: []string{cve}, Summary: cve + " (lab test data, illustrative range)", Severity: sev, KEV: kev,
			References: []string{"https://nvd.nist.gov/vuln/detail/" + cve},
			Affected:   []vulndb.Affected{{Ecosystem: eco, Package: pkg, Ranges: []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}
	}
	s := vulndb.Snapshot{Header: vulndb.Header{Schema: 1, Generated: generated, Fixture: false,
		Sources: []vulndb.Source{{Name: "OpenVAPT simulated lab", URL: "https://openvapt.com/learn.html", Licence: "lab test data"}}},
		Advisories: []vulndb.Advisory{
			adv("LAB-CVE-2021-3156", "CVE-2021-3156", "high", true, "Ubuntu:18.04:LTS", "sudo", "1.8.21p2-3ubuntu1.5"),
			adv("LAB-CVE-2021-4034", "CVE-2021-4034", "high", true, "Ubuntu:18.04:LTS", "policykit-1", "0.105-20ubuntu0.18.04.6"),
			adv("LAB-CVE-2020-11022", "CVE-2020-11022", "high", false, "npm", "jquery", "3.5.0"),
			adv("LAB-CVE-2020-11022", "CVE-2020-11022", "high", false, "Packagist", "components/jquery", "3.5.0"),
			adv("LAB-CVE-2019-17671", "CVE-2019-17671", "high", false, "WordPress:Core", "wordpress", "5.2.4"),
		}}
	s.Header.Counts = vulndb.Counts{Advisories: len(s.Advisories), Affected: len(s.Advisories)}
	b, _ := json.Marshal(s)
	return string(b)
}

func init() {
	Register(func(f *sys.Fake) {
		f.Files["/var/lib/dpkg/status"] = "Package: sudo\nStatus: install ok installed\nVersion: 1.8.21p2-3ubuntu1.4\n\nPackage: openssh-server\nStatus: install ok installed\nVersion: 1:7.6p1-4ubuntu0.6\n\nPackage: policykit-1\nStatus: install ok installed\nVersion: 0.105-20ubuntu0.18.04.5\n"
		f.Files["/etc/apache2/sites-enabled/shop.conf"] += "DocumentRoot /var/www/shop\n"
		f.Files["/var/www/shop/package-lock.json"] = "{\"lockfileVersion\":2,\"packages\":{\"node_modules/jquery\":{\"version\":\"3.4.1\"}}}"
		f.Infos["/var/www/shop/package-lock.json"] = sys.FileInfo{Path: "/var/www/shop/package-lock.json"}
		// WordPress 5.2.1 core, read from wp-includes/version.php.
		f.Files["/var/www/shop/wp-includes/version.php"] = "<?php\n$wp_version = '5.2.1';\n$wp_db_version = 44719;\n"
		f.Infos["/var/www/shop/wp-includes/version.php"] = sys.FileInfo{Path: "/var/www/shop/wp-includes/version.php"}
		f.Files[collect.LabSnapshotPath] = labSnapshot("2021-01-01")
	}, func(f *sys.Fake) {
		f.Files["/var/lib/dpkg/status"] = "Package: sudo\nStatus: install ok installed\nVersion: 1.9.15p5-3ubuntu5\n\nPackage: openssh-server\nStatus: install ok installed\nVersion: 1:9.6p1-3ubuntu13\n\nPackage: policykit-1\nStatus: install ok installed\nVersion: 124-2ubuntu1\n"
		f.Files["/etc/apache2/sites-enabled/shop.conf"] += "DocumentRoot /var/www/shop\n"
		f.Files["/var/www/shop/package-lock.json"] = "{\"lockfileVersion\":3,\"packages\":{\"node_modules/jquery\":{\"version\":\"3.7.1\"}}}"
		f.Infos["/var/www/shop/package-lock.json"] = sys.FileInfo{Path: "/var/www/shop/package-lock.json"}
		f.Files["/var/www/shop/wp-includes/version.php"] = "<?php\n$wp_version = '6.7.1';\n"
		f.Infos["/var/www/shop/wp-includes/version.php"] = sys.FileInfo{Path: "/var/www/shop/wp-includes/version.php"}
		f.Files[collect.LabSnapshotPath] = labSnapshot(time.Now().UTC().Format("2006-01-02"))
	})
}
