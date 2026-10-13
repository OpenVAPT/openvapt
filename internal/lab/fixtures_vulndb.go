package lab

import (
	"github.com/openvapt/openvapt/internal/sys"
	"time"
)

func init() {
	Register(func(f *sys.Fake) {
		f.Files["/var/lib/dpkg/status"] = "Package: sudo\nStatus: install ok installed\nVersion: 1.8.21p2-3ubuntu1.4\n\nPackage: openssh-server\nStatus: install ok installed\nVersion: 1:7.6p1-4ubuntu0.6\n\nPackage: policykit-1\nStatus: install ok installed\nVersion: 0.105-20ubuntu0.18.04.5\n"
		f.Files["/etc/apache2/sites-enabled/shop.conf"] += "DocumentRoot /var/www/shop\n"
		f.Files["/var/www/shop/package-lock.json"] = "{\"lockfileVersion\":2,\"packages\":{\"node_modules/jquery\":{\"version\":\"3.4.1\"}}}"
		f.Infos["/var/www/shop/package-lock.json"] = sys.FileInfo{Path: "/var/www/shop/package-lock.json"}
	}, func(f *sys.Fake) {
		f.Files["/var/lib/dpkg/status"] = "Package: sudo\nStatus: install ok installed\nVersion: 1.9.15p5-3ubuntu5\n\nPackage: openssh-server\nStatus: install ok installed\nVersion: 1:9.6p1-3ubuntu13\n\nPackage: policykit-1\nStatus: install ok installed\nVersion: 124-2ubuntu1\n"
		f.Files["/etc/apache2/sites-enabled/shop.conf"] += "DocumentRoot /var/www/shop\n"
		f.Files["/var/www/shop/package-lock.json"] = "{\"lockfileVersion\":3,\"packages\":{\"node_modules/jquery\":{\"version\":\"3.7.1\"}}}"
		f.Infos["/var/www/shop/package-lock.json"] = sys.FileInfo{Path: "/var/www/shop/package-lock.json"}
		f.Files["/run/openvapt/lab-snapshot-date"] = time.Now().UTC().Format("2006-01-02")
	})
}
