package lab

import (
	"github.com/openvapt/openvapt/internal/sys"
)

// Kerberos and image layer checks. The vulnerable sudo version matches the
// lab snapshot's advisories; the hardened layer holds the fixed one.
func layerFixture(f *sys.Fake, version string) {
	base := "/var/lib/docker/overlay2/0123456789abcdef/diff"
	f.Files[base+"/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"18.04\"\nPRETTY_NAME=\"Ubuntu 18.04 LTS\"\n"
	f.Files[base+"/var/lib/dpkg/status"] = "Package: sudo\nStatus: install ok installed\nVersion: " + version + "\n"
}

func init() {
	Register(func(f *sys.Fake) {
		f.Files["/etc/krb5.conf"] = "[libdefaults]\n  allow_weak_crypto = true\n  permitted_enctypes = aes256-cts rc4-hmac\n"
		owned(f, "/etc/krb5.keytab", 0o644, 0, 0)
		layerFixture(f, "1.8.21p2-3ubuntu1.4")
	}, func(f *sys.Fake) {
		f.Files["/etc/krb5.conf"] = "[libdefaults]\n  permitted_enctypes = aes256-cts-hmac-sha1-96\n"
		owned(f, "/etc/krb5.keytab", 0o600, 0, 0)
		layerFixture(f, "1.8.21p2-3ubuntu1.5")
	})
}
