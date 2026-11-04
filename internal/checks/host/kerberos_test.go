package host

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func TestKerberosIncludesAndRemovals(t *testing.T) {
	f := func(conf string, more map[string]string) check.Status {
		files := map[string]string{"/etc/krb5.conf": conf}
		for k, v := range more {
			files[k] = v
		}
		return check.Get("HOST-KRB-001").Run(context.Background(), &sys.Fake{Files: files, Infos: map[string]sys.FileInfo{}})[0].Status
	}
	if got := f("permitted_enctypes = DEFAULT -des3 -rc4\n", nil); got != check.Pass {
		t.Errorf("removals: %v", got)
	}
	if got := f("includedir /etc/krb5.conf.d/\n", map[string]string{"/etc/krb5.conf.d/crypto": "permitted_enctypes = rc4-hmac\n"}); got != check.Fail {
		t.Errorf("included file: %v", got)
	}
	if got := f("allow_weak_crypto = on\n", nil); got != check.Fail {
		t.Errorf("on: %v", got)
	}
}
