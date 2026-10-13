package host

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// C-11: only advisory lines are counted, never headers or footers.
func TestDnfAdvisoryLinesOnly(t *testing.T) {
	out := "Updates Information Summary: available\nALSA-2024:1234 Important/Sec. openssl-1:3.0.7-27.el9.x86_64\nRLSA-2024:0005 Moderate/Sec.  curl-7.76.1-29.el9.x86_64\nLast metadata expiration check: 0:10:00 ago on Mon.\n"
	f := &sys.Fake{Commands: map[string]string{"dnf -q updateinfo list --security": out}}
	rs := check.Get("HOST-PKG-001").Run(context.Background(), f)
	if len(rs) != 1 || rs[0].Status != check.Fail || !strings.HasPrefix(rs[0].Message, "2 security advisories") || len(rs[0].Evidence) != 2 {
		t.Errorf("want exactly two advisories, got %+v", rs)
	}
	f = &sys.Fake{Commands: map[string]string{"dnf -q updateinfo list --security": "Last metadata expiration check: 0:10:00 ago on Mon.\n"}}
	rs = check.Get("HOST-PKG-001").Run(context.Background(), f)
	if len(rs) != 1 || rs[0].Status != check.Pass {
		t.Errorf("a footer alone is not an advisory, got %+v", rs)
	}
}
