//go:build unix

package report

import (
	"os"
	"syscall"
)

func ownedByCurrentUser(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}

// noFollow makes report files refuse a planted link in the last path element.
const noFollow = syscall.O_NOFOLLOW
