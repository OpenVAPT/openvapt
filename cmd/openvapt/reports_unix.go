//go:build unix

package main

import (
	"os"
	"syscall"
)

// fileUID returns the owner of a file, when the system records one.
func fileUID(st os.FileInfo) (int, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(s.Uid), true
}
