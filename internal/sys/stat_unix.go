//go:build unix

package sys

import (
	"io/fs"
	"syscall"
)

func toInfo(path string, st fs.FileInfo) FileInfo {
	fi := FileInfo{Path: path, Mode: st.Mode(), Size: st.Size(), IsDir: st.IsDir(), UID: -1, GID: -1}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		fi.UID, fi.GID = int(s.Uid), int(s.Gid)
	}
	return fi
}
