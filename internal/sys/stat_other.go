//go:build !unix

package sys

import "io/fs"

func toInfo(path string, st fs.FileInfo) FileInfo {
	return FileInfo{Path: path, Mode: st.Mode(), Size: st.Size(), IsDir: st.IsDir(), UID: -1, GID: -1}
}
