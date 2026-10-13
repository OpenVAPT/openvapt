//go:build !unix

package sign

import "os"

// On systems without POSIX ownership, permission bits are not meaningful;
// the symlink and exclusive-create rules still apply.
func ownedByEUID(os.FileInfo) bool { return true }

func createExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

const strictPerms = false
