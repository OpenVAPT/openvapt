//go:build unix

package sys

import (
	"os"
	"syscall"
)

// openRead opens path read-only without ever blocking (O_NONBLOCK keeps a
// FIFO or device from stalling the scan) and, when noFollow is set, refuses
// a symlink in the final path component (O_NOFOLLOW).
func openRead(path string, noFollow bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if noFollow {
		flags |= syscall.O_NOFOLLOW
	}
	return os.OpenFile(path, flags, 0)
}
