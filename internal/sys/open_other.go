//go:build !unix

package sys

import (
	"errors"
	"os"
)

func openRead(path string, noFollow bool) (*os.File, error) {
	if noFollow {
		if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("refused: symlink")
		}
	}
	return os.Open(path)
}
