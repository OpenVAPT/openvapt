//go:build !unix

package report

import "os"

func ownedByCurrentUser(os.FileInfo) bool { return true }
