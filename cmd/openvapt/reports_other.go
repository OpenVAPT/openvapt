//go:build !unix

package main

import "os"

// fileUID is not available on this system.
func fileUID(os.FileInfo) (int, bool) { return 0, false }
