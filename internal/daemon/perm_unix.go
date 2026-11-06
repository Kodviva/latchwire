//go:build !windows

package daemon

import "os"

// writableByOthers reports whether the mode lets a group or other users
// write the file.
func writableByOthers(fi os.FileInfo) bool { return fi.Mode().Perm()&0o022 != 0 }
