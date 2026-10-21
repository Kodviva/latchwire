//go:build unix

package netcfg

import (
	"os"
	"syscall"
)

// ownerUID returns the uid that owns the file.
func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
