package daemon

import "os"

// writableByOthers is always false: Windows has no mode bits (every file
// reads as 0666). The data directory's DACL (datadir.Secure), inherited by
// everything below it, is what keeps others out.
func writableByOthers(os.FileInfo) bool { return false }
