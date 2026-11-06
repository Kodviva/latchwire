package daemon

import "os"

// writableByOthers is always false: Windows has no mode bits (every file
// reads as 0666). datadir.Secure, which Serve runs before it opens anything
// and whose failure stops the service, puts a DACL on the data directory
// and all that is in it, and new files inherit it.
func writableByOthers(os.FileInfo) bool { return false }
