//go:build !unix

package netcfg

import "os"

func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }
