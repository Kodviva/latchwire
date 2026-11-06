//go:build !windows

package daemon

import "runtime"

// DefaultSocket is the daemon's socket path.
const DefaultSocket = "/var/run/latchwire.sock"

// DefaultStoreDir returns where tunnel configurations are kept on this
// platform.
func DefaultStoreDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Latchwire/tunnels"
	}
	return "/etc/latchwire/tunnels"
}
