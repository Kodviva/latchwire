package daemon

import (
	"path/filepath"

	"github.com/Kodviva/latchwire/internal/datadir"
)

// DefaultSocket is the daemon's named pipe.
const DefaultSocket = `\\.\pipe\latchwire`

// DefaultStoreDir returns where tunnel configurations are kept.
func DefaultStoreDir() string { return filepath.Join(datadir.Dir(), "tunnels") }
