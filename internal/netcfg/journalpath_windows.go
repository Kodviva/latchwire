package netcfg

import (
	"path/filepath"

	"github.com/Kodviva/latchwire/internal/datadir"
)

// DefaultJournalPath is where the daemon keeps its journal. Unlike /var/run
// it survives a reboot, so a kill switch a crash left behind is restored
// after one.
var DefaultJournalPath = filepath.Join(datadir.Dir(), "journal.json")
