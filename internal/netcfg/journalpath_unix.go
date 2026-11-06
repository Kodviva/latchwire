//go:build !windows

package netcfg

// DefaultJournalPath is where the daemon keeps its journal.
const DefaultJournalPath = "/var/run/latchwire/journal.json"
