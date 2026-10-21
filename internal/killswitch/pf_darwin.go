package killswitch

import "github.com/Kodviva/latchwire/internal/netcfg"

// newPlatform returns the pf kill switch. It runs nothing: pfctl needs
// root even to read the ruleset, and whether the main ruleset has the
// com.apple anchor point is checked at every Set that blocks.
func newPlatform(r netcfg.Runner, j *netcfg.Journal) (Firewall, error) {
	return newPf(r, j), nil
}
