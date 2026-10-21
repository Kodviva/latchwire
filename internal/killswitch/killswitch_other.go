//go:build !linux

package killswitch

import "github.com/Kodviva/latchwire/internal/netcfg"

// newPlatform: no kill switch here yet (macOS pf comes later; Windows has
// none).
func newPlatform(netcfg.Runner, *netcfg.Journal) (Firewall, error) {
	return nil, ErrUnsupported
}
