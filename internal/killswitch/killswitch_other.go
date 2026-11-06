//go:build !linux && !darwin && !windows

package killswitch

import "github.com/Kodviva/latchwire/internal/netcfg"

// newPlatform: no kill switch here.
func newPlatform(netcfg.Runner, *netcfg.Journal) (Firewall, error) {
	return nil, ErrUnsupported
}
