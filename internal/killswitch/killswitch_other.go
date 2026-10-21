//go:build !linux && !darwin

package killswitch

import "github.com/Kodviva/latchwire/internal/netcfg"

// newPlatform: no kill switch here (Windows has none yet).
func newPlatform(netcfg.Runner, *netcfg.Journal) (Firewall, error) {
	return nil, ErrUnsupported
}
