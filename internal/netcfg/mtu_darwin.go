package netcfg

import (
	"context"
	"net/netip"
)

// AutoMTU returns the tunnel MTU for the current network: the MTU of the
// default route's interface minus the WireGuard overhead, or 1420 when it
// cannot be found.
func AutoMTU(ctx context.Context, r Runner, endpoints []netip.AddrPort) int {
	return autoMTUDarwin(ctx, r, endpoints)
}
