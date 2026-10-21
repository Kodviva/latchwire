package netcfg

import (
	"context"
	"net/netip"
)

// AutoMTU returns the tunnel MTU for the current network: the smallest path
// MTU towards the endpoints minus the WireGuard overhead, or 1420 when none
// can be found.
func AutoMTU(ctx context.Context, r Runner, endpoints []netip.AddrPort) int {
	return autoMTULinux(ctx, r, endpoints)
}
