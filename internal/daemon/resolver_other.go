//go:build !linux

package daemon

import (
	"context"
	"net"
	"net/netip"
)

// lookupHost resolves an endpoint host name. The mark is Linux's (SO_MARK)
// and is ignored here.
func lookupHost(ctx context.Context, host string, _ uint32) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
