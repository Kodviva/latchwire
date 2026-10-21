package daemon

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// lookupHost resolves an endpoint host name. With a mark (a full tunnel's
// table), the queries carry SO_MARK = mark, so they leave outside the tunnel
// and pass the kill switch, like the WireGuard socket's packets.
func lookupHost(ctx context.Context, host string, mark uint32) ([]netip.Addr, error) {
	return resolverFor(mark).LookupNetIP(ctx, "ip", host)
}

// resolverFor returns the default resolver for mark 0, else the Go resolver
// (the only one that dials through Dial) with a marking dialer.
func resolverFor(mark uint32) *net.Resolver {
	if mark == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Control: markControl(mark)}
			return d.DialContext(ctx, network, address)
		},
	}
}

// markControl sets SO_MARK on a socket before it connects; failing to set it
// fails the dial, so no query leaves unmarked.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return serr
	}
}
