// Package killswitch blocks the traffic that would leave outside the
// tunnels: while a kill switch is on, only the tunnel interfaces, loopback,
// the tunnels' endpoints, their DNS servers and what a link needs to come up
// (DHCP, IPv6 neighbour discovery) pass. Linux uses one nftables table
// (inet latchwire); other platforms have no implementation yet.
//
// Every change is journaled (owner JournalOwner) before it is made, so a
// crash leaves the command that removes the rules; whether startup keeps or
// removes them is the daemon's decision.
package killswitch

import (
	"context"
	"errors"
	"net/netip"

	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

// ErrUnsupported is returned by New when this system has no firewall the
// kill switch can use (Linux without nft), and by Set when the firewall
// command has gone missing since. There is no fallback (no iptables): a
// tunnel that needs the kill switch is refused.
var ErrUnsupported = errors.New(msg.KillSwitchUnsupported)

// JournalOwner is the journal owner of the kill switch's rules. It holds a
// ':', which no interface name may contain, so it never collides with a
// tunnel's owner (its interface name).
const JournalOwner = "latchwire:killswitch"

// TunnelRule is what one tunnel needs to pass the kill switch: its
// interface, its peers' endpoints (literal addresses) and its DNS servers.
type TunnelRule struct {
	Iface     string
	Endpoints []netip.AddrPort
	DNS       []netip.Addr
}

// State is the whole kill switch. Block false removes the rules; Block true
// replaces them with the rules for Tunnels (none: everything but loopback
// and link setup is blocked). FwMark, when not 0, is the mark of the full
// tunnel's WireGuard socket and endpoint resolver (Linux), whose packets
// pass.
type State struct {
	Block   bool
	Tunnels []TunnelRule
	FwMark  uint32
}

// Firewall puts a State in place. Each Set replaces the previous one as a
// whole, atomically where the platform allows it.
type Firewall interface {
	Set(ctx context.Context, s State) error
}

// New returns this platform's Firewall, which runs its commands with r and
// journals them in j (nil: nothing is journaled). It fails with
// ErrUnsupported when the platform or the system has none.
func New(r netcfg.Runner, j *netcfg.Journal) (Firewall, error) {
	return newPlatform(r, j)
}
