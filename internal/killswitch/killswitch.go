// Package killswitch blocks the traffic that would leave outside the
// tunnels: while a kill switch is on, only the tunnel interfaces, loopback,
// the tunnels' endpoints and what a link needs to come up (DHCP, IPv6
// neighbour discovery and MLD) pass; DNS goes through the tunnels only.
// Linux uses one nftables table (inet latchwire), macOS one pf anchor
// (com.apple/250.latchwire) and an enable reference of its own, Windows WFP
// filters in a sublayer of their own; other platforms have none.
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
// command has gone missing since or (macOS) the main pf ruleset lacks the
// com.apple anchor point. There is no fallback (no iptables): a
// tunnel that needs the kill switch is refused.
var ErrUnsupported = errors.New(msg.KillSwitchUnsupported)

// unsupportedError is ErrUnsupported (errors.Is) with a platform's own
// explanation.
type unsupportedError string

func (e unsupportedError) Error() string        { return string(e) }
func (e unsupportedError) Is(target error) bool { return target == ErrUnsupported }

// JournalOwner is the journal owner of the kill switch's rules. It holds a
// ':', which no interface name may contain, so it never collides with a
// tunnel's owner (its interface name).
const JournalOwner = "latchwire:killswitch"

// TunnelRule is what one tunnel needs to pass the kill switch: its
// interface, its peers' endpoints (literal addresses) and the local UDP port
// its WireGuard socket is bound to. ListenPort must be the port actually
// bound (the device's listen_port when the configuration sets none).
//
// A tunnel that is still connecting has no interface yet (Iface "": no
// interface rule) and no bound port (ListenPort 0): its endpoints get
// outbound rules only, and only the replies to what was sent come back
// (pf state, nft conntrack); no local port is opened to them. That lets the
// first handshake out the moment the device comes up. DNS passes only
// through the tunnel interface, so a tunnel's DNS servers need no rule.
type TunnelRule struct {
	Iface      string
	Endpoints  []netip.AddrPort
	ListenPort uint16
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

// Verifier is a Firewall that can check that the blocking state it last
// set is still in effect: something outside Latchwire may have disabled pf
// (pfctl -d) or deleted the nft table. ok false asks for the state to be
// set again; err says why the check itself failed (ok is then false too).
// An err that is ErrUnsupported (errors.Is) says that the rules are in
// place but cannot take effect, which setting them again does not change
// (macOS: the main pf ruleset no longer evaluates the com.apple anchors).
type Verifier interface {
	Verify(ctx context.Context) (ok bool, err error)
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
