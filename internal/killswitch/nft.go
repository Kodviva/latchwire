package killswitch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/Kodviva/latchwire/internal/netcfg"
)

// tableName is the kill switch's nftables table, in the inet family (IPv4
// and IPv6).
const tableName = "latchwire"

// removeScript deletes the table. Declaring it first makes the deletion
// succeed when the table is not there, so the removal is idempotent.
const removeScript = "table inet " + tableName + " {}\ndelete table inet " + tableName + "\n"

// ndTypes are the ICMPv6 neighbour discovery messages a link needs: router
// solicitation and advertisement (SLAAC, the default router) and neighbour
// solicitation and advertisement (address resolution, duplicate address
// detection). Redirects (137) are left out: a host on the link could use
// them to steer traffic, and nothing breaks without them.
//
// They pass only from a link-local source or to a link-local or
// link-scope multicast destination: that covers the default router (always
// link-local), duplicate address detection (from ::, to the solicited-node
// group) and address resolution through the solicited-node groups. Not
// covered: neighbour discovery between two global addresses on the link,
// which only an endpoint on the local link would need.
const ndTypes = "icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255"

// ndScopes are the two conditions, either of which lets ndTypes pass.
var ndScopes = []string{"ip6 saddr fe80::/10", "ip6 daddr { fe80::/10, ff02::/16 }"}

// DHCP (P16): requests leave only from sockets of root (the system's DHCP
// clients; one using a packet socket is not filtered at all) and only to
// the broadcast address or private and link-local networks, where a DHCP
// server can be; replies come only from those networks (or 0.0.0.0).
// DHCPv6 goes from a link-local address to the All_DHCP_Relay_Agents_and_
// Servers group, and replies come from link-local addresses. Otherwise an
// unprivileged process could reach any host on ports 67 and 547 around the
// kill switch.
const (
	dhcp4Nets = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16"
	dhcp4Out  = "meta skuid 0 ip daddr { 255.255.255.255, " + dhcp4Nets + " } udp sport 68 udp dport 67"
	dhcp4In   = "ip saddr { 0.0.0.0, " + dhcp4Nets + " } udp sport 67 udp dport 68"
	dhcp6Out  = "meta skuid 0 ip6 saddr fe80::/10 ip6 daddr ff02::1:2 udp sport 546 udp dport 547"
	dhcp6In   = "ip6 saddr fe80::/10 udp sport 547 udp dport 546"
)

// MLD: the kernel reports the multicast groups it listens on (the
// solicited-node groups neighbour discovery depends on) and answers the
// router's queries. A switch that snoops MLD stops forwarding those groups
// to a host that never reports, which cuts IPv6 off minutes later. MLD
// always has hop limit 1 and a link-local (or, before an address is ready,
// unspecified) source.
const (
	mldOut = "icmpv6 type { mld-listener-report, mld2-listener-report } ip6 hoplimit 1 ip6 saddr { fe80::/10, :: }"
	mldIn  = "icmpv6 type mld-listener-query ip6 hoplimit 1 ip6 saddr { fe80::/10, :: }"
)

// nftScript returns the nft script, run as one transaction (nft -f -), that
// puts s in place: the removal of the table, or its replacement.
//
// While blocking, each base chain accepts, in order:
//
//   - output: loopback; the tunnel interfaces; packets with the mark (the
//     WireGuard socket, the endpoint resolver), whose connections get the
//     mark too; DHCPv4 and DHCPv6 requests (dhcp4Out, dhcp6Out); neighbour
//     discovery; MLD reports; UDP to each endpoint, connected or
//     connecting. The rest is rejected (admin-prohibited), so applications
//     fail at once.
//   - input: loopback; the tunnel interfaces; established and related
//     packets of connections that carry the mark; DHCP replies; neighbour
//     discovery; MLD queries; UDP from each endpoint to the tunnel's listen
//     port (the peer may start a handshake; no other local port is open to
//     a source address anyone can forge), or, for a tunnel still
//     connecting (no listen port yet), only the replies of flows to the
//     endpoint that conntrack has seen go out; and ICMP errors about
//     traffic to the endpoint (path MTU). The rest is dropped. Established traffic in
//     general is not accepted: a connection opened before the kill switch
//     came on must not survive it.
//
// There is no DNS rule: DNS passes only through the tunnel interfaces.
// Accepting the tunnels' DNS servers on any interface would send queries
// in clear text over the local network while a tunnel is down. Endpoint
// names are resolved with the mark (Linux full tunnel) or come from the
// daemon's endpoint cache.
//   - forward: traffic routed into a tunnel, and its replies. The rest is
//     dropped.
//
// Declaring the table, deleting it and defining it again replaces an older
// copy in the same transaction, so there is never a moment without rules.
func nftScript(s State) ([]byte, error) {
	if !s.Block {
		return []byte(removeScript), nil
	}
	if err := validState(s); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(removeScript)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)

	chain := func(name string) {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority filter; policy accept;\n", name, name)
	}
	rule := func(format string, args ...any) {
		b.WriteString("\t\t")
		fmt.Fprintf(&b, format, args...)
		b.WriteString("\n")
	}
	mark := strconv.FormatUint(uint64(s.FwMark), 10)

	chain("output")
	rule(`oifname "lo" accept`)
	for _, t := range s.Tunnels {
		if t.Iface != "" {
			rule("oifname %s accept", strconv.Quote(t.Iface))
		}
	}
	if s.FwMark != 0 {
		rule("meta mark %s ct mark set meta mark accept", mark)
	}
	rule("%s accept", dhcp4Out)
	rule("%s accept", dhcp6Out)
	for _, sc := range ndScopes {
		rule("%s %s accept", ndTypes, sc)
	}
	rule("%s accept", mldOut)
	for _, t := range s.Tunnels {
		for _, e := range t.Endpoints {
			a := e.Addr().Unmap()
			rule("%s daddr %s udp dport %d accept", fam(a), a, e.Port())
		}
	}
	rule("reject with icmpx type admin-prohibited")
	b.WriteString("\t}\n")

	chain("input")
	rule(`iifname "lo" accept`)
	for _, t := range s.Tunnels {
		if t.Iface != "" {
			rule("iifname %s accept", strconv.Quote(t.Iface))
		}
	}
	if s.FwMark != 0 {
		rule("ct mark %s ct state established,related accept", mark)
	}
	rule("%s accept", dhcp4In)
	rule("%s accept", dhcp6In)
	for _, sc := range ndScopes {
		rule("%s %s accept", ndTypes, sc)
	}
	rule("%s accept", mldIn)
	for _, t := range s.Tunnels {
		for _, e := range t.Endpoints {
			a := e.Addr().Unmap()
			if t.ListenPort != 0 {
				rule("%s saddr %s udp sport %d udp dport %d accept", fam(a), a, e.Port(), t.ListenPort)
			} else {
				rule("%s saddr %s udp sport %d ct state established accept", fam(a), a, e.Port())
			}
			rule("ct state related ct original %s daddr %s accept", fam(a), a)
		}
	}
	rule("drop")
	b.WriteString("\t}\n")

	chain("forward")
	for _, t := range s.Tunnels {
		if t.Iface == "" {
			continue
		}
		q := strconv.Quote(t.Iface)
		rule("oifname %s accept", q)
		rule("iifname %s ct state established,related accept", q)
	}
	rule("drop")
	b.WriteString("\t}\n}\n")
	return []byte(b.String()), nil
}

// fam is the nft address family keyword of a.
func fam(a netip.Addr) string {
	if a.Is4() {
		return "ip"
	}
	return "ip6"
}

// validState checks what goes into the script: interface names (empty for
// a tunnel still connecting) that need no escaping in an nft string (the
// tunnel name rules, at most 15 characters), and literal endpoint
// addresses without a zone (nft has none). A tunnel without a listen port
// gets outbound endpoint rules only.
func validState(s State) error {
	for _, t := range s.Tunnels {
		if t.Iface != "" && !validIface(t.Iface) {
			return fmt.Errorf("killswitch: invalid interface name %q", t.Iface)
		}
		for _, e := range t.Endpoints {
			if !e.IsValid() || e.Port() == 0 || e.Addr().Zone() != "" {
				return fmt.Errorf("killswitch: invalid endpoint %q for %q", e, t.Iface)
			}
		}
	}
	return nil
}

func validIface(s string) bool {
	if len(s) == 0 || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_=+.-", c) >= 0) {
			return false
		}
	}
	return true
}

// nftFirewall is the Linux kill switch: one nftables table, replaced or
// removed by one nft -f - transaction per Set.
type nftFirewall struct {
	r netcfg.Runner
	j *netcfg.Journal // nil: nothing is journaled

	mu sync.Mutex
}

// newNft checks that nft is installed (nft --version) and returns the
// firewall; ErrUnsupported when it is not.
func newNft(ctx context.Context, r netcfg.Runner, j *netcfg.Journal) (Firewall, error) {
	if _, err := r.Run(ctx, "nft", []string{"--version"}, nil); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, ErrUnsupported
		}
		return nil, fmt.Errorf("killswitch: nft --version: %w", err)
	}
	return &nftFirewall{r: r, j: j}, nil
}

// removeStep is the journaled undo of the table: persistent, so a failure
// keeps it for a retry, and idempotent.
func removeStep() netcfg.Step {
	return netcfg.Step{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(removeScript), Persistent: true}
}

// Set replaces the table (s.Block) or removes it. The removal is journaled
// before the table is created, and forgotten only once a removal ran; a
// failed run leaves it journaled, since a table from an earlier Set may
// still be in place.
func (f *nftFirewall) Set(ctx context.Context, s State) error {
	script, err := nftScript(s)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.Block && f.j != nil {
		if err := f.j.Record(JournalOwner, []netcfg.Step{removeStep()}); err != nil {
			return err
		}
	}
	if _, err := f.r.Run(ctx, "nft", []string{"-f", "-"}, script); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return ErrUnsupported
		}
		return fmt.Errorf("killswitch: nft -f -: %w", err)
	}
	if !s.Block && f.j != nil {
		return f.j.Forget(JournalOwner)
	}
	return nil
}

// Verify checks that the table is there (nft list table): nft reports a
// table that does not exist with ENOENT's text.
func (f *nftFirewall) Verify(ctx context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.r.Run(ctx, "nft", []string{"list", "table", "inet", tableName}, nil); err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return false, nil
		}
		return false, fmt.Errorf("killswitch: nft list table inet %s: %w", tableName, err)
	}
	return true, nil
}
