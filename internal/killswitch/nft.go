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
const ndTypes = "icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255"

// nftScript returns the nft script, run as one transaction (nft -f -), that
// puts s in place: the removal of the table, or its replacement.
//
// While blocking, each base chain accepts, in order:
//
//   - output: loopback; the tunnel interfaces; packets with the mark (the
//     WireGuard socket, the endpoint resolver), whose connections get the
//     mark too; DHCPv4 and DHCPv6 requests; neighbour discovery; DNS (TCP
//     and UDP 53) to the tunnels' DNS servers on any interface (they are
//     routed into the tunnel when it is up); UDP to each endpoint. The rest
//     is rejected (admin-prohibited), so applications fail at once.
//   - input: loopback; the tunnel interfaces; established and related
//     packets of connections that carry the mark; DHCP replies; neighbour
//     discovery; DNS replies from the tunnels' servers in established
//     connections; UDP from each endpoint (the peer may start a handshake)
//     and ICMP errors about traffic to it (path MTU). The rest is dropped.
//     Established traffic in general is not accepted: a connection opened
//     before the kill switch came on must not survive it.
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
		rule("oifname %s accept", strconv.Quote(t.Iface))
	}
	if s.FwMark != 0 {
		rule("meta mark %s ct mark set meta mark accept", mark)
	}
	rule("meta nfproto ipv4 udp sport 68 udp dport 67 accept")
	rule("meta nfproto ipv6 udp sport 546 udp dport 547 accept")
	rule("%s accept", ndTypes)
	for _, t := range s.Tunnels {
		for _, d := range t.DNS {
			d = d.Unmap()
			rule("%s daddr %s meta l4proto { tcp, udp } th dport 53 accept", fam(d), d)
		}
	}
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
		rule("iifname %s accept", strconv.Quote(t.Iface))
	}
	if s.FwMark != 0 {
		rule("ct mark %s ct state established,related accept", mark)
	}
	rule("meta nfproto ipv4 udp sport 67 udp dport 68 accept")
	rule("meta nfproto ipv6 udp sport 547 udp dport 546 accept")
	rule("%s accept", ndTypes)
	for _, t := range s.Tunnels {
		for _, d := range t.DNS {
			d = d.Unmap()
			rule("%s saddr %s meta l4proto { tcp, udp } th sport 53 ct state established accept", fam(d), d)
		}
	}
	for _, t := range s.Tunnels {
		for _, e := range t.Endpoints {
			a := e.Addr().Unmap()
			rule("%s saddr %s udp sport %d accept", fam(a), a, e.Port())
			rule("ct state related ct original %s daddr %s accept", fam(a), a)
		}
	}
	rule("drop")
	b.WriteString("\t}\n")

	chain("forward")
	for _, t := range s.Tunnels {
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

// validState checks what goes into the script: interface names that need
// no escaping in an nft string (the tunnel name rules, at most 15
// characters), and literal addresses without a zone (nft has none).
func validState(s State) error {
	for _, t := range s.Tunnels {
		if !validIface(t.Iface) {
			return fmt.Errorf("killswitch: invalid interface name %q", t.Iface)
		}
		for _, e := range t.Endpoints {
			if !e.IsValid() || e.Port() == 0 || e.Addr().Zone() != "" {
				return fmt.Errorf("killswitch: invalid endpoint %q for %s", e, t.Iface)
			}
		}
		for _, d := range t.DNS {
			if !d.IsValid() || d.Zone() != "" {
				return fmt.Errorf("killswitch: invalid DNS server %q for %s", d, t.Iface)
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
