package netcfg

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Kodviva/latchwire/internal/msg"
)

// A Linux full tunnel routes the default route of each family through its
// own routing table T, chosen by LinuxTable. Two policy rules send every
// packet that does not carry the mark T to that table, except where the main
// table has a more specific route (suppress_prefixlength 0 ignores main's
// default route only). The WireGuard socket and the daemon's endpoint
// resolver mark their packets with T, so they keep using main.
const (
	// firstTable is the first routing table tried; the table number is
	// also the fwmark.
	firstTable = 51820
	// tablesTried bounds the search for a free table.
	tablesTried = 1000

	srcValidMarkKey = "net.ipv4.conf.all.src_valid_mark"
)

// defaultFamilies reports which families have a default route in routes.
func defaultFamilies(routes []netip.Prefix) (v4, v6 bool) {
	for _, r := range routes {
		if r.Bits() == 0 {
			if r.Addr().Is4() {
				v4 = true
			} else {
				v6 = true
			}
		}
	}
	return
}

// LinuxTable returns the first routing table from 51820 up that holds no
// route, for a full tunnel's policy routing and fwmark. An error from the
// IPv4 query fails; one from the IPv6 query (IPv6 disabled) does not.
func LinuxTable(ctx context.Context, r Runner) (uint32, error) {
	for t := uint32(firstTable); t < firstTable+tablesTried; t++ {
		n := strconv.FormatUint(uint64(t), 10)
		out, err := r.Run(ctx, "ip", []string{"-4", "route", "show", "table", n}, nil)
		if err != nil {
			return 0, fmt.Errorf("netcfg: finding a free routing table: %w", err)
		}
		if strings.TrimSpace(string(out)) != "" {
			continue
		}
		out, err = r.Run(ctx, "ip", []string{"-6", "route", "show", "table", n}, nil)
		if err == nil && strings.TrimSpace(string(out)) != "" {
			continue
		}
		return t, nil
	}
	return 0, fmt.Errorf("netcfg: no free routing table in %d-%d", firstTable, firstTable+tablesTried-1)
}

// srcValidMark returns the current value of src_valid_mark, or "" when it
// cannot be read or is not a number.
func srcValidMark(ctx context.Context, r Runner) string {
	out, err := r.Run(ctx, "sysctl", []string{"-n", srcValidMarkKey}, nil)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if _, err := strconv.ParseUint(v, 10, 8); err != nil {
		return ""
	}
	return v
}

// linuxFullTunnel reads the system state a full tunnel's plan depends on and
// returns its steps and table. p.FwMark, when set, is the table to use.
func linuxFullTunnel(ctx context.Context, r Runner, p Plan) ([]step, uint32, error) {
	v4, v6 := defaultFamilies(p.Routes)
	table := p.FwMark
	if table == 0 {
		var err error
		if table, err = LinuxTable(ctx, r); err != nil {
			return nil, 0, err
		}
	}
	prev := ""
	if v4 {
		prev = srcValidMark(ctx, r)
	}
	return planLinuxFullTunnel(p.Iface, table, v4, v6, p.Addresses, prev), table, nil
}

func persistentUndo(name string, args ...string) *Step {
	s := undoOf(name, args...)
	s.Persistent = true
	return s
}

// planLinuxFullTunnel returns the steps that route the families v4/v6 of a
// full tunnel on iface through table, after the interface's own addresses
// and routes are in place. prevSrcValidMark is the value src_valid_mark had
// ("" = unknown, restored as the kernel default 0); when it is already 1
// nothing is changed. src_valid_mark lets reverse-path filtering see the
// mark of the WireGuard socket's replies (IPv4 only).
func planLinuxFullTunnel(iface string, table uint32, v4, v6 bool, addrs []netip.Prefix, prevSrcValidMark string) []step {
	t := strconv.FormatUint(uint64(table), 10)
	var out []step
	if v4 && prevSrcValidMark != "1" {
		prev := prevSrcValidMark
		if prev == "" {
			prev = "0"
		}
		out = append(out, step{
			do:   command("sysctl", "-q", srcValidMarkKey+"=1"),
			undo: persistentUndo("sysctl", "-q", srcValidMarkKey+"="+prev),
		})
	}
	for _, f := range []struct {
		on        bool
		flag, dst string
	}{{v4, "-4", "0.0.0.0/0"}, {v6, "-6", "::/0"}} {
		if !f.on {
			continue
		}
		out = append(out,
			// The route goes with the interface, so it is not
			// persistent: its undo fails once the device is closed.
			step{
				do:   command("ip", f.flag, "route", "add", f.dst, "dev", iface, "table", t),
				undo: undoOf("ip", f.flag, "route", "del", f.dst, "dev", iface, "table", t),
			},
			step{
				do:   command("ip", f.flag, "rule", "add", "not", "fwmark", t, "table", t),
				undo: persistentUndo("ip", f.flag, "rule", "del", "not", "fwmark", t, "table", t),
			},
			step{
				do:   command("ip", f.flag, "rule", "add", "table", "main", "suppress_prefixlength", "0"),
				undo: persistentUndo("ip", f.flag, "rule", "del", "table", "main", "suppress_prefixlength", "0"),
			},
		)
	}
	name := rpTableName(iface)
	nft := command("nft", "-f", "-")
	nft.Stdin = rpScript(iface, name, t, addrs)
	out = append(out, step{
		do:      nft,
		undo:    persistentUndo("nft", "delete", "table", "inet", name),
		missing: fmt.Sprintf(msg.NetNoRPFilterFmt, iface),
	})
	return out
}

// rpTableName is the nft table of iface's reverse-path filter. A tunnel name
// may hold characters an nft name may not ('=', '+', '.'); such names are
// hex-encoded under another prefix, so no two interfaces share a table.
func rpTableName(iface string) string {
	for _, c := range iface {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
		if !ok {
			return "latchwire_rpx_" + hex.EncodeToString([]byte(iface))
		}
	}
	return "latchwire_rp_" + iface
}

// rpScript is the nft script, run as one transaction, that (re)creates the
// table name:
//
//   - raw prerouting (priority -300): a packet addressed to one of the
//     tunnel's addresses that arrives on another interface (loopback aside)
//     is dropped, so a host on the local network cannot reach services bound
//     to the tunnel address by spoofing;
//   - mangle output (-150): a packet carrying the mark (the WireGuard
//     socket's, the endpoint resolver's) stores it in its connection;
//   - mangle prerouting (-150): a UDP reply in such a connection gets the
//     mark back, so routing and reverse-path checks treat it as outside the
//     tunnel.
//
// Declaring then deleting the table first replaces a stale copy in the same
// transaction.
func rpScript(iface, name, mark string, addrs []netip.Prefix) []byte {
	q := strconv.Quote(iface)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\ntable inet %s {\n", name, name, name)
	b.WriteString("\tchain prerouting_raw {\n\t\ttype filter hook prerouting priority -300; policy accept;\n")
	for _, a := range addrs {
		fam := "ip6"
		if a.Addr().Is4() {
			fam = "ip"
		}
		fmt.Fprintf(&b, "\t\tiifname != %s iifname != \"lo\" %s daddr %s drop\n", q, fam, a.Addr())
	}
	b.WriteString("\t}\n")
	fmt.Fprintf(&b, "\tchain output_mangle {\n\t\ttype filter hook output priority -150; policy accept;\n\t\tmeta mark %s ct mark set meta mark\n\t}\n", mark)
	fmt.Fprintf(&b, "\tchain prerouting_mangle {\n\t\ttype filter hook prerouting priority -150; policy accept;\n\t\tmeta l4proto udp ct mark %s meta mark set ct mark\n\t}\n", mark)
	b.WriteString("}\n")
	return []byte(b.String())
}
