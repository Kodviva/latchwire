package killswitch

import (
	"fmt"
	"net/netip"
)

// The Windows kill switch is a list of Windows Filtering Platform filters at
// the application layer enforcement (ALE) layers, where connections are
// authorized: outbound at connect, inbound at receive-accept, for each
// family. The list is worked out here and installed by a wfpEngine.
//
// Filters at the highest weight permit, and one filter at the lowest weight
// on each layer blocks the rest. Conditions on one field are alternatives;
// conditions on different fields must all match.

type wfpLayer int

const (
	layerConnect4 wfpLayer = iota
	layerConnect6
	layerRecv4
	layerRecv6
)

var wfpLayers = []wfpLayer{layerConnect4, layerConnect6, layerRecv4, layerRecv6}

func (l wfpLayer) outbound() bool { return l == layerConnect4 || l == layerConnect6 }

type wfpField int

const (
	fieldProtocol wfpField = iota
	fieldRemoteAddr
	fieldLocalAddr
	fieldRemotePort
	fieldLocalPort // also the ICMP type, which WFP files under this field
	fieldInterface
	fieldLoopback
)

// wfpCond is one condition: prefix for an address field, iface for the
// interface field, value for the others (the loopback flag has none).
type wfpCond struct {
	field  wfpField
	value  uint16
	prefix netip.Prefix
	iface  string
}

// wfpFilter is one filter. hard permits cannot be overridden by a block in
// a lower sublayer, such as a third-party firewall's: the tunnel's own
// packets must get out, and every other permit leaves other firewalls their
// say.
type wfpFilter struct {
	name   string
	layer  wfpLayer
	permit bool
	hard   bool
	conds  []wfpCond
}

const (
	protoUDP    = 17
	protoICMPv6 = 58
)

func cond(f wfpField, v uint16) wfpCond { return wfpCond{field: f, value: v} }

func addrConds(f wfpField, ps ...string) []wfpCond {
	out := make([]wfpCond, len(ps))
	for i, p := range ps {
		out[i] = wfpCond{field: f, prefix: netip.MustParsePrefix(p)}
	}
	return out
}

func icmpConds(types ...uint16) []wfpCond {
	out := []wfpCond{cond(fieldProtocol, protoICMPv6)}
	for _, t := range types {
		out = append(out, cond(fieldLocalPort, t))
	}
	return out
}

// wfpDHCP4Nets are the networks a DHCPv4 server can be on.
var wfpDHCP4Nets = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}

// wfpLinkFilters are what a link needs to come up, with the limits of the
// nft and pf rules where WFP can express them:
//
//   - DHCP (P16): only to the broadcast address or the networks a server can
//     be on, replies only from those (or 0.0.0.0); DHCPv6 only from a
//     link-local address to ff02::1:2, replies only from link-local
//     addresses. Unlike Linux and macOS this does not depend on the sender:
//     on Windows any program may bind port 68 or 546, so it can reach those
//     networks on the server ports.
//   - IPv6 neighbour discovery: router and neighbour solicitation and
//     advertisement (not redirects, 137), only from a link-local source or
//     to a link-local or link-scope multicast destination. WFP cannot match
//     the hop limit.
//   - MLD reports out and queries in, only with a link-local or unspecified
//     source.
func wfpLinkFilters() []wfpFilter {
	nd := icmpConds(133, 134, 135, 136)
	return []wfpFilter{
		{name: "dhcp out", layer: layerConnect4, conds: append([]wfpCond{cond(fieldProtocol, protoUDP), cond(fieldLocalPort, 68), cond(fieldRemotePort, 67)},
			addrConds(fieldRemoteAddr, append([]string{"255.255.255.255/32"}, wfpDHCP4Nets...)...)...)},
		{name: "dhcp in", layer: layerRecv4, conds: append([]wfpCond{cond(fieldProtocol, protoUDP), cond(fieldLocalPort, 68), cond(fieldRemotePort, 67)},
			addrConds(fieldRemoteAddr, append([]string{"0.0.0.0/32"}, wfpDHCP4Nets...)...)...)},
		{name: "dhcpv6 out", layer: layerConnect6, conds: append([]wfpCond{cond(fieldProtocol, protoUDP), cond(fieldLocalPort, 546), cond(fieldRemotePort, 547)},
			append(addrConds(fieldLocalAddr, "fe80::/10"), addrConds(fieldRemoteAddr, "ff02::1:2/128")...)...)},
		{name: "dhcpv6 in", layer: layerRecv6, conds: append([]wfpCond{cond(fieldProtocol, protoUDP), cond(fieldLocalPort, 546), cond(fieldRemotePort, 547)},
			addrConds(fieldRemoteAddr, "fe80::/10")...)},
		{name: "nd out from link-local", layer: layerConnect6, conds: append(addrConds(fieldLocalAddr, "fe80::/10"), nd...)},
		{name: "nd out to link scope", layer: layerConnect6, conds: append(addrConds(fieldRemoteAddr, "fe80::/10", "ff02::/16"), nd...)},
		{name: "nd in from link-local", layer: layerRecv6, conds: append(addrConds(fieldRemoteAddr, "fe80::/10"), nd...)},
		{name: "nd in to link scope", layer: layerRecv6, conds: append(addrConds(fieldLocalAddr, "fe80::/10", "ff02::/16"), nd...)},
		{name: "mld reports", layer: layerConnect6, conds: append(addrConds(fieldLocalAddr, "fe80::/10", "::/128"), icmpConds(131, 143)...)},
		{name: "mld queries", layer: layerRecv6, conds: append(addrConds(fieldRemoteAddr, "fe80::/10", "::/128"), icmpConds(130)...)},
	}
}

// wfpFilters returns the filters for s, which must be blocking.
//
// On every layer: loopback and each tunnel interface pass; the rest is
// blocked. Then what a link needs (wfpLinkFilters), UDP out to each
// endpoint, and UDP in from each endpoint to the tunnel's listen port only.
// A tunnel still connecting has no listen port: its replies pass as part of
// the outbound flow. Any process may use the endpoint's address and port,
// as with the nft and pf rules.
//
// There is no DNS rule (P14): DNS passes only through the tunnel interfaces.
//
// Forwarded packets do not pass these layers, so a host that routes for
// others (Internet Connection Sharing, Hyper-V, WSL) is not limited by them.
func wfpFilters(s State) ([]wfpFilter, error) {
	if err := validState(s); err != nil {
		return nil, err
	}
	var out []wfpFilter
	for _, l := range wfpLayers {
		out = append(out, wfpFilter{name: "loopback", layer: l, permit: true, conds: []wfpCond{{field: fieldLoopback}}})
		for _, t := range s.Tunnels {
			if t.Iface != "" {
				out = append(out, wfpFilter{name: "tunnel " + t.Iface, layer: l, permit: true, conds: []wfpCond{{field: fieldInterface, iface: t.Iface}}})
			}
		}
	}
	for _, f := range wfpLinkFilters() {
		f.permit = true
		out = append(out, f)
	}
	for _, t := range s.Tunnels {
		for _, e := range t.Endpoints {
			a := e.Addr().Unmap()
			conn, recv := layerConnect4, layerRecv4
			if a.Is6() {
				conn, recv = layerConnect6, layerRecv6
			}
			host := wfpCond{field: fieldRemoteAddr, prefix: netip.PrefixFrom(a, a.BitLen())}
			name := fmt.Sprintf("endpoint %s", netip.AddrPortFrom(a, e.Port()))
			base := []wfpCond{cond(fieldProtocol, protoUDP), host, cond(fieldRemotePort, e.Port())}
			out = append(out, wfpFilter{name: name, layer: conn, permit: true, hard: true, conds: base})
			if t.ListenPort != 0 {
				out = append(out, wfpFilter{name: name, layer: recv, permit: true, hard: true,
					conds: append(base[:len(base):len(base)], cond(fieldLocalPort, t.ListenPort))})
			}
		}
	}
	for _, l := range wfpLayers {
		out = append(out, wfpFilter{name: "block", layer: l})
	}
	return out, nil
}
