package netcfg

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// winRoute is one row of `route print`. gw is invalid for an on-link route.
// The IPv4 table names the interface by its address, the IPv6 table by its
// index.
type winRoute struct {
	prefix  netip.Prefix
	gw      netip.Addr
	ifAddr  netip.Addr
	ifIndex int
	metric  int
}

// parseRoutePrint4 reads `route print -4`. An active route is
//
//	destination  netmask  gateway  interface  metric
//
// and the gateway of an on-link route is a word in the system's language,
// possibly several. Only rows that start with two addresses and end with an
// address and a number are routes: that skips the headers in any language,
// and the persistent routes, which have no interface column.
func parseRoutePrint4(out string) []winRoute {
	var rs []winRoute
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		dst, err1 := netip.ParseAddr(f[0])
		mask, err2 := netip.ParseAddr(f[1])
		ifAddr, err3 := netip.ParseAddr(f[len(f)-2])
		metric, err4 := strconv.Atoi(f[len(f)-1])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || !dst.Is4() || !mask.Is4() || !ifAddr.Is4() {
			continue
		}
		bits, ok := maskBits(mask)
		if !ok {
			continue
		}
		p, err := dst.Prefix(bits)
		if err != nil {
			continue
		}
		r := winRoute{prefix: p, ifAddr: ifAddr, metric: metric}
		if len(f) == 5 {
			if gw, err := netip.ParseAddr(f[2]); err == nil && gw.Is4() {
				r.gw = gw
			}
		}
		rs = append(rs, r)
	}
	return rs
}

// parseRoutePrint6 reads `route print -6`:
//
//	interface-index  metric  destination  gateway
//
// A long destination pushes the gateway to the next line, alone.
func parseRoutePrint6(out string) []winRoute {
	var rs []winRoute
	waiting := false
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if waiting {
			waiting = false
			if len(f) >= 1 && len(rs) > 0 {
				rs[len(rs)-1].gw = v6Gateway(f[0])
				if len(f) == 1 {
					continue
				}
			}
		}
		if len(f) < 3 {
			continue
		}
		index, err1 := strconv.Atoi(f[0])
		metric, err2 := strconv.Atoi(f[1])
		p, err3 := netip.ParsePrefix(f[2])
		if err1 != nil || err2 != nil || err3 != nil || p.Addr().Is4() {
			continue
		}
		r := winRoute{prefix: p, ifIndex: index, metric: metric}
		if len(f) == 3 {
			waiting = true
		} else {
			r.gw = v6Gateway(f[3])
		}
		rs = append(rs, r)
	}
	return rs
}

func v6Gateway(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4() {
		return netip.Addr{}
	}
	return a
}

// lowestDefault returns the default route with the lowest metric among rs,
// the first of equals, leaving out what skip reports.
func lowestDefault(rs []winRoute, skip func(winRoute) bool) (winRoute, bool) {
	var best winRoute
	found := false
	for _, r := range rs {
		if r.prefix.Bits() != 0 || (skip != nil && skip(r)) {
			continue
		}
		if !found || r.metric < best.metric {
			best, found = r, true
		}
	}
	return best, found
}

// WindowsDefaultGateway returns the gateway of the preferred IPv4 default
// route in the output of `route print -4`, or the invalid address when
// there is none or it is on-link.
func WindowsDefaultGateway(routePrint string) netip.Addr {
	r, ok := lowestDefault(parseRoutePrint4(routePrint), nil)
	if !ok {
		return netip.Addr{}
	}
	return r.gw
}

// ifaceInfo is what the routing code needs to know about an interface.
type ifaceInfo struct {
	Name  string
	Index int
	MTU   int
	Addrs []netip.Addr
}

// systemIfaces lists the interfaces. An interface whose addresses cannot
// be read is listed without them.
func systemIfaces() []ifaceInfo {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]ifaceInfo, 0, len(list))
	for _, ifc := range list {
		info := ifaceInfo{Name: ifc.Name, Index: ifc.Index, MTU: ifc.MTU}
		if as, err := ifc.Addrs(); err == nil {
			for _, a := range as {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					info.Addrs = append(info.Addrs, p.Addr().Unmap())
				}
			}
		}
		out = append(out, info)
	}
	return out
}

// ifaceOf finds the interface of a route.
func ifaceOf(list []ifaceInfo, r winRoute) (ifaceInfo, bool) {
	for _, i := range list {
		if r.ifIndex != 0 && i.Index == r.ifIndex {
			return i, true
		}
		if r.ifAddr.IsValid() {
			for _, a := range i.Addrs {
				if a == r.ifAddr {
					return i, true
				}
			}
		}
	}
	return ifaceInfo{}, false
}

// readWindowsRoutes reads one family's routing table.
func readWindowsRoutes(ctx context.Context, r Runner, v4 bool) ([]winRoute, error) {
	if v4 {
		out, err := r.Run(ctx, "route", []string{"print", "-4"}, nil)
		if err != nil {
			return nil, err
		}
		return parseRoutePrint4(string(out)), nil
	}
	out, err := r.Run(ctx, "route", []string{"print", "-6"}, nil)
	if err != nil {
		return nil, err
	}
	return parseRoutePrint6(string(out)), nil
}

// windowsDefaultRoute reads the default route of one family, ignoring the
// tunnel own itself: the next hop's interface is its index as a string.
// No default route is a known absence; a table or interface that cannot be
// read is unknown (ok false).
func windowsDefaultRoute(ctx context.Context, r Runner, v4 bool, own string, ifaces func() []ifaceInfo) (nextHop, int, bool) {
	rs, err := readWindowsRoutes(ctx, r, v4)
	if err != nil {
		return nextHop{}, 0, false
	}
	list := ifaces()
	best, found := lowestDefault(rs, func(w winRoute) bool {
		i, ok := ifaceOf(list, w)
		return ok && i.Name == own
	})
	if !found {
		return nextHop{}, 0, true
	}
	i, ok := ifaceOf(list, best)
	if !ok {
		return nextHop{}, 0, false
	}
	return nextHop{gw: best.gw, iface: strconv.Itoa(i.Index)}, i.MTU, true
}

// autoMTUWindows finds the MTU of the default route's interface, for the
// family of each endpoint (IPv4 without endpoints), and uses the smallest.
func autoMTUWindows(ctx context.Context, r Runner, endpoints []netip.AddrPort, ifaces func() []ifaceInfo) int {
	var want [2]bool
	for _, ep := range endpoints {
		want[famIndex(ep.Addr().Unmap())] = true
	}
	if !want[0] && !want[1] {
		want[0] = true
	}
	path := 0
	for f := range 2 {
		if !want[f] {
			continue
		}
		if _, mtu, ok := windowsDefaultRoute(ctx, r, f == 0, "", ifaces); ok && mtu > 0 && (path == 0 || mtu < path) {
			path = mtu
		}
	}
	return tunnelMTU(path)
}
