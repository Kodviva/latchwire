package netcfg

import (
	"context"
	"log"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Windows networking goes through netsh, route and reg from System32, like
// ip on Linux. Every address and route is added with store=active, so none
// outlives a reboot; addresses, routes on the tunnel and its MTU go with
// the adapter when the device closes.
//
// Only numbers and addresses are read from these tools: their words depend
// on the system's language, and so do their error messages, which is why
// nothing here looks at an error's text. When a command fails, the routing
// table says what happened.

const (
	netshCmd = "netsh"
	regCmd   = "reg"
)

func netshFamily(v4 bool) string {
	if v4 {
		return "ipv4"
	}
	return "ipv6"
}

// netsh builds a step's command: netsh interface <family> args...
func netsh(v4 bool, args ...string) Step {
	return command(netshCmd, append([]string{"interface", netshFamily(v4)}, args...)...)
}

func netshUndo(v4 bool, args ...string) *Step {
	s := netsh(v4, args...)
	return &s
}

// netshAddrKey is the keyword that names the interface in add address: the
// two families of netsh differ.
func netshAddrKey(v4 bool) string {
	if v4 {
		return "name="
	}
	return "interface="
}

// planFamilies says which address families p uses.
func planFamilies(p Plan) (v4, v6 bool) {
	for _, a := range p.Addresses {
		v4, v6 = v4 || a.Addr().Is4(), v6 || !a.Addr().Is4()
	}
	for _, r := range p.Routes {
		v4, v6 = v4 || r.Addr().Is4(), v6 || !r.Addr().Is4()
	}
	return v4, v6
}

// planWindows: the MTU first, then the addresses, whose connected routes
// Windows adds by itself, then the routes. IPv6 neighbour discovery on the
// tunnel would only delay the addresses (duplicate address detection) and
// has no routers to find. As on macOS, default routes are left to the
// full-tunnel plan, and so is a route that is exactly one of a full tunnel's
// endpoints.
func planWindows(p Plan) []step {
	iface := p.Iface
	v4, v6 := planFamilies(p)
	var out []step
	for _, f := range []struct {
		on, v4 bool
	}{{v4, true}, {v6, false}} {
		if f.on && p.MTU > 0 {
			out = append(out, step{do: netsh(f.v4, "set", "subinterface", "interface="+iface, "mtu="+strconv.Itoa(p.MTU), "store=active")})
		}
	}
	if v6 {
		out = append(out, step{do: netsh(false, "set", "interface", "interface="+iface, "dadtransmits=0", "routerdiscovery=disabled", "store=active")})
	}
	connected := map[netip.Prefix]bool{}
	for _, a := range p.Addresses {
		is4 := a.Addr().Is4()
		key := netshAddrKey(is4) + iface
		out = append(out, step{
			do:   netsh(is4, "add", "address", key, "address="+a.String(), "store=active"),
			undo: netshUndo(is4, "delete", "address", key, "address="+a.Addr().String(), "store=active"),
		})
		connected[a.Masked()] = true
	}
	dv4, dv6 := defaultFamilies(p.Routes)
	endpoints := capturedEndpoints(p.Endpoints, dv4, dv6)
	for _, r := range p.Routes {
		r = r.Masked()
		if connected[r] || r.Bits() == 0 || (r.IsSingleIP() && slices.Contains(endpoints, r.Addr())) {
			continue
		}
		out = append(out, windowsIfaceRoute(r, iface))
	}
	return out
}

// windowsIfaceRoute is an on-link route through the tunnel. Its undo is not
// persistent: the route goes with the adapter.
func windowsIfaceRoute(r netip.Prefix, iface string) step {
	is4 := r.Addr().Is4()
	args := []string{"prefix=" + r.String(), "interface=" + iface, "store=active"}
	return step{
		do:   netsh(is4, append([]string{"add", "route"}, args...)...),
		undo: netshUndo(is4, append([]string{"delete", "route"}, args...)...),
	}
}

// netshRouteUndo recognises the undo of a route: netsh interface <family>
// delete route prefix=P ... and returns the prefix.
func netshRouteUndo(s Step) (netip.Prefix, bool) {
	a := s.Args
	if s.Name != netshCmd || len(a) < 5 || a[0] != "interface" || a[2] != "delete" || a[3] != "route" {
		return netip.Prefix{}, false
	}
	v, ok := strings.CutPrefix(a[4], "prefix=")
	if !ok {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(v)
	return p, err == nil
}

// windowsUndoOurs says whether a Windows undo step still has something to
// do. An undo that outlives the tunnel (an endpoint route, an NRPT rule) is
// retried until it worked, and "not found" cannot be told from any other
// failure, so a step whose target is gone must count as done or it would be
// retried for ever. Looking is cheap and a failed look lets the step run.
func windowsUndoOurs(ctx context.Context, r Runner, s Step) bool {
	if !s.Persistent {
		return true
	}
	switch s.Name {
	case regCmd:
		if len(s.Args) < 2 || s.Args[0] != "delete" {
			return true
		}
		_, err := r.Run(ctx, regCmd, []string{"query", s.Args[1]}, nil)
		return err == nil
	case netshCmd:
		p, ok := netshRouteUndo(s)
		if !ok {
			return true
		}
		routes, err := readWindowsRoutes(ctx, r, p.Addr().Is4())
		if err != nil {
			return true
		}
		return slices.ContainsFunc(routes, func(w winRoute) bool { return w.prefix == p })
	}
	return true
}

// windowsRouteFailed explains a failed route add: a route to that prefix
// that exists already belongs to somebody else (Cleanup ran before Apply),
// and is left alone like on macOS; anything else is the error.
func windowsRouteFailed(ctx context.Context, r Runner, do Step, err error) error {
	p, ok := hostRouteDst(do)
	if !ok {
		return err
	}
	routes, rerr := readWindowsRoutes(ctx, r, p.Addr().Is4())
	if rerr != nil || !slices.ContainsFunc(routes, func(w winRoute) bool { return w.prefix == p }) {
		return err
	}
	log.Printf("netcfg: %s: a route to the endpoint exists already; leaving it alone", do)
	return nil
}
