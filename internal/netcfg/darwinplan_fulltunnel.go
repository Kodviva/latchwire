package netcfg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// A macOS full tunnel never replaces the default route: for each family with
// a default route in the plan it adds the two halves of the address space
// (0.0.0.0/1 and 128.0.0.0/1, ::/1 and 8000::/1) on the tunnel interface,
// which win over the default route by being more specific and vanish with
// the interface.
//
// The tunnel's own packets to its endpoints must not follow them, so each
// endpoint of a captured family gets a host route through the default
// route's gateway. Such a route outlives the interface (it is Persistent,
// P7) and must follow the gateway when the network changes: Refresh moves
// it. Without a gateway the endpoint gets a blackhole route instead, so
// its packets are dropped rather than looping into the tunnel.

// loopback is the blackhole route's nominal gateway per family.
func loopback(a netip.Addr) string {
	if a.Is4() {
		return "127.0.0.1"
	}
	return "::1"
}

func addrFamily(a netip.Addr) string {
	if a.Is4() {
		return "-inet"
	}
	return "-inet6"
}

// famIndex is the index of a's family in per-family arrays (0 IPv4, 1 IPv6).
func famIndex(a netip.Addr) int {
	if a.Is4() {
		return 0
	}
	return 1
}

// planDarwinEndpointRoutes returns a host route for each endpoint through
// the gateway of its family (gw4, gw6), or a blackhole route when that
// gateway is invalid. An endpoint that is its own gateway is on the local
// network and needs none.
func planDarwinEndpointRoutes(endpoints []netip.Addr, gw4, gw6 netip.Addr) []step {
	var out []step
	for _, ep := range endpoints {
		gw := gw4
		if !ep.Is4() {
			gw = gw6
		}
		fam, ip := addrFamily(ep), ep.String()
		var s step
		switch {
		case gw.IsValid() && gw.WithZone("") == ep:
			continue
		case gw.IsValid():
			s = step{
				do:   command("route", "-q", "-n", "add", fam, ip, "-gateway", gw.String()),
				undo: persistentUndo("route", "-q", "-n", "delete", fam, ip, "-gateway", gw.String()),
			}
		default:
			s = step{
				do:   command("route", "-q", "-n", "add", fam, ip, loopback(ep), "-blackhole"),
				undo: persistentUndo("route", "-q", "-n", "delete", fam, ip, loopback(ep), "-blackhole"),
			}
		}
		s.hostRoute = true
		out = append(out, s)
	}
	return out
}

// planDarwinFullTunnel returns the steps of a full tunnel on iface for the
// families v4/v6: the endpoints' host routes first, then the /1 routes.
// endpoints must already be limited to the captured families.
func planDarwinFullTunnel(iface string, v4, v6 bool, endpoints []netip.Addr, gw4, gw6 netip.Addr) []step {
	out := planDarwinEndpointRoutes(endpoints, gw4, gw6)
	for _, f := range []struct {
		on     bool
		halves []string
	}{{v4, []string{"0.0.0.0/1", "128.0.0.0/1"}}, {v6, []string{"::/1", "8000::/1"}}} {
		if !f.on {
			continue
		}
		for _, h := range f.halves {
			r := netip.MustParsePrefix(h)
			out = append(out, step{
				do:   command("route", "-q", "-n", "add", family(r), h, "-interface", iface),
				undo: undoOf("route", "-q", "-n", "delete", family(r), h, "-interface", iface),
			})
		}
	}
	return out
}

// capturedEndpoints returns the distinct endpoint addresses whose family the
// full tunnel captures.
func capturedEndpoints(eps []netip.AddrPort, v4, v6 bool) []netip.Addr {
	var out []netip.Addr
	for _, ep := range eps {
		a := ep.Addr().Unmap()
		if !a.IsValid() || (a.Is4() && !v4) || (a.Is6() && !v6) || slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// routeInfo is what `route -n get` prints about the route it found.
type routeInfo struct {
	dst, gateway, iface string
	flags               []string
}

// parseRouteGet reads `route -n get` output (C locale): "key: value" lines.
func parseRouteGet(out string) routeInfo {
	var ri routeInfo
	for line := range strings.Lines(out) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "destination":
			ri.dst = v
		case "gateway":
			ri.gateway = v
		case "interface":
			ri.iface = v
		case "flags":
			v = strings.TrimSuffix(strings.TrimPrefix(v, "<"), ">")
			if v != "" {
				ri.flags = strings.Split(v, ",")
			}
		}
	}
	return ri
}

// gatewayAddr returns the route's gateway as an address of the family
// (4 or 6), or the invalid address when it is none (link#N, a link-layer
// address, a zone that is not an interface name).
func (ri routeInfo) gatewayAddr(v4 bool) netip.Addr {
	a, err := netip.ParseAddr(ri.gateway)
	if err != nil || a.Is4() != v4 || (a.Zone() != "" && !ifaceName(a.Zone())) {
		return netip.Addr{}
	}
	return a
}

// notInTable reports whether err from route(8) says that no such route
// exists (ESRCH; ExecRunner fixes the C locale).
func notInTable(err error) bool {
	return strings.Contains(err.Error(), "not in table")
}

// routeExists reports whether err from "route add" says that the route is
// there already (EEXIST).
func routeExists(err error) bool {
	return strings.Contains(err.Error(), "File exists")
}

// nextHop is the default route of one family: its gateway (invalid: none,
// so the endpoints get blackhole routes) and its interface ("" unknown).
type nextHop struct {
	gw    netip.Addr
	iface string
}

// darwinDefaultRoute reads the default route of one family. own is the
// tunnel's interface and phys the physical interface last seen.
//
// When the default route points at the tunnel itself (something made the
// tunnel the primary interface), it says nothing about the network outside:
// the physical interface's scoped default route (route get -ifscope) is read
// instead. That scoped route is what the system really uses, so it is
// preferred over remembering the gateway from connect time, which would go
// stale on a network change. Without a known physical interface the result
// is unknown (ok false), and so is a failed lookup other than "no default
// route", which is a known absence.
func darwinDefaultRoute(ctx context.Context, r Runner, v4 bool, own, phys string) (nextHop, bool) {
	args := []string{"-n", "get"}
	if !v4 {
		args = append(args, "-inet6")
	}
	ri, ok, err := routeGet(ctx, r, append(slices.Clone(args), "default"))
	if err != nil || !ok {
		return nextHop{}, err == nil
	}
	if ri.iface == own {
		if phys == "" {
			return nextHop{}, false
		}
		ri, ok, err = routeGet(ctx, r, append(args, "-ifscope", phys, "default"))
		if err != nil || ri.iface == own {
			return nextHop{}, false
		}
		if !ok {
			return nextHop{iface: phys}, true
		}
	}
	h := nextHop{gw: ri.gatewayAddr(v4)}
	if ifaceName(ri.iface) {
		h.iface = ri.iface
	}
	return h, true
}

// routeGet runs `route args` and parses the route found; ok is false (and
// err nil) when there is no such route.
func routeGet(ctx context.Context, r Runner, args []string) (routeInfo, bool, error) {
	out, err := r.Run(ctx, "route", args, nil)
	if err != nil {
		if notInTable(err) {
			return routeInfo{}, false, nil
		}
		return routeInfo{}, false, err
	}
	return parseRouteGet(string(out)), true, nil
}

// hostRouteUndo recognises the undo of an endpoint host route and returns
// the destination, the gateway it was added with and whether it is a
// blackhole route.
func hostRouteUndo(s Step) (dst, gw netip.Addr, ok bool) {
	a := s.Args
	if s.Name != "route" || len(a) != 7 || a[0] != "-q" || a[1] != "-n" || a[2] != "delete" {
		return
	}
	var err error
	if dst, err = netip.ParseAddr(a[4]); err != nil || addrFamily(dst) != a[3] {
		return
	}
	switch {
	case a[5] == "-gateway":
		gw, err = netip.ParseAddr(a[6])
	case a[6] == "-blackhole":
		gw, err = netip.ParseAddr(a[5])
	default:
		return
	}
	return dst, gw, err == nil
}

// ownsHostRoute reports whether the route found for dst is the host route
// to dst through gw (a blackhole route when blackhole is set).
func ownsHostRoute(ri routeInfo, dst, gw netip.Addr, blackhole bool) bool {
	d, err := netip.ParseAddr(ri.dst)
	if err != nil || d != dst {
		return false
	}
	g, err := netip.ParseAddr(ri.gateway)
	return err == nil && g == gw && slices.Contains(ri.flags, "BLACKHOLE") == blackhole
}

// runUndo runs one undo step. An undo whose target is already gone
// succeeded (see alreadyUndone). Before deleting an endpoint host route it
// checks that the route is still the one that was added: macOS matches a
// delete by destination only, so the delete alone could remove a route that
// somebody else has put there since; such a route is left alone.
func runUndo(ctx context.Context, r Runner, s Step) error {
	if dst, gw, ok := hostRouteUndo(s); ok {
		ri, found, err := routeGet(ctx, r, []string{"-n", "get", addrFamily(dst), dst.String()})
		if err != nil {
			return fmt.Errorf("route -n get %s: %w", dst, err)
		}
		if !found || !ownsHostRoute(ri, dst, gw, slices.Contains(s.Args, "-blackhole")) {
			return nil
		}
	}
	if _, err := r.Run(ctx, s.Name, s.Args, s.Stdin); err != nil && !alreadyUndone(s, err) {
		return fmt.Errorf("%s: %w", s, err)
	}
	return nil
}

// darwinFollow is what a macOS configurer keeps for Refresh.
type darwinFollow struct {
	iface   string
	mtu     int  // current interface MTU
	mtuAuto bool // the MTU follows the network
	// Per family (0 IPv4, 1 IPv6): the endpoints with host routes, the
	// gateway they use (invalid: blackhole) and the physical interface
	// last seen.
	eps  [2][]netip.Addr
	gw   [2]netip.Addr
	phys [2]string
}

// darwinFullTunnel is the macOS fullPlanner: it reads the default route of
// each captured family that has endpoints. An unknown default route at
// connect time gets the blackhole (fail closed); Refresh fixes it once the
// network is known. c.mu is held.
func (c *configurer) darwinFullTunnel(ctx context.Context, r Runner, p Plan) ([]step, uint32, error) {
	v4, v6 := defaultFamilies(p.Routes)
	eps := capturedEndpoints(p.Endpoints, v4, v6)
	var gw [2]netip.Addr
	for _, ep := range eps {
		f := famIndex(ep)
		if len(c.dn.eps[f]) == 0 {
			if h, ok := darwinDefaultRoute(ctx, r, f == 0, p.Iface, ""); ok {
				gw[f], c.dn.phys[f] = h.gw, h.iface
			}
		}
		c.dn.eps[f] = append(c.dn.eps[f], ep)
	}
	c.dn.gw = gw
	return planDarwinFullTunnel(p.Iface, v4, v6, eps, gw[0], gw[1]), 0, nil
}

// refreshDarwin moves the endpoint host routes when a family's gateway
// changed and sets the interface MTU when the automatic MTU changed. When
// neither changed it only reads (P9: the route events of its own changes
// must not make it change again). c.mu is held and something is applied.
func (c *configurer) refreshDarwin(ctx context.Context) error {
	d := &c.dn
	var (
		hop   [2]nextHop
		known [2]bool
		read  [2]bool
	)
	look := func(f int) (nextHop, bool) {
		if !read[f] {
			read[f] = true
			hop[f], known[f] = darwinDefaultRoute(ctx, c.run, f == 0, d.iface, d.phys[f])
			if known[f] && hop[f].iface != "" {
				d.phys[f] = hop[f].iface
			}
		}
		return hop[f], known[f]
	}
	var errs []error
	for f := range 2 {
		if len(d.eps[f]) == 0 {
			continue
		}
		h, ok := look(f)
		if !ok || h.gw == d.gw[f] {
			continue
		}
		if err := c.moveEndpointRoutesLocked(ctx, f, h.gw); err != nil {
			errs = append(errs, err)
		}
	}
	if d.mtuAuto {
		phys := ""
		for f := range 2 {
			if h, ok := look(f); ok && h.iface != "" {
				phys = h.iface
				break
			}
		}
		// No physical interface or no MTU: offline, keep the MTU
		// rather than flap to the fallback and back.
		path := 0
		if phys != "" {
			path = ifaceMTU(ctx, c.run, "ifconfig", phys)
		}
		if mtu := tunnelMTU(path); path > 0 && mtu != d.mtu {
			if err := c.exec(ctx, command("ifconfig", d.iface, "mtu", strconv.Itoa(mtu))); err != nil {
				errs = append(errs, err)
			} else {
				d.mtu = mtu
			}
		}
	}
	return errors.Join(errs...)
}

// moveEndpointRoutesLocked replaces family f's endpoint host routes with
// routes through gw. Each old route is deleted, then forgotten in the
// journal; each new undo is journaled before its route is added. A route
// that fails to move is retried by the next Refresh: the gateway is only
// taken as the state when every step succeeded.
func (c *configurer) moveEndpointRoutesLocked(ctx context.Context, f int, gw netip.Addr) error {
	var errs []error
	for i := len(c.applied) - 1; i >= 0; i-- {
		s := c.applied[i]
		if !s.hostRoute || famIndex(mustHostRouteDst(s)) != f {
			continue
		}
		if err := runUndo(ctx, c.run, *s.undo); err != nil {
			errs = append(errs, err)
			continue
		}
		c.applied = slices.Delete(c.applied, i, i+1)
		if err := c.recordLocked(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	for _, s := range planDarwinEndpointRoutes(c.dn.eps[f], gw, gw) {
		if _, err := c.applyStepLocked(ctx, s); err != nil {
			// Its undo must not stay journaled: the route is not there.
			if jerr := c.recordLocked(); jerr != nil {
				err = errors.Join(err, jerr)
			}
			return err
		}
	}
	c.dn.gw[f] = gw
	return nil
}

// mustHostRouteDst returns the destination of a host route step.
func mustHostRouteDst(s step) netip.Addr {
	a, _ := netip.ParseAddr(s.do.Args[4])
	return a
}

// logExistingRoute says that an endpoint already had a host route, which is
// then left as it is.
func logExistingRoute(s Step) {
	log.Printf("netcfg: %s: a route to the endpoint exists already; leaving it alone", s)
}
