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
	"time"

	"github.com/Kodviva/latchwire/internal/msg"
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

// routeInfo is what `route -n get` prints about the route it found. mask
// is "" for a host route.
type routeInfo struct {
	dst, mask, gateway, iface string
	flags                     []string
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
		case "mask":
			ri.mask = v
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

// prefix returns the destination of the route found as a prefix of the
// family (v4 or not), or false when the output cannot be read as one.
// route(8) prints the zero address as "default"; a missing mask means a
// host route.
func (ri routeInfo) prefix(v4 bool) (netip.Prefix, bool) {
	zero := netip.IPv6Unspecified()
	if v4 {
		zero = netip.IPv4Unspecified()
	}
	addr := func(v string) (netip.Addr, bool) {
		if v == "default" {
			return zero, true
		}
		a, err := netip.ParseAddr(v)
		return a, err == nil && a.Is4() == v4 && a.Zone() == ""
	}
	d, ok := addr(ri.dst)
	if !ok {
		return netip.Prefix{}, false
	}
	bits := d.BitLen()
	if ri.mask != "" {
		m, ok := addr(ri.mask)
		if !ok {
			return netip.Prefix{}, false
		}
		if bits, ok = maskBits(m); !ok {
			return netip.Prefix{}, false
		}
	}
	p, err := d.Prefix(bits)
	return p, err == nil && p.Addr() == d
}

// maskBits returns the length of a contiguous netmask.
func maskBits(m netip.Addr) (int, bool) {
	n, ones := 0, true
	for _, b := range m.AsSlice() {
		for i := 7; i >= 0; i-- {
			set := b&(1<<i) != 0
			switch {
			case set && !ones:
				return 0, false
			case set:
				n++
			default:
				ones = false
			}
		}
	}
	return n, true
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
// the destination and the gateway it was added with (the loopback address
// for a blackhole route).
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

// ifaceRouteUndo recognises the undo of a route bound to an interface
// (route -q -n delete -inet|-inet6 P -interface IFACE) and returns its
// prefix and interface.
func ifaceRouteUndo(s Step) (p netip.Prefix, iface string, ok bool) {
	a := s.Args
	if s.Name != "route" || len(a) != 7 || a[0] != "-q" || a[1] != "-n" || a[2] != "delete" || a[5] != "-interface" {
		return
	}
	p, err := netip.ParsePrefix(a[4])
	if err != nil || family(p) != a[3] || p != p.Masked() {
		return netip.Prefix{}, "", false
	}
	return p, a[6], true
}

// undoTargetOurs reports whether the route an undo step deletes is still
// the one Latchwire added. macOS matches a route delete by destination
// only (the -gateway and -interface arguments do not narrow it), so a bare
// delete could remove a route that somebody else has put there since, such
// as another VPN's 0.0.0.0/1 after a crash. The route found by `route -n
// get` must have the same prefix and, for an endpoint host route, the same
// gateway (and blackhole flag) or, for an interface route, the same
// interface. A different prefix means ours is gone; output that cannot be
// read leaves the route in place: a leak is safer than deleting another
// tool's route. scutil DNS steps are checked by scutilUndoOurs; other
// steps are not checked.
func undoTargetOurs(ctx context.Context, r Runner, s Step) (bool, error) {
	if s.Name == scutilCmd {
		return scutilUndoOurs(ctx, r, s)
	}
	if s.Name == netshCmd || s.Name == regCmd {
		return windowsUndoOurs(ctx, r, s), nil
	}
	var (
		want  netip.Prefix
		query string
		match func(routeInfo) bool
	)
	if dst, gw, ok := hostRouteUndo(s); ok {
		want, query = netip.PrefixFrom(dst, dst.BitLen()), dst.String()
		blackhole := slices.Contains(s.Args, "-blackhole")
		match = func(ri routeInfo) bool {
			g, err := netip.ParseAddr(ri.gateway)
			return err == nil && g == gw && slices.Contains(ri.flags, "BLACKHOLE") == blackhole
		}
	} else if p, iface, ok := ifaceRouteUndo(s); ok {
		want, query = p, p.String()
		match = func(ri routeInfo) bool { return ri.iface == iface }
	} else {
		return true, nil
	}
	ri, found, err := routeGet(ctx, r, []string{"-n", "get", family(want), query})
	if err != nil {
		return false, fmt.Errorf("route -n get %s: %w", query, err)
	}
	if !found {
		return false, nil
	}
	got, ok := ri.prefix(want.Addr().Is4())
	switch {
	case !ok:
		log.Printf("netcfg: %s: cannot read the route in place for %s; leaving it alone", s, query)
		return false, nil
	case got != want:
		return false, nil // gone: a covering route answered
	case !match(ri):
		log.Printf("netcfg: %s: the route in place for %s is not the one Latchwire added; leaving it alone", s, query)
		return false, nil
	}
	return true, nil
}

// runUndo runs one undo step. An undo whose target is already gone, or is
// no longer ours (undoTargetOurs), succeeded (see also alreadyUndone).
func runUndo(ctx context.Context, r Runner, s Step) error {
	ours, err := undoTargetOurs(ctx, r, s)
	if err != nil {
		return err
	}
	if !ours {
		return nil
	}
	if err := runStep(ctx, r, s); err != nil && !alreadyUndone(s, err) {
		return fmt.Errorf("%s: %w", s, err)
	}
	return nil
}

// existingHostRoute decides what to do when adding the endpoint host route
// do failed because a route to the endpoint exists already. A route into
// the tunnel interface own would make the endpoint unreachable: that is an
// error. A blackhole route to exactly the endpoint is stale (a lost
// journal, a leaked undo): it is deleted and retry is set, so do runs
// again and the route becomes ours. Anything else (another gateway,
// another VPN's interface) belongs to somebody else and is left alone.
func existingHostRoute(ctx context.Context, r Runner, do Step, own string) (retry bool, err error) {
	dst, err := netip.ParseAddr(do.Args[4])
	if err != nil {
		return false, err
	}
	fam := addrFamily(dst)
	ri, found, err := routeGet(ctx, r, []string{"-n", "get", fam, dst.String()})
	if err != nil {
		return false, fmt.Errorf("route -n get %s: %w", dst, err)
	}
	if !found {
		return true, nil // gone meanwhile
	}
	p, ok := ri.prefix(dst.Is4())
	switch {
	case ri.iface == own:
		return false, fmt.Errorf(msg.NetEndpointRouteLoopFmt, dst, own)
	case ok && p.Bits() == dst.BitLen() && p.Addr() == dst && slices.Contains(ri.flags, "BLACKHOLE"):
		del := command("route", "-q", "-n", "delete", fam, dst.String(), loopback(dst), "-blackhole")
		log.Printf("netcfg: replacing a stale blackhole route to the endpoint %s", dst)
		if _, err := r.Run(ctx, del.Name, del.Args, nil); err != nil && !alreadyUndone(del, err) {
			return false, fmt.Errorf("%s: %w", del, err)
		}
		return true, nil
	}
	log.Printf("netcfg: %s: a route to the endpoint exists already (interface %s); leaving it alone", do, ri.iface)
	return false, nil
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
	// fam says which families the tunnel uses (Windows sets the MTU per
	// family).
	fam [2]bool
	// failGW is the gateway a move to failed at failAt (failed set): it
	// is not tried again before moveBackoff.
	failed [2]bool
	failGW [2]netip.Addr
	failAt [2]time.Time
	// The DNS that follows the primary service (darwinplan_dns.go).
	dnsFollow
}

// moveBackoff is how long a failed move of the endpoint routes to one
// gateway is not retried, unless the gateway changes again. Without it a
// move that keeps failing would retry on every network event (P9).
const moveBackoff = 30 * time.Second

// gwString names a gateway for messages.
func gwString(gw netip.Addr) string {
	if !gw.IsValid() {
		return "none (blackhole)"
	}
	return gw.String()
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
		now := c.clock()
		if d.failed[f] && d.failGW[f] == h.gw && now.Sub(d.failAt[f]) < moveBackoff {
			continue
		}
		if err := c.moveEndpointRoutesLocked(ctx, f, h.gw); err != nil {
			d.failed[f], d.failGW[f], d.failAt[f] = true, h.gw, now
			log.Printf("netcfg: %s: moving the endpoint routes to gateway %s failed (retried at the first network check after %v, which the daemon makes every 30 s and at network changes, or at once when the gateway changes): %v",
				d.iface, gwString(h.gw), moveBackoff, err)
			errs = append(errs, err)
		} else {
			d.failed[f] = false
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
	if d.dnsPrimary {
		if err := c.refreshDNSLocked(ctx); err != nil {
			errs = append(errs, err)
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

// clock returns the current time (c.now in tests).
func (c *configurer) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}
