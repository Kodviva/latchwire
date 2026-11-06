package netcfg

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// A Windows full tunnel works like a macOS one: the default routes stay,
// the halves of the address space (0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1)
// go on the tunnel and win by being more specific, and each endpoint of a
// captured family gets a host route out through the default route, which
// Refresh moves when the network changes. See darwinplan_fulltunnel.go.
//
// A host route names its interface by index: physical interface names are
// the user's and hold spaces and any language. Without a default route the
// endpoint gets a route on the loopback interface (always index 1), so its
// packets are dropped rather than looping into the tunnel; Windows has no
// blackhole route as such.

// windowsLoopbackIndex is the index of the loopback pseudo-interface.
const windowsLoopbackIndex = "1"

func newWindows(r Runner, j *Journal) Configurer {
	c := newConfigurer(r, j, planWindows, nil)
	c.full = c.windowsFullTunnel
	c.refresh = c.refreshWindows
	c.dns = windowsDNS
	c.ifaces = systemIfaces
	return c
}

// planWindowsEndpointRoutes returns a host route for each endpoint through
// the next hop of its family. An endpoint that is its own gateway is on the
// local network and needs none.
func planWindowsEndpointRoutes(endpoints []netip.Addr, hops [2]nextHop) []step {
	var out []step
	for _, ep := range endpoints {
		hop := hops[famIndex(ep)]
		if hop.gw.IsValid() && hop.gw.WithZone("") == ep {
			continue
		}
		is4 := ep.Is4()
		idx := hop.iface
		if idx == "" {
			idx = windowsLoopbackIndex
		}
		args := []string{"prefix=" + netip.PrefixFrom(ep, ep.BitLen()).String(), "interface=" + idx}
		if hop.gw.IsValid() && hop.iface != "" {
			args = append(args, "nexthop="+hop.gw.WithZone("").String())
		}
		args = append(args, "store=active")
		undo := netshUndo(is4, append([]string{"delete", "route"}, args...)...)
		undo.Persistent = true
		out = append(out, step{
			do:        netsh(is4, append([]string{"add", "route"}, args...)...),
			undo:      undo,
			hostRoute: true,
			onFail:    windowsRouteFailed,
		})
	}
	return out
}

// planWindowsFullTunnel returns the endpoints' host routes, then the /1
// routes on iface. endpoints must already be limited to the captured
// families.
func planWindowsFullTunnel(iface string, v4, v6 bool, endpoints []netip.Addr, hops [2]nextHop) []step {
	out := planWindowsEndpointRoutes(endpoints, hops)
	for _, f := range []struct {
		on     bool
		halves []string
	}{{v4, []string{"0.0.0.0/1", "128.0.0.0/1"}}, {v6, []string{"::/1", "8000::/1"}}} {
		if !f.on {
			continue
		}
		for _, h := range f.halves {
			out = append(out, windowsIfaceRoute(netip.MustParsePrefix(h), iface))
		}
	}
	return out
}

// hostRouteDst returns the prefix of a netsh add route command.
func hostRouteDst(s Step) (netip.Prefix, bool) {
	for _, a := range s.Args {
		if v, ok := strings.CutPrefix(a, "prefix="); ok {
			p, err := netip.ParsePrefix(v)
			return p, err == nil
		}
	}
	return netip.Prefix{}, false
}

// windowsFullTunnel is the Windows fullPlanner. An unknown default route at
// connect time gets the loopback route (fail closed); Refresh fixes it once
// the network is known. c.mu is held.
func (c *configurer) windowsFullTunnel(ctx context.Context, r Runner, p Plan) ([]step, uint32, error) {
	v4, v6 := defaultFamilies(p.Routes)
	eps := capturedEndpoints(p.Endpoints, v4, v6)
	var hops [2]nextHop
	for _, ep := range eps {
		f := famIndex(ep)
		if len(c.dn.eps[f]) == 0 {
			if h, _, ok := windowsDefaultRoute(ctx, r, f == 0, p.Iface, c.ifaces); ok {
				hops[f] = h
			}
		}
		c.dn.eps[f] = append(c.dn.eps[f], ep)
	}
	c.dn.gw = [2]netip.Addr{hops[0].gw, hops[1].gw}
	c.dn.phys = [2]string{hops[0].iface, hops[1].iface}
	return planWindowsFullTunnel(p.Iface, v4, v6, eps, hops), 0, nil
}

// refreshWindows moves the endpoint host routes when a family's next hop
// changed and sets the interface MTU when the automatic MTU changed. When
// neither changed it only reads (P9). c.mu is held and something is applied.
func (c *configurer) refreshWindows(ctx context.Context) error {
	d := &c.dn
	var errs []error
	path := 0
	for f := range 2 {
		h, mtu, ok := windowsDefaultRoute(ctx, c.run, f == 0, d.iface, c.ifaces)
		if !ok {
			continue
		}
		if mtu > 0 && path == 0 {
			path = mtu
		}
		if len(d.eps[f]) == 0 || (h.gw == d.gw[f] && h.iface == d.phys[f]) {
			continue
		}
		now := c.clock()
		if d.failed[f] && d.failGW[f] == h.gw && now.Sub(d.failAt[f]) < moveBackoff {
			continue
		}
		if err := c.moveWindowsRoutesLocked(ctx, f, h); err != nil {
			d.failed[f], d.failGW[f], d.failAt[f] = true, h.gw, now
			log.Printf("netcfg: %s: moving the endpoint routes to gateway %s failed: %v", d.iface, gwString(h.gw), err)
			errs = append(errs, err)
		} else {
			d.failed[f] = false
		}
	}
	if d.mtuAuto {
		// No path MTU: offline, keep the MTU rather than flap.
		if mtu := tunnelMTU(path); path > 0 && mtu != d.mtu {
			if err := c.setWindowsMTULocked(ctx, mtu); err != nil {
				errs = append(errs, err)
			} else {
				d.mtu = mtu
			}
		}
	}
	return errors.Join(errs...)
}

func (c *configurer) setWindowsMTULocked(ctx context.Context, mtu int) error {
	var errs []error
	for _, v4 := range []bool{true, false} {
		if !c.dn.fam[famIndexOf(v4)] {
			continue
		}
		if err := c.exec(ctx, netsh(v4, "set", "subinterface", "interface="+c.dn.iface, "mtu="+strconv.Itoa(mtu), "store=active")); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func famIndexOf(v4 bool) int {
	if v4 {
		return 0
	}
	return 1
}

// moveWindowsRoutesLocked replaces family f's endpoint host routes with
// routes through h, like moveEndpointRoutesLocked: each old route is
// deleted and forgotten, each new undo journaled before its route is added.
// The next hop is the state only when every step succeeded.
func (c *configurer) moveWindowsRoutesLocked(ctx context.Context, f int, h nextHop) error {
	var errs []error
	for i := len(c.applied) - 1; i >= 0; i-- {
		s := c.applied[i]
		if !s.hostRoute {
			continue
		}
		p, ok := hostRouteDst(s.do)
		if !ok || famIndex(p.Addr()) != f {
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
	var hops [2]nextHop
	hops[f] = h
	for _, s := range planWindowsEndpointRoutes(c.dn.eps[f], hops) {
		if _, err := c.applyStepLocked(ctx, s); err != nil {
			if jerr := c.recordLocked(); jerr != nil {
				err = errors.Join(err, jerr)
			}
			return err
		}
	}
	c.dn.gw[f], c.dn.phys[f] = h.gw, h.iface
	return nil
}
