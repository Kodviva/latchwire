package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Errors as ExecRunner reports them (C locale, stderr appended).
var (
	errNotInTable = errors.New("exit status 1: route: writing to routing socket: not in table")
	errExists     = errors.New("exit status 1: route: writing to routing socket: File exists")
)

// defaultVia is `route -n get [-inet6] default` output for a default route
// through gw on iface.
func defaultVia(gw, iface string) string {
	return fmt.Sprintf(`   route to: default
destination: default
       mask: default
    gateway: %s
  interface: %s
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`, gw, iface)
}

// hostVia is `route -n get -inet IP` output for a host route to dst via gw.
func hostVia(dst, gw, iface, flags string) string {
	return fmt.Sprintf(`   route to: %s
destination: %s
    gateway: %s
  interface: %s
      flags: <%s>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`, dst, dst, gw, iface, flags)
}

const hostFlags = "UP,GATEWAY,HOST,DONE,STATIC"

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, v := range s {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

// hostRouteUndos returns the journaled undo steps of endpoint host routes,
// persistent ones marked with "P ".
func hostRouteUndos(j *Journal, owner string) []string {
	var out []string
	for _, s := range j.Entries()[owner] {
		if slices.Contains(s.Args, "-gateway") || slices.Contains(s.Args, "-blackhole") {
			p := "  "
			if s.Persistent {
				p = "P "
			}
			out = append(out, p+s.String())
		}
	}
	return out
}

func TestDarwinFullTunnelSplitsDefault(t *testing.T) {
	r := &recorder{}
	j, _ := newJournal(t)
	a, err := newDarwin(r, j).Apply(ctx, plan("utun7", pfx("10.0.0.2/32", "fd00::2/128"), pfx("0.0.0.0/0", "::/0")))
	if err != nil {
		t.Fatal(err)
	}
	if want := (Applied{FullTunnel: true}); a != want {
		t.Errorf("Applied = %+v, want %+v", a, want)
	}
	// No endpoint: nothing to look up, no host route.
	want := []string{
		"ifconfig utun7 inet 10.0.0.2 10.0.0.2 alias",
		"ifconfig utun7 inet6 fd00::2 prefixlen 128 alias",
		"route -q -n add -inet 0.0.0.0/1 -interface utun7",
		"route -q -n add -inet 128.0.0.0/1 -interface utun7",
		"route -q -n add -inet6 ::/1 -interface utun7",
		"route -q -n add -inet6 8000::/1 -interface utun7",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	// The /1 routes go with the interface: not persistent.
	_, undo := render(planDarwinFullTunnel("utun7", true, true, nil, netip.Addr{}, netip.Addr{}))
	wantUndo := []string{
		"  route -q -n delete -inet6 8000::/1 -interface utun7",
		"  route -q -n delete -inet6 ::/1 -interface utun7",
		"  route -q -n delete -inet 128.0.0.0/1 -interface utun7",
		"  route -q -n delete -inet 0.0.0.0/1 -interface utun7",
	}
	if !reflect.DeepEqual(undo, wantUndo) {
		t.Errorf("undo:\n%q\nwant:\n%q", undo, wantUndo)
	}
	// planDarwin itself never adds a default route.
	do, _ := render(planDarwin(plan("utun7", nil, pfx("0.0.0.0/0", "::/0", "10.0.0.0/24"))))
	if want := []string{"route -q -n add -inet 10.0.0.0/24 -interface utun7"}; !reflect.DeepEqual(do, want) {
		t.Errorf("planDarwin with /0: %q, want %q", do, want)
	}
}

func TestDarwinEndpointHostRoute(t *testing.T) {
	r := &recorder{out: map[string]string{"route -n get default": defaultVia("192.168.1.1", "en0")}}
	j, _ := newJournal(t)
	p := plan("utun7", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	// The IPv6 endpoint is not captured by an IPv4-only full tunnel; the
	// repeated address gets one route.
	p.Endpoints = eps("203.0.113.5:51820", "[2001:db8::5]:51820", "203.0.113.5:4500")
	if _, err := newDarwin(r, j).Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route -n get default",
		"ifconfig utun7 inet 10.0.0.2 10.0.0.2 alias",
		"route -q -n add -inet 203.0.113.5 -gateway 192.168.1.1",
		"route -q -n add -inet 0.0.0.0/1 -interface utun7",
		"route -q -n add -inet 128.0.0.0/1 -interface utun7",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	// The host route outlives the interface (P7).
	if got, want := hostRouteUndos(j, "utun7"), []string{"P route -q -n delete -inet 203.0.113.5 -gateway 192.168.1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("journal host routes %q, want %q", got, want)
	}

	// Both families, a link-local IPv6 gateway with its zone; an endpoint
	// that is the gateway itself needs no host route.
	do, undo := render(planDarwinFullTunnel("utun7", true, true,
		addrs("203.0.113.5", "2001:db8::5", "192.168.1.1"),
		netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fe80::1%en0")))
	wantDo := []string{
		"route -q -n add -inet 203.0.113.5 -gateway 192.168.1.1",
		"route -q -n add -inet6 2001:db8::5 -gateway fe80::1%en0",
		"route -q -n add -inet 0.0.0.0/1 -interface utun7",
		"route -q -n add -inet 128.0.0.0/1 -interface utun7",
		"route -q -n add -inet6 ::/1 -interface utun7",
		"route -q -n add -inet6 8000::/1 -interface utun7",
	}
	wantUndo := []string{
		"  route -q -n delete -inet6 8000::/1 -interface utun7",
		"  route -q -n delete -inet6 ::/1 -interface utun7",
		"  route -q -n delete -inet 128.0.0.0/1 -interface utun7",
		"  route -q -n delete -inet 0.0.0.0/1 -interface utun7",
		"P route -q -n delete -inet6 2001:db8::5 -gateway fe80::1%en0",
		"P route -q -n delete -inet 203.0.113.5 -gateway 192.168.1.1",
	}
	if !reflect.DeepEqual(do, wantDo) || !reflect.DeepEqual(undo, wantUndo) {
		t.Errorf("plan:\ndo   %q\nundo %q\nwant\ndo   %q\nundo %q", do, undo, wantDo, wantUndo)
	}

	// The IPv6 gateway comes from `route -n get -inet6 default`.
	r = &recorder{out: map[string]string{
		"route -n get default":        defaultVia("192.168.1.1", "en0"),
		"route -n get -inet6 default": defaultVia("fe80::1%en0", "en0"),
	}}
	p = plan("utun7", pfx("fd00::2/128"), pfx("::/0"))
	p.Endpoints = eps("[2001:db8::5]:51820", "203.0.113.5:51820")
	if _, err := newDarwin(r, nil).Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.cmds, "route -q -n add -inet6 2001:db8::5 -gateway fe80::1%en0") ||
		slices.Contains(r.cmds, "route -n get default") || slices.ContainsFunc(r.cmds, func(c string) bool { return strings.Contains(c, "203.0.113.5") }) {
		t.Errorf("IPv6-only full tunnel commands %q", r.cmds)
	}
}

// Without a usable gateway, packets to the endpoint are dropped rather than
// sent into the tunnel (where they would loop).
func TestDarwinEndpointBlackholeWithoutGateway(t *testing.T) {
	cases := map[string]*recorder{
		// No default route at all (offline).
		"none": {fail: map[string]error{
			"route -n get default":        errNotInTable,
			"route -n get -inet6 default": errNotInTable,
		}},
		// An interface route (another VPN, PPP): no gateway address.
		"link": {out: map[string]string{
			"route -n get default":        defaultVia("link#21", "utun3"),
			"route -n get -inet6 default": defaultVia("link#21", "utun3"),
		}},
		// The lookup itself failed: fail closed.
		"error": {fail: map[string]error{
			"route -n get default":        errors.New("signal: killed"),
			"route -n get -inet6 default": errors.New("signal: killed"),
		}},
	}
	for name, r := range cases {
		j, _ := newJournal(t)
		p := plan("utun7", pfx("10.0.0.2/32"), pfx("0.0.0.0/0", "::/0"))
		p.Endpoints = eps("203.0.113.5:51820", "[2001:db8::5]:51820")
		if _, err := newDarwin(r, j).Apply(ctx, p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range []string{
			"route -q -n add -inet 203.0.113.5 127.0.0.1 -blackhole",
			"route -q -n add -inet6 2001:db8::5 ::1 -blackhole",
		} {
			if !slices.Contains(r.cmds, c) {
				t.Errorf("%s: %q not run; commands %q", name, c, r.cmds)
			}
		}
		want := []string{
			"P route -q -n delete -inet 203.0.113.5 127.0.0.1 -blackhole",
			"P route -q -n delete -inet6 2001:db8::5 ::1 -blackhole",
		}
		if got := hostRouteUndos(j, "utun7"); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: journal %q, want %q", name, got, want)
		}
	}
}

// P9 and the main reason for Refresh: when the network changes, the
// endpoint's host route moves to the new gateway. The journal always holds
// what is in place: the new undo before the new route is added, the old
// one only until the old route is deleted.
func TestEndpointRouteFollowsGatewayChange(t *testing.T) {
	j, _ := newJournal(t)
	r := &recorder{out: map[string]string{"route -n get default": defaultVia("192.168.1.1", "en0")}}
	c := newDarwin(r, j)
	p := plan("utun7", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	p.Endpoints = eps("203.0.113.5:51820")
	if _, err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}

	// Nothing changed: Refresh only looks.
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := []string{"route -n get default"}; !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("unchanged Refresh ran %q, want %q", r.cmds, want)
	}

	r.out["route -n get default"] = defaultVia("10.0.0.1", "en1")
	r.out["route -n get -inet 203.0.113.5"] = hostVia("203.0.113.5", "192.168.1.1", "en0", hostFlags)
	r.cmds = nil
	var seen []string
	r.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, "route -q") {
			seen = append(seen, fmt.Sprintf("%s | %q", cmd, hostRouteUndos(j, "utun7")))
		}
	}
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route -n get default",
		"route -n get -inet 203.0.113.5",
		"route -q -n delete -inet 203.0.113.5 -gateway 192.168.1.1",
		"route -q -n add -inet 203.0.113.5 -gateway 10.0.0.1",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("Refresh commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	wantSeen := []string{
		`route -q -n delete -inet 203.0.113.5 -gateway 192.168.1.1 | ["P route -q -n delete -inet 203.0.113.5 -gateway 192.168.1.1"]`,
		`route -q -n add -inet 203.0.113.5 -gateway 10.0.0.1 | ["P route -q -n delete -inet 203.0.113.5 -gateway 10.0.0.1"]`,
	}
	if !reflect.DeepEqual(seen, wantSeen) {
		t.Errorf("journal while running:\n%q\nwant:\n%q", seen, wantSeen)
	}
	r.onRun = nil

	// The new gateway is now the state: no change, no command.
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil || len(r.cmds) != 1 {
		t.Fatalf("second Refresh: err=%v cmds=%q", err, r.cmds)
	}

	// Remove deletes the route that is in place now.
	r.out["route -n get -inet 203.0.113.5"] = hostVia("203.0.113.5", "10.0.0.1", "en1", hostFlags)
	r.cmds = nil
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.cmds, "route -q -n delete -inet 203.0.113.5 -gateway 10.0.0.1") ||
		slices.Contains(r.cmds, "route -q -n delete -inet 203.0.113.5 -gateway 192.168.1.1") {
		t.Errorf("Remove commands %q", r.cmds)
	}
	if len(j.Entries()) != 0 {
		t.Errorf("journal after Remove: %v", j.Entries())
	}
	// Refresh after Remove does nothing.
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil || len(r.cmds) != 0 {
		t.Fatalf("Refresh after Remove: err=%v cmds=%q", err, r.cmds)
	}
}

// A failed move is retried by the next Refresh, and the journal never holds
// the undo of a route that was not added.
func TestEndpointRouteMoveRetried(t *testing.T) {
	j, _ := newJournal(t)
	r := &recorder{out: map[string]string{"route -n get default": defaultVia("192.168.1.1", "en0")}}
	c := newDarwin(r, j)
	p := plan("utun7", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	p.Endpoints = eps("203.0.113.5:51820")
	if _, err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	r.out["route -n get default"] = defaultVia("10.0.0.1", "en1")
	r.out["route -n get -inet 203.0.113.5"] = hostVia("203.0.113.5", "192.168.1.1", "en0", hostFlags)
	r.fail = map[string]error{"route -q -n add -inet 203.0.113.5 -gateway 10.0.0.1": errors.New("exit status 1: route: writing to routing socket: Network is unreachable")}
	if err := c.Refresh(ctx); err == nil {
		t.Fatal("Refresh succeeded although the add failed")
	}
	if got := hostRouteUndos(j, "utun7"); len(got) != 0 {
		t.Errorf("journal after failed move %q, want no host route", got)
	}
	r.fail = nil
	delete(r.out, "route -n get -inet 203.0.113.5")
	r.fail = map[string]error{"route -n get -inet 203.0.113.5": errNotInTable}
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.cmds, "route -q -n add -inet 203.0.113.5 -gateway 10.0.0.1") {
		t.Errorf("retry commands %q", r.cmds)
	}
	if got, want := hostRouteUndos(j, "utun7"), []string{"P route -q -n delete -inet 203.0.113.5 -gateway 10.0.0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("journal %q, want %q", got, want)
	}
}

// Once the full tunnel is up, the default route may point at the tunnel
// itself; the physical interface's own (scoped) default route then gives the
// gateway. Without a known physical interface nothing changes.
func TestRefreshDefaultOnOwnTunnel(t *testing.T) {
	r := &recorder{out: map[string]string{"route -n get default": defaultVia("192.168.1.1", "en0")}}
	c := newDarwin(r, nil)
	p := plan("utun7", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	p.Endpoints = eps("203.0.113.5:51820")
	if _, err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	r.out["route -n get default"] = defaultVia("link#21", "utun7")
	r.out["route -n get -ifscope en0 default"] = defaultVia("192.168.1.1", "en0")
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := []string{"route -n get default", "route -n get -ifscope en0 default"}; !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("Refresh ran %q, want %q", r.cmds, want)
	}
	r.out["route -n get -ifscope en0 default"] = defaultVia("192.168.1.254", "en0")
	r.out["route -n get -inet 203.0.113.5"] = hostVia("203.0.113.5", "192.168.1.1", "en0", hostFlags)
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := "route -q -n add -inet 203.0.113.5 -gateway 192.168.1.254"; !slices.Contains(r.cmds, want) {
		t.Errorf("Refresh ran %q, want %q", r.cmds, want)
	}

	// Connected while offline: blackhole, no physical interface known.
	r = &recorder{fail: map[string]error{"route -n get default": errNotInTable}}
	c = newDarwin(r, nil)
	if _, err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	r.fail = nil
	r.out = map[string]string{"route -n get default": defaultVia("link#21", "utun7")}
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := []string{"route -n get default"}; !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("Refresh without physical interface ran %q, want %q", r.cmds, want)
	}
	// The network comes back: the blackhole gives way to the gateway.
	r.out["route -n get default"] = defaultVia("192.168.1.1", "en0")
	r.out["route -n get -inet 203.0.113.5"] = hostVia("203.0.113.5", "127.0.0.1", "lo0", "UP,GATEWAY,HOST,DONE,STATIC,BLACKHOLE")
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"route -n get default",
		"route -n get -inet 203.0.113.5",
		"route -q -n delete -inet 203.0.113.5 127.0.0.1 -blackhole",
		"route -q -n add -inet 203.0.113.5 -gateway 192.168.1.1",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("Refresh ran\n%q\nwant\n%q", r.cmds, want)
	}
}

func TestRefreshUpdatesMTU(t *testing.T) {
	r := &recorder{out: map[string]string{
		"route -n get default": defaultVia("192.168.1.1", "en0"),
		"ifconfig en0":         "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n",
	}}
	c := newDarwin(r, nil)
	p := plan("utun7", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))
	p.MTU, p.MTUAuto = 1420, true
	if _, err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := []string{"route -n get default", "ifconfig en0"}; !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("unchanged Refresh ran %q, want %q", r.cmds, want)
	}
	r.out["ifconfig en0"] = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1440\n"
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := []string{"route -n get default", "ifconfig en0", "ifconfig utun7 mtu 1360"}; !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("Refresh ran %q, want %q", r.cmds, want)
	}
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil || slices.Contains(r.cmds, "ifconfig utun7 mtu 1360") {
		t.Fatalf("third Refresh: err=%v cmds=%q", err, r.cmds)
	}
	// Offline: the MTU stays as it is (no flapping to the fallback).
	r.out = nil
	r.fail = map[string]error{"route -n get default": errNotInTable, "route -n get -inet6 default": errNotInTable}
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil || slices.ContainsFunc(r.cmds, func(c string) bool { return strings.HasPrefix(c, "ifconfig") }) {
		t.Fatalf("offline Refresh: err=%v cmds=%q", err, r.cmds)
	}

	// An MTU from the configuration is never changed; a split tunnel has
	// nothing else to refresh.
	r = &recorder{out: map[string]string{"route -n get default": defaultVia("192.168.1.1", "en0")}}
	c = newDarwin(r, nil)
	p.MTUAuto = false
	if _, err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	if err := c.Refresh(ctx); err != nil || len(r.cmds) != 0 {
		t.Fatalf("fixed-MTU Refresh: err=%v cmds=%q", err, r.cmds)
	}
}

// An undo deletes an endpoint host route only while it is still the one
// Latchwire added: on macOS a delete matches the destination, so without
// this check it could remove a route somebody else put there.
func TestHostRouteUndoTouchesOnlyOwnRoute(t *testing.T) {
	const del = "route -q -n delete -inet 203.0.113.5 -gateway 192.168.1.1"
	for name, set := range map[string]func(r *recorder){
		"other gateway": func(r *recorder) {
			r.out["route -n get -inet 203.0.113.5"] = hostVia("203.0.113.5", "192.168.1.99", "en0", hostFlags)
		},
		"covering route": func(r *recorder) {
			r.out["route -n get -inet 203.0.113.5"] = defaultVia("192.168.1.1", "en0")
		},
		"gone": func(r *recorder) {
			r.fail["route -n get -inet 203.0.113.5"] = errNotInTable
		},
	} {
		j, _ := newJournal(t)
		r := &recorder{out: map[string]string{"route -n get default": defaultVia("192.168.1.1", "en0")}, fail: map[string]error{}}
		c := newDarwin(r, j)
		p := plan("utun7", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
		p.Endpoints = eps("203.0.113.5:51820")
		if _, err := c.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
		set(r)
		// The device is closed: its routes are gone already.
		r.fail["route -q -n delete -inet 0.0.0.0/1 -interface utun7"] = errNotInTable
		r.fail["route -q -n delete -inet 128.0.0.0/1 -interface utun7"] = errNotInTable
		r.cmds = nil
		if err := c.Remove(ctx); err != nil {
			t.Errorf("%s: Remove: %v", name, err)
		}
		if slices.Contains(r.cmds, del) {
			t.Errorf("%s: Remove deleted a route that is not ours: %q", name, r.cmds)
		}
		if len(j.Entries()) != 0 {
			t.Errorf("%s: journal %v, want forgotten", name, j.Entries())
		}
	}

	// The startup cleanup checks the same way.
	j, _ := newJournal(t)
	undo := persistentUndo("route", "-q", "-n", "delete", "-inet", "203.0.113.5", "-gateway", "192.168.1.1")
	if err := j.Record("utun7", []Step{*undo}); err != nil {
		t.Fatal(err)
	}
	r := &recorder{out: map[string]string{"route -n get -inet 203.0.113.5": hostVia("203.0.113.5", "192.168.1.99", "en0", hostFlags)}}
	if err := Cleanup(ctx, r, j, nil); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.cmds, del) {
		t.Errorf("Cleanup deleted a route that is not ours: %q", r.cmds)
	}
	r = &recorder{out: map[string]string{"route -n get -inet 203.0.113.5": hostVia("203.0.113.5", "192.168.1.1", "en0", hostFlags)}}
	if err := j.Record("utun7", []Step{*undo}); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(ctx, r, j, nil); err != nil || !slices.Contains(r.cmds, del) {
		t.Errorf("Cleanup of our route: err=%v cmds=%q", err, r.cmds)
	}
}

// A host route for the endpoint that is already there (an on-link neighbour
// entry, another tool's route) is left alone and never undone.
func TestDarwinEndpointRouteExists(t *testing.T) {
	j, _ := newJournal(t)
	r := &recorder{
		out:  map[string]string{"route -n get default": defaultVia("192.168.1.1", "en0")},
		fail: map[string]error{"route -q -n add -inet 203.0.113.5 -gateway 192.168.1.1": errExists},
	}
	c := newDarwin(r, j)
	p := plan("utun7", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	p.Endpoints = eps("203.0.113.5:51820")
	if _, err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got := hostRouteUndos(j, "utun7"); len(got) != 0 {
		t.Errorf("journal holds %q for a route that is not ours", got)
	}
	r.cmds = nil
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(r.cmds, func(c string) bool { return strings.Contains(c, "203.0.113.5") }) {
		t.Errorf("Remove touched the existing route: %q", r.cmds)
	}
}

func TestParseRouteGet(t *testing.T) {
	ri := parseRouteGet(hostVia("2001:db8::5", "fe80::1%en0", "en0", hostFlags))
	if ri.dst != "2001:db8::5" || ri.gateway != "fe80::1%en0" || ri.iface != "en0" || !slices.Equal(ri.flags, strings.Split(hostFlags, ",")) {
		t.Errorf("parsed %+v", ri)
	}
	if ri := parseRouteGet(""); ri.dst != "" || ri.gateway != "" || ri.iface != "" || ri.flags != nil {
		t.Errorf("empty output parsed as %+v", ri)
	}
}
