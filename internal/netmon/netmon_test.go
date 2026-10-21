package netmon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeSource delivers scripted notifications; it honours ctx like a real one.
type fakeSource struct {
	ch     chan string
	closed chan struct{}
}

func newFakeSource() *fakeSource {
	return &fakeSource{ch: make(chan string, 64), closed: make(chan struct{})}
}

func (f *fakeSource) Next(ctx context.Context) (string, error) {
	select {
	case s := <-f.ch:
		return s, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (f *fakeSource) Close() error { close(f.closed); return nil }

const testDebounce = 200 * time.Millisecond

func TestWatchDebounces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newFakeSource()
	ev := Watch(ctx, src, testDebounce, nil)

	// 10 events 50 ms apart: the burst spans 450 ms, longer than one
	// debounce window, so only a debounce that restarts on each event gives
	// a single Event.
	for i := 0; i < 10; i++ {
		src.ch <- "en0"
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case e := <-ev:
		if e.At.IsZero() {
			t.Error("Event.At is zero")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Event after burst")
	}
	select {
	case e := <-ev:
		t.Fatalf("second Event for one burst: %v", e)
	case <-time.After(2 * testDebounce):
	}
}

func TestWatchDeliversAgainAfterQuiet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newFakeSource()
	ev := Watch(ctx, src, 50*time.Millisecond, nil)
	for i := 0; i < 2; i++ {
		src.ch <- ""
		select {
		case <-ev:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: no Event", i)
		}
	}
}

func TestWatchIgnoresOwnIfaces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newFakeSource()
	ev := Watch(ctx, src, 50*time.Millisecond, func(n string) bool { return n == "utun7" })

	src.ch <- "utun7"
	src.ch <- "utun7"
	select {
	case e := <-ev:
		t.Fatalf("Event for own interface: %v", e)
	case <-time.After(300 * time.Millisecond):
	}

	// An unnamed notification and another interface still count.
	src.ch <- "utun7"
	src.ch <- "en0"
	select {
	case <-ev:
	case <-time.After(2 * time.Second):
		t.Fatal("no Event for en0")
	}
	src.ch <- ""
	select {
	case <-ev:
	case <-time.After(2 * time.Second):
		t.Fatal("no Event for unnamed notification")
	}
}

func TestWatchSteadyStreamStillFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newFakeSource()
	ev := Watch(ctx, src, 50*time.Millisecond, nil)
	// A notification every 20 ms never lets a plain debounce settle; the
	// cap (10 x debounce = 500 ms) must still deliver an Event.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case src.ch <- "en0":
			case <-stop:
				return
			}
			select {
			case <-time.After(20 * time.Millisecond):
			case <-stop:
				return
			}
		}
	}()
	select {
	case <-ev:
	case <-time.After(2 * time.Second):
		t.Fatal("no Event during a steady stream")
	}
}

func TestWatchStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	src := newFakeSource()
	ev := Watch(ctx, src, 50*time.Millisecond, nil)
	cancel()
	select {
	case _, ok := <-ev:
		if ok {
			t.Fatal("Event after cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("channel not closed after cancel")
	}
	select {
	case <-src.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("source not closed after cancel")
	}
}

type failingSource struct{}

func (failingSource) Next(context.Context) (string, error) { return "", errors.New("socket gone") }

func TestWatchClosesOnSourceError(t *testing.T) {
	ev := Watch(context.Background(), failingSource{}, 50*time.Millisecond, nil)
	select {
	case _, ok := <-ev:
		if ok {
			t.Fatal("unexpected Event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("channel not closed after source error")
	}
}

// TestNewSourceOpens opens the real platform socket. It needs no privileges
// (an AF_ROUTE or NETLINK_ROUTE socket is read-only) and changes nothing.
func TestNewSourceOpens(t *testing.T) {
	src, err := NewSource()
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("no network change source on this OS")
	}
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	defer func() {
		if c, ok := src.(interface{ Close() error }); ok {
			c.Close()
		} else {
			t.Error("source has no Close")
		}
	}()

	// Next must return promptly once ctx ends.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := src.Next(ctx); err != nil {
				done <- err
				return
			}
			// A real network event may arrive; keep reading until ctx ends.
		}
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Next error = %v, want context deadline", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Next did not return after ctx expired")
	}
}

// scriptedRunner answers commands from a table keyed by the command line.
type scriptedRunner struct {
	out  map[string]string
	errs map[string]error
	cmds []string
}

func (s *scriptedRunner) Run(_ context.Context, name string, args []string, _ []byte) ([]byte, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	s.cmds = append(s.cmds, c)
	if err, ok := s.errs[c]; ok {
		return nil, err
	}
	if o, ok := s.out[c]; ok {
		return []byte(o), nil
	}
	return nil, errors.New("exit status 1")
}

const (
	darwinRoute = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	darwinARP  = "? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]\n"
	linuxRoute = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
	linuxNeigh = "192.168.1.1 dev eth0 lladdr a4:2b:b0:01:02:03 REACHABLE\n"
)

func darwinRunner(arp string) *scriptedRunner {
	return &scriptedRunner{out: map[string]string{
		"route -n get default": darwinRoute,
		"arp -n 192.168.1.1":   arp,
	}}
}

func TestNetworkIDStable(t *testing.T) {
	ctx := context.Background()
	a, err := networkID(ctx, darwinRunner(darwinARP), "darwin")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := networkID(ctx, darwinRunner(darwinARP), "darwin")
	if a != b {
		t.Errorf("same gateway+MAC gave %q and %q", a, b)
	}
	if len(a) != 16 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Errorf("ID %q is not 16 lower-case hex digits", a)
	}
	other := strings.Replace(darwinARP, "a4:2b:b0:1:2:3", "a4:2b:b0:1:2:4", 1)
	c, _ := networkID(ctx, darwinRunner(other), "darwin")
	if c == a {
		t.Error("different MAC gave the same ID")
	}

	// The same MAC written with leading zeros (Linux) or without (macOS)
	// is the same network.
	padded := strings.Replace(darwinARP, "a4:2b:b0:1:2:3", "A4:2B:B0:01:02:03", 1)
	d, _ := networkID(ctx, darwinRunner(padded), "darwin")
	if d != a {
		t.Errorf("MAC spelling changed the ID: %q vs %q", d, a)
	}

	l := &scriptedRunner{out: map[string]string{
		"ip route show default":     linuxRoute,
		"ip neigh show 192.168.1.1": linuxNeigh,
	}}
	e, err := networkID(ctx, l, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if e != a {
		t.Errorf("linux ID %q != darwin ID %q for the same gateway+MAC", e, a)
	}
}

func TestNetworkIDNone(t *testing.T) {
	ctx := context.Background()
	// macOS: no default route makes `route get` fail.
	r := &scriptedRunner{errs: map[string]error{
		"route -n get default": errors.New("exit status 1: route: writing to routing socket: not in table"),
	}}
	if id, err := networkID(ctx, r, "darwin"); err != nil || id != NoNetwork {
		t.Errorf("darwin no route: %q, %v", id, err)
	}
	// Linux: no default route prints nothing.
	r = &scriptedRunner{out: map[string]string{"ip route show default": ""}}
	if id, err := networkID(ctx, r, "linux"); err != nil || id != NoNetwork {
		t.Errorf("linux no route: %q, %v", id, err)
	}
	// A default route without a gateway address (on-link, e.g. a tunnel).
	r = &scriptedRunner{out: map[string]string{"ip route show default": "default dev wg0 scope link\n"}}
	if id, err := networkID(ctx, r, "linux"); err != nil || id != NoNetwork {
		t.Errorf("linux on-link route: %q, %v", id, err)
	}
	if len(r.cmds) != 1 {
		t.Errorf("commands run: %v", r.cmds)
	}
}

func TestNetworkIDErrors(t *testing.T) {
	ctx := context.Background()
	// Any other failure is an error, not "none".
	r := &scriptedRunner{errs: map[string]error{"ip route show default": errors.New("boom")}}
	if id, err := networkID(ctx, r, "linux"); err == nil {
		t.Errorf("want error, got %q", id)
	}
	// An unknown MAC is never a gateway-address-only hash: the constant
	// "unknown" cannot collide with any real network's ID.
	r = &scriptedRunner{out: map[string]string{"ip route show default": linuxRoute}}
	if id, err := networkID(ctx, r, "linux"); err != nil || id != UnknownNetwork {
		t.Fatalf("no neighbour entry (lookup fails): %q, %v", id, err)
	}
	for _, neigh := range []string{
		"", "192.168.1.1 dev eth0  FAILED\n", "192.168.1.1 dev eth0 INCOMPLETE\n",
		"192.168.1.1 dev eth0 lladdr 00:00:00:00:00:00 STALE\n",
	} {
		r.out["ip neigh show 192.168.1.1"] = neigh
		if id, err := networkID(ctx, r, "linux"); err != nil || id != UnknownNetwork {
			t.Errorf("neighbour %q: %q, %v", neigh, id, err)
		}
	}
	for _, arp := range []string{
		"? (192.168.1.1) at (incomplete) on en0 ifscope [ethernet]\n",
		"arp: no entry for 192.168.1.1\n", "",
	} {
		if id, err := networkID(ctx, darwinRunner(arp), "darwin"); err != nil || id != UnknownNetwork {
			t.Errorf("arp %q: %q, %v", arp, id, err)
		}
	}
	r = &scriptedRunner{out: map[string]string{"route -n get default": darwinRoute}}
	if id, err := networkID(ctx, r, "darwin"); err != nil || id != UnknownNetwork {
		t.Errorf("darwin arp failing: %q, %v", id, err)
	}
	if UnknownNetwork != "unknown" || NoNetwork != "none" {
		t.Errorf("constants changed: %q %q", UnknownNetwork, NoNetwork)
	}
	// Cancelled context is reported.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	r = &scriptedRunner{
		out:  map[string]string{"ip route show default": linuxRoute},
		errs: map[string]error{"ip neigh show 192.168.1.1": context.Canceled},
	}
	if _, err := networkID(cctx, r, "linux"); err == nil {
		t.Error("cancelled context not reported")
	}
}

func TestParseDefaultRouteLinux(t *testing.T) {
	cases := []struct {
		name, in, gw, iface string
	}{
		{"simple", linuxRoute, "192.168.1.1", "eth0"},
		{"lowest metric wins", "default via 10.0.0.1 dev wlan0 metric 600\ndefault via 192.168.1.1 dev eth0 metric 100\n", "192.168.1.1", "eth0"},
		{"no metric is 0", "default via 10.0.0.1 dev wlan0 metric 600\ndefault via 192.168.1.1 dev eth0\n", "192.168.1.1", "eth0"},
		{"on-link", "default dev wg0 scope link\n", "", "wg0"},
		{"ipv6", "default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n", "fe80::1", "eth0"},
		{"empty", "", "", ""},
		{"not a default line", "10.0.0.0/8 via 10.0.0.1 dev eth0\n", "", ""},
		{"bad via", "default via inet6 fe80::1 dev eth0\n", "", "eth0"},
	}
	for _, c := range cases {
		gw, iface := parseDefaultRouteLinux(c.in)
		if gw.IsValid() != (c.gw != "") || (c.gw != "" && gw.String() != c.gw) || iface != c.iface {
			t.Errorf("%s: got (%v, %q), want (%q, %q)", c.name, gw, iface, c.gw, c.iface)
		}
	}
}

func TestParseDefaultRouteDarwin(t *testing.T) {
	gw, iface := parseDefaultRouteDarwin(darwinRoute)
	if gw.String() != "192.168.1.1" || iface != "en0" {
		t.Errorf("got (%v, %q)", gw, iface)
	}
	// Link-scoped gateway: no address.
	gw, iface = parseDefaultRouteDarwin("    gateway: link#14\n  interface: en1\n")
	if gw.IsValid() || iface != "en1" {
		t.Errorf("link gateway: got (%v, %q)", gw, iface)
	}
	// IPv6 gateways carry a zone.
	gw, _ = parseDefaultRouteDarwin("    gateway: fe80::1%en0\n  interface: en0\n")
	if gw.String() != "fe80::1" {
		t.Errorf("zone not stripped: %v", gw)
	}
	gw, iface = parseDefaultRouteDarwin("")
	if gw.IsValid() || iface != "" {
		t.Errorf("empty: got (%v, %q)", gw, iface)
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"a4:2b:b0:1:2:3":       "a4:2b:b0:01:02:03",
		"A4:2B:B0:01:02:03":    "a4:2b:b0:01:02:03",
		"(incomplete)":         "",
		"":                     "",
		"a4:2b:b0:01:02":       "",
		"a4:2b:b0:01:02:03:04": "",
		"a4:2b:b0:01:02:zz":    "",
		"a4:2b:b0:001:02:03":   "",
		"00:00:00:00:00:00":    "",
	}
	for in, want := range cases {
		if got := normalizeMAC(in); got != want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMACFromNeighbours(t *testing.T) {
	// Prefer the entry on the default route's interface.
	darwin := "? (192.168.1.1) at 0:11:22:33:44:55 on en1 ifscope [ethernet]\n? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]\n"
	if got := macFromNeighbours(darwin, "at", "en0"); got != "a4:2b:b0:01:02:03" {
		t.Errorf("darwin: %q", got)
	}
	if got := macFromNeighbours(darwin, "at", ""); got != "00:11:22:33:44:55" {
		t.Errorf("darwin first: %q", got)
	}
	if got := macFromNeighbours("? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n", "at", "en0"); got != "" {
		t.Errorf("incomplete: %q", got)
	}
	if got := macFromNeighbours("192.168.1.1 dev eth0  FAILED\n", "lladdr", "eth0"); got != "" {
		t.Errorf("failed: %q", got)
	}
	if got := macFromNeighbours(linuxNeigh, "lladdr", "eth0"); got != "a4:2b:b0:01:02:03" {
		t.Errorf("linux: %q", got)
	}
}
