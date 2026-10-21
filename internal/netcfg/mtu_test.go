package netcfg

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// scripted answers commands from a table keyed by the rendered command line;
// any other command fails. It records the commands it was asked to run.
type scripted struct {
	out  map[string]string
	cmds []string
}

func (s *scripted) Run(_ context.Context, name string, args []string, _ []byte) ([]byte, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	s.cmds = append(s.cmds, c)
	if o, ok := s.out[c]; ok {
		return []byte(o), nil
	}
	return nil, errors.New("exit status 1")
}

func eps(s ...string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, v := range s {
		out = append(out, netip.MustParseAddrPort(v))
	}
	return out
}

const (
	darwinRouteDefault = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`
	darwinIfconfigEn0 = `en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether aa:bb:cc:dd:ee:ff
	inet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255
`
	linuxRouteGet1500 = "203.0.113.5 via 192.168.1.1 dev eth0 src 192.168.1.10 uid 0 \n    cache \n"
	linuxRouteGet1400 = "198.51.100.7 via 10.0.0.1 dev eth1 src 10.0.0.9 uid 0 \n    cache mtu 1400 \n"
	linuxLinkEth0     = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
)

func TestAutoMTUDarwinFromDefaultIface(t *testing.T) {
	r := &scripted{out: map[string]string{
		"route -n get default": darwinRouteDefault,
		"ifconfig en0":         darwinIfconfigEn0,
	}}
	if got := autoMTUDarwin(ctx, r, eps("203.0.113.5:51820")); got != 1420 {
		t.Fatalf("MTU = %d, want 1420", got)
	}
	want := []string{"route -n get default", "ifconfig en0"}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands %q, want %q", r.cmds, want)
	}
}

func TestAutoMTULinuxMinOverEndpoints(t *testing.T) {
	r := &scripted{out: map[string]string{
		"ip route get 203.0.113.5":  linuxRouteGet1500,
		"ip link show eth0":         linuxLinkEth0,
		"ip route get 198.51.100.7": linuxRouteGet1400,
	}}
	got := autoMTULinux(ctx, r, eps("203.0.113.5:51820", "198.51.100.7:51820"))
	if got != 1320 {
		t.Fatalf("MTU = %d, want 1320", got)
	}
}

func TestAutoMTULinuxRouteWithoutMTUUsesLink(t *testing.T) {
	r := &scripted{out: map[string]string{
		"ip route get 203.0.113.5": linuxRouteGet1500,
		"ip link show eth0":        linuxLinkEth0,
	}}
	if got := autoMTULinux(ctx, r, eps("203.0.113.5:51820")); got != 1420 {
		t.Fatalf("MTU = %d, want 1420", got)
	}
}

func TestAutoMTULinuxSkipsFailedEndpoint(t *testing.T) {
	r := &scripted{out: map[string]string{
		"ip route get 198.51.100.7": linuxRouteGet1400,
	}}
	got := autoMTULinux(ctx, r, eps("203.0.113.5:51820", "198.51.100.7:51820"))
	if got != 1320 {
		t.Fatalf("MTU = %d, want 1320", got)
	}
}

func TestAutoMTULinuxIPv6Endpoint(t *testing.T) {
	r := &scripted{out: map[string]string{
		"ip route get 2001:db8::1": "2001:db8::1 from :: via fe80::1 dev eth0 src 2001:db8::2 metric 1024 pref medium\n",
		"ip link show eth0":        linuxLinkEth0,
	}}
	if got := autoMTULinux(ctx, r, eps("[2001:db8::1]:51820")); got != 1420 {
		t.Fatalf("MTU = %d, want 1420", got)
	}
}

func TestAutoMTUFallback(t *testing.T) {
	fail := &scripted{}
	if got := autoMTUDarwin(ctx, fail, eps("203.0.113.5:51820")); got != fallbackMTU {
		t.Fatalf("darwin MTU = %d, want %d", got, fallbackMTU)
	}
	if got := autoMTULinux(ctx, fail, eps("203.0.113.5:51820")); got != fallbackMTU {
		t.Fatalf("linux MTU = %d, want %d", got, fallbackMTU)
	}
	if got := autoMTULinux(ctx, fail, nil); got != fallbackMTU {
		t.Fatalf("linux, no endpoints: MTU = %d, want %d", got, fallbackMTU)
	}
	if got := AutoMTU(ctx, fail, nil); got != fallbackMTU {
		t.Fatalf("AutoMTU MTU = %d, want %d", got, fallbackMTU)
	}
}

func TestAutoMTUClampsToMinimum(t *testing.T) {
	r := &scripted{out: map[string]string{
		"route -n get default": darwinRouteDefault,
		"ifconfig en0":         strings.Replace(darwinIfconfigEn0, "mtu 1500", "mtu 1300", 1),
	}}
	if got := autoMTUDarwin(ctx, r, nil); got != 1280 {
		t.Fatalf("MTU = %d, want 1280", got)
	}
}

func TestAutoMTURejectsHostileInterfaceName(t *testing.T) {
	r := &scripted{out: map[string]string{
		"route -n get default": "  interface: -v\n",
	}}
	if got := autoMTUDarwin(ctx, r, nil); got != fallbackMTU {
		t.Fatalf("MTU = %d, want %d", got, fallbackMTU)
	}
	if len(r.cmds) != 1 {
		t.Fatalf("ran %q after a bad interface name", r.cmds)
	}
}

func TestParseMTUToken(t *testing.T) {
	cases := map[string]int{
		"mtu 1400":               1400,
		"cache mtu lock 1280 ":   1280,
		"x mtu 1500 qdisc":       1500,
		"no mtu here":            0,
		"mtu":                    0,
		"mtu 0":                  0,
		"mtu 70000":              0,
		"mtu abc mtu 1450":       1450,
		"prefmtu 1500 mtu 1300 ": 1300,
	}
	for in, want := range cases {
		if got := parseMTU(in); got != want {
			t.Errorf("parseMTU(%q) = %d, want %d", in, got, want)
		}
	}
}
