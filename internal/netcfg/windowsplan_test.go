package netcfg

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const routePrint4 = `===========================================================================
Interface List
 12...a4 2b b0 01 02 03 ......Intel(R) Wi-Fi 6 AX201
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.5     35
          0.0.0.0          0.0.0.0       10.20.0.1       10.20.0.7     50
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link       192.168.1.5    291
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0     172.16.0.1       1
===========================================================================
`

// German: other headers, and on-link is two words.
const routePrint4DE = `IPv4-Routentabelle
===========================================================================
Aktive Routen:
     Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik
          0.0.0.0          0.0.0.0    192.168.178.1   192.168.178.20     25
      192.168.178.0    255.255.255.0   Auf Verbindung   192.168.178.20    281
===========================================================================
Ständige Routen:
  Keine
`

const routePrint6 = `IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
 12    291 ::/0                     fe80::1
  1    331 ::1/128                  On-link
 12    291 2001:db8:abcd:ef01:2345:6789:abcd:ef01/128
                                    On-link
 12    291 2001:db8:1:2:3:4:5:6/128
                                    fe80::2
===========================================================================
Persistent Routes:
  None
`

func testIfaces() []ifaceInfo {
	return []ifaceInfo{
		{Name: "Wi-Fi", Index: 12, MTU: 1500, Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.5")}},
		{Name: "Ethernet 2", Index: 7, MTU: 1400, Addrs: []netip.Addr{netip.MustParseAddr("10.20.0.7")}},
		{Name: "wg0", Index: 30, MTU: 1420, Addrs: []netip.Addr{netip.MustParseAddr("10.9.0.2")}},
	}
}

func windowsConfigurer(r Runner, j *Journal) *configurer {
	c := newWindows(r, j).(*configurer)
	c.ifaces = testIfaces
	return c
}

func stepsOf(ss []step) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s.do.String())
	}
	return out
}

func TestPlanWindowsSplit(t *testing.T) {
	got := stepsOf(planWindows(Plan{Iface: "wg0", MTU: 1420,
		Addresses: pfx("10.9.0.2/32", "fd00::2/128"),
		Routes:    pfx("10.0.0.0/8", "fd00:1::/48")}))
	want := []string{
		"netsh interface ipv4 set subinterface interface=wg0 mtu=1420 store=active",
		"netsh interface ipv6 set subinterface interface=wg0 mtu=1420 store=active",
		"netsh interface ipv6 set interface interface=wg0 dadtransmits=0 routerdiscovery=disabled store=active",
		"netsh interface ipv4 add address name=wg0 address=10.9.0.2/32 store=active",
		"netsh interface ipv6 add address interface=wg0 address=fd00::2/128 store=active",
		"netsh interface ipv4 add route prefix=10.0.0.0/8 interface=wg0 store=active",
		"netsh interface ipv6 add route prefix=fd00:1::/48 interface=wg0 store=active",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%s", strings.Join(got, "\n"))
	}
}

func TestPlanWindowsSkipsConnectedSubnet(t *testing.T) {
	got := stepsOf(planWindows(Plan{Iface: "wg0", Addresses: pfx("10.9.0.2/24"), Routes: pfx("10.9.0.0/24", "10.8.0.0/24")}))
	for _, c := range got {
		if strings.Contains(c, "prefix=10.9.0.0/24") {
			t.Fatalf("connected subnet added again: %s", c)
		}
	}
	if !slices.Contains(got, "netsh interface ipv4 add route prefix=10.8.0.0/24 interface=wg0 store=active") {
		t.Fatalf("route missing: %v", got)
	}
}

func TestPlanWindowsIPv4OnlyLeavesIPv6Alone(t *testing.T) {
	for _, c := range stepsOf(planWindows(Plan{Iface: "wg0", MTU: 1420, Addresses: pfx("10.9.0.2/32")})) {
		if strings.Contains(c, "ipv6") {
			t.Fatalf("touches IPv6: %s", c)
		}
	}
}

func TestPlanWindowsFullTunnel(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4, "route print -6": routePrint6}}
	c := windowsConfigurer(r, nil)
	if _, err := c.Apply(context.Background(), Plan{Iface: "wg0", Addresses: pfx("10.9.0.2/32"),
		Routes:    pfx("0.0.0.0/0", "198.51.100.7/32"),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820")}}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"netsh interface ipv4 add route prefix=198.51.100.7/32 interface=12 nexthop=192.168.1.1 store=active",
		"netsh interface ipv4 add route prefix=0.0.0.0/1 interface=wg0 store=active",
		"netsh interface ipv4 add route prefix=128.0.0.0/1 interface=wg0 store=active",
	}
	i := 0
	for _, cmd := range r.cmds {
		if i < len(want) && cmd == want[i] {
			i++
		}
		if strings.Contains(cmd, "0.0.0.0/0") || strings.Contains(cmd, "prefix=198.51.100.7/32 interface=wg0") {
			t.Fatalf("bad route: %s", cmd)
		}
	}
	if i != len(want) {
		t.Fatalf("got\n%s", strings.Join(r.cmds, "\n"))
	}
}

func TestWindowsHostRouteUsesIndex(t *testing.T) {
	ss := planWindowsEndpointRoutes([]netip.Addr{netip.MustParseAddr("2001:db8::9")},
		[2]nextHop{1: {gw: netip.MustParseAddr("fe80::1"), iface: "12"}})
	if got := ss[0].do.String(); got != "netsh interface ipv6 add route prefix=2001:db8::9/128 interface=12 nexthop=fe80::1 store=active" {
		t.Fatal(got)
	}
	if !ss[0].undo.Persistent {
		t.Fatal("a host route outlives the interface: its undo must be persistent")
	}
}

func TestWindowsOnLinkDefaultRoute(t *testing.T) {
	ss := planWindowsEndpointRoutes([]netip.Addr{netip.MustParseAddr("198.51.100.7")}, [2]nextHop{0: {iface: "12"}})
	if got := ss[0].do.String(); got != "netsh interface ipv4 add route prefix=198.51.100.7/32 interface=12 store=active" {
		t.Fatal(got)
	}
}

func TestWindowsBlackholeWithoutGateway(t *testing.T) {
	ss := planWindowsEndpointRoutes([]netip.Addr{netip.MustParseAddr("198.51.100.7")}, [2]nextHop{})
	if got := ss[0].do.String(); got != "netsh interface ipv4 add route prefix=198.51.100.7/32 interface=1 store=active" {
		t.Fatal(got)
	}
}

func TestWindowsEndpointIsGateway(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	if ss := planWindowsEndpointRoutes([]netip.Addr{gw}, [2]nextHop{0: {gw: gw, iface: "12"}}); len(ss) != 0 {
		t.Fatalf("%v", stepsOf(ss))
	}
}

func TestParseRoutePrint(t *testing.T) {
	rs := parseRoutePrint4(routePrint4)
	if len(rs) != 4 {
		t.Fatalf("rows %d: %+v", len(rs), rs)
	}
	best, ok := lowestDefault(rs, nil)
	if !ok || best.gw != netip.MustParseAddr("192.168.1.1") || best.ifAddr != netip.MustParseAddr("192.168.1.5") {
		t.Fatalf("%+v", best)
	}
	if rs[3].prefix != netip.MustParsePrefix("192.168.1.0/24") || rs[3].gw.IsValid() {
		t.Fatalf("on-link row: %+v", rs[3])
	}
}

func TestParseRoutePrintLocalized(t *testing.T) {
	rs := parseRoutePrint4(routePrint4DE)
	if len(rs) != 2 {
		t.Fatalf("rows: %+v", rs)
	}
	if rs[1].prefix != netip.MustParsePrefix("192.168.178.0/24") || rs[1].gw.IsValid() {
		t.Fatalf("two-word on-link: %+v", rs[1])
	}
	if WindowsDefaultGateway(routePrint4DE) != netip.MustParseAddr("192.168.178.1") {
		t.Fatal("no gateway")
	}
}

func TestParseRoutePrint6Wrapped(t *testing.T) {
	rs := parseRoutePrint6(routePrint6)
	if len(rs) != 4 {
		t.Fatalf("rows: %+v", rs)
	}
	if rs[0].ifIndex != 12 || rs[0].gw != netip.MustParseAddr("fe80::1") || rs[0].prefix.Bits() != 0 {
		t.Fatalf("%+v", rs[0])
	}
	if rs[2].gw.IsValid() {
		t.Fatalf("wrapped on-link: %+v", rs[2])
	}
	if rs[3].gw != netip.MustParseAddr("fe80::2") {
		t.Fatalf("wrapped gateway: %+v", rs[3])
	}
}

func fullRefreshFixture(t *testing.T, r *recorder) (*configurer, *Journal) {
	t.Helper()
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := windowsConfigurer(r, j)
	if _, err := c.Apply(context.Background(), Plan{Iface: "wg0", Addresses: pfx("10.9.0.2/32"), Routes: pfx("0.0.0.0/0"),
		MTU: 1420, MTUAuto: true, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820")}}); err != nil {
		t.Fatal(err)
	}
	return c, j
}

func TestRefreshMovesEndpointRoutes(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4}}
	c, j := fullRefreshFixture(t, r)
	r.cmds = nil
	r.out["route print -4"] = strings.ReplaceAll(routePrint4, "192.168.1.1 ", "192.168.1.254 ") + "   198.51.100.7  255.255.255.255  192.168.1.1  192.168.1.5  35\n"
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	del := "netsh interface ipv4 delete route prefix=198.51.100.7/32 interface=12 nexthop=192.168.1.1 store=active"
	add := "netsh interface ipv4 add route prefix=198.51.100.7/32 interface=12 nexthop=192.168.1.254 store=active"
	if !slices.Contains(r.cmds, del) || !slices.Contains(r.cmds, add) {
		t.Fatalf("got\n%s", strings.Join(r.cmds, "\n"))
	}
	var hasNew bool
	for _, s := range j.Entries()["wg0"] {
		hasNew = hasNew || strings.Contains(s.String(), "nexthop=192.168.1.254")
		if strings.Contains(s.String(), "nexthop=192.168.1.1 ") {
			t.Fatalf("old undo still journaled: %s", s)
		}
	}
	if !hasNew {
		t.Fatal("new undo not journaled")
	}
}

func TestRefreshIdleRunsNoChange(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4}}
	c, _ := fullRefreshFixture(t, r)
	r.cmds = nil
	for range 3 {
		if err := c.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range r.cmds {
		if !strings.HasPrefix(cmd, "route print") {
			t.Fatalf("changed something: %s", cmd)
		}
	}
}

func TestRefreshFollowsAutoMTU(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4}}
	c, _ := fullRefreshFixture(t, r)
	r.cmds = nil
	c.ifaces = func() []ifaceInfo {
		l := testIfaces()
		l[0].MTU = 1400
		return l
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.cmds, "netsh interface ipv4 set subinterface interface=wg0 mtu=1320 store=active") {
		t.Fatalf("got %v", r.cmds)
	}
}

func TestRefreshOfflineKeepsMTU(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4}}
	c, _ := fullRefreshFixture(t, r)
	r.cmds = nil
	r.out["route print -4"] = "nothing\n"
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range r.cmds {
		if strings.Contains(cmd, "mtu=") {
			t.Fatalf("changed MTU: %s", cmd)
		}
	}
}

func TestAutoMTUWindows(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4, "route print -6": routePrint6}}
	ep := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:1")}
	if got := autoMTUWindows(context.Background(), r, ep, testIfaces); got != 1420 {
		t.Fatalf("%d", got)
	}
	if got := autoMTUWindows(context.Background(), &recorder{failOn: "route"}, ep, testIfaces); got != fallbackMTU {
		t.Fatalf("fallback: %d", got)
	}
}

func TestDefaultRouteIgnoresOwnTunnel(t *testing.T) {
	table := routePrint4 + "          0.0.0.0          0.0.0.0        10.9.0.1        10.9.0.2      5\n"
	r := &recorder{out: map[string]string{"route print -4": table}}
	h, _, ok := windowsDefaultRoute(context.Background(), r, true, "wg0", testIfaces)
	if !ok || h.iface != "12" {
		t.Fatalf("%+v %v", h, ok)
	}
}

func winDNSPlan(role DNSRole) Plan {
	return Plan{Iface: "wg0", DNSRole: role, DNS: []netip.Addr{netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.9.0.3"), netip.MustParseAddr("fd00::1")},
		DNSSearch: []string{"corp.example", "lab.example"}}
}

func TestWindowsDNSPrimary(t *testing.T) {
	ss, how, err := windowsDNS(context.Background(), nil, winDNSPlan(DNSPrimary))
	if err != nil || how != DNSOutcomeNRPTPrimary {
		t.Fatal(how, err)
	}
	g := WindowsInterfaceGUID("wg0")
	want := []string{
		"netsh interface ipv4 set interface interface=wg0 metric=1 store=active",
		"netsh interface ipv4 set dnsservers name=wg0 source=static address=10.9.0.1 register=none validate=no",
		"netsh interface ipv4 add dnsservers name=wg0 address=10.9.0.3 index=2 validate=no",
		"netsh interface ipv6 set interface interface=wg0 metric=1 store=active",
		"netsh interface ipv6 set dnsservers name=wg0 source=static address=fd00::1 register=none validate=no",
		`reg add ` + tcpipIfaces + g + ` /v SearchList /t REG_SZ /d corp.example,lab.example /f`,
		`reg add ` + nrptKey + g + ` /v Version /t REG_DWORD /d 2 /f`,
		`reg add ` + nrptKey + g + ` /v Name /t REG_MULTI_SZ /d . /f`,
		`reg add ` + nrptKey + g + ` /v GenericDNSServers /t REG_SZ /d 10.9.0.1;10.9.0.3;fd00::1 /f`,
		`reg add ` + nrptKey + g + ` /v ConfigOptions /t REG_DWORD /d 8 /f`,
		"ipconfig /flushdns",
	}
	if got := stepsOf(ss); !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%s", strings.Join(got, "\n"))
	}
	for _, s := range ss {
		if strings.Contains(s.do.String(), "/v Version") && (s.undo == nil || !s.undo.Persistent) {
			t.Fatal("the NRPT rule's undo must be journaled first and persistent")
		}
	}
}

func TestWindowsDNSScoped(t *testing.T) {
	ss, how, err := windowsDNS(context.Background(), nil, winDNSPlan(DNSScoped))
	if err != nil || how != DNSOutcomeNRPTScoped {
		t.Fatal(how, err)
	}
	got := stepsOf(ss)
	if !slices.Contains(got, `reg add `+nrptKey+WindowsInterfaceGUID("wg0")+` /v Name /t REG_MULTI_SZ /d .corp.example\0.lab.example /f`) {
		t.Fatalf("got\n%s", strings.Join(got, "\n"))
	}
	for _, c := range got {
		if strings.Contains(c, "dnsservers") || strings.Contains(c, "metric=") {
			t.Fatalf("scoped DNS touches the interface: %s", c)
		}
	}
}

func TestWindowsDNSNone(t *testing.T) {
	p := winDNSPlan(DNSNone)
	if ss, how, err := windowsDNS(context.Background(), nil, p); err != nil || len(ss) != 0 || how != DNSOutcomeNone {
		t.Fatal(ss, how, err)
	}
	p = winDNSPlan(DNSPrimary)
	p.DNS = nil
	if ss, how, _ := windowsDNS(context.Background(), nil, p); len(ss) != 0 || how != DNSOutcomeNone {
		t.Fatal(ss, how)
	}
}

func TestWindowsDNSRejectsInjection(t *testing.T) {
	p := winDNSPlan(DNSScoped)
	p.DNSSearch = []string{`evil /f & calc`}
	if _, _, err := windowsDNS(context.Background(), nil, p); err == nil {
		t.Fatal("bad search domain accepted")
	}
}

func TestWindowsDNSRoleChange(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	c := windowsConfigurer(r, j)
	p := winDNSPlan(DNSPrimary)
	p.Addresses = pfx("10.9.0.2/32")
	if _, err := c.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	defer c.Remove(context.Background())
	r.cmds = nil
	how, err := c.SetDNSRole(context.Background(), DNSScoped)
	if err != nil || how != DNSOutcomeNRPTScoped {
		t.Fatal(how, err)
	}
	if !slices.Contains(r.cmds, "netsh interface ipv4 set dnsservers name=wg0 source=dhcp") {
		t.Fatalf("interface DNS not undone:\n%s", strings.Join(r.cmds, "\n"))
	}
	if !slices.Contains(r.cmds, `reg delete `+nrptKey+WindowsInterfaceGUID("wg0")+` /f`) {
		t.Fatalf("primary rule not removed:\n%s", strings.Join(r.cmds, "\n"))
	}
}

func TestPersistentUndoGoneIsDone(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	route := Step{Name: netshCmd, Args: []string{"interface", "ipv4", "delete", "route", "prefix=198.51.100.7/32", "interface=12", "nexthop=192.168.1.1", "store=active"}, Persistent: true}
	key := nrptKey + WindowsInterfaceGUID("wg0")
	rule := Step{Name: regCmd, Args: []string{"delete", key, "/f"}, Persistent: true}
	if err := j.Record("wg0", []Step{route, rule}); err != nil {
		t.Fatal(err)
	}
	r := &recorder{
		out:  map[string]string{"route print -4": routePrint4},
		fail: map[string]error{"reg query " + key: errors.New("exit status 1")},
	}
	if err := Cleanup(context.Background(), r, j, nil); err != nil {
		t.Fatal(err)
	}
	if len(j.Entries()) != 0 {
		t.Fatalf("left: %v", j.Entries())
	}
	for _, c := range r.cmds {
		if strings.HasPrefix(c, "netsh") || strings.HasPrefix(c, "reg delete") {
			t.Fatalf("ran an undo with nothing to undo: %s", c)
		}
	}
}

func TestPersistentUndoFailureStaysJournaled(t *testing.T) {
	j, err := OpenJournal(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	route := Step{Name: netshCmd, Args: []string{"interface", "ipv4", "delete", "route", "prefix=192.168.1.0/24", "interface=12", "store=active"}, Persistent: true}
	j.Record("wg0", []Step{route})
	r := &recorder{out: map[string]string{"route print -4": routePrint4}, failOn: "netsh"}
	if err := Cleanup(context.Background(), r, j, nil); err == nil {
		t.Fatal("no error")
	}
	if len(j.Entries()["wg0"]) != 1 {
		t.Fatal("a route still in place must stay journaled")
	}
}

func TestExistingRouteLeftAlone(t *testing.T) {
	table := routePrint4 + "   198.51.100.7  255.255.255.255  10.20.0.1  10.20.0.7  35\n"
	add := "netsh interface ipv4 add route prefix=198.51.100.7/32 interface=12 nexthop=192.168.1.1 store=active"
	r := &recorder{out: map[string]string{"route print -4": table}, fail: map[string]error{add: errors.New("exit status 1")}}
	c := windowsConfigurer(r, nil)
	_, err := c.Apply(context.Background(), Plan{Iface: "wg0", Addresses: pfx("10.9.0.2/32"), Routes: pfx("0.0.0.0/0"),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820")}})
	if err != nil {
		t.Fatalf("a route already there failed the connect: %v", err)
	}
	r.cmds = nil
	c.Remove(context.Background())
	for _, cmd := range r.cmds {
		if strings.Contains(cmd, "delete route prefix=198.51.100.7/32") {
			t.Fatalf("deleted a route that is not ours: %s", cmd)
		}
	}
}

func TestRouteFailureWithoutRouteIsAnError(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4}, failOn: "netsh interface ipv4 add route prefix=198"}
	c := windowsConfigurer(r, nil)
	_, err := c.Apply(context.Background(), Plan{Iface: "wg0", Addresses: pfx("10.9.0.2/32"), Routes: pfx("0.0.0.0/0"),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820")}})
	if err == nil {
		t.Fatal("no error")
	}
}

func TestInterfaceGUIDStable(t *testing.T) {
	a, b := WindowsInterfaceGUID("wg0"), WindowsInterfaceGUID("wg1")
	if a == b || a != WindowsInterfaceGUID("wg0") {
		t.Fatal(a, b)
	}
	if len(a) != 38 || a[0] != '{' || a[37] != '}' || a[9] != '-' || a[15] != '5' {
		t.Fatal(a)
	}
}

func TestWindowsMoveBackoff(t *testing.T) {
	r := &recorder{out: map[string]string{"route print -4": routePrint4}}
	c, _ := fullRefreshFixture(t, r)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	r.out["route print -4"] = strings.ReplaceAll(routePrint4, "192.168.1.1 ", "192.168.1.254 ")
	r.failOn = "netsh interface ipv4 add route"
	c.Refresh(context.Background())
	r.cmds = nil
	c.Refresh(context.Background())
	for _, cmd := range r.cmds {
		if strings.HasPrefix(cmd, "netsh") {
			t.Fatalf("retried inside the backoff: %s", cmd)
		}
	}
}
