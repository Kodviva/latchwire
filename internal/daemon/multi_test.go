package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

// multiEnv is an environment for several tunnels on card A whose peers
// never answer (connect does not wait for a handshake). Full tunnels are
// supported; table says whether the platform picks a routing table
// (Linux) or not (macOS).
func multiEnv(t *testing.T, table bool) *env {
	t.Helper()
	hook := func(m *Manager) {
		m.fullTunnel = true
		m.pickTable = nil
		if table {
			m.pickTable = func(context.Context) (uint32, error) { return 51820, nil }
			real := m.ops.ipcSet
			m.ops.ipcSet = func(d *device.Device, s string) error {
				// The test's sockets cannot take SO_MARK.
				s, _ = strings.CutPrefix(s, "fwmark=51820\n")
				return real(d, s)
			}
		}
	}
	e := newEnv(t, envOpts{present: []uint32{serialA}, hook: hook})
	e.waitCard(serialA, true)
	return e
}

// addTunnel adds tunnel name routing allowed (comma separated) to a peer
// that never answers; iface is extra [Interface] lines (DNS, ListenPort).
func (e *env) addTunnel(name, allowed, iface string) {
	e.t.Helper()
	pub := e.b.pub(serialA)
	var peer [32]byte
	peer[0] = 7
	cfg := fmt.Sprintf("[Interface]\nMTU = 1420\n%s[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = 10.0.0.2/32\n"+
		"[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\nAllowedIPs = %s\n",
		iface, refA, base64.StdEncoding.EncodeToString(pub[:]), base64.StdEncoding.EncodeToString(peer[:]), allowed)
	if err := e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: name, Config: cfg}, nil); err != nil {
		e.t.Fatalf("tunnel.add %s: %v", name, err)
	}
}

func (e *env) connectTunnel(name string) (ipc.TunnelStatus, error) {
	var st ipc.TunnelStatus
	err := e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: name}, &st)
	return st, err
}

func (e *env) mustConnect(name string) {
	e.t.Helper()
	st, err := e.connectTunnel(name)
	if err != nil {
		e.t.Fatalf("connect %s: %v", name, err)
	}
	if st.State != StateConnected {
		e.t.Fatalf("connect %s: state %q", name, st.State)
	}
}

func (e *env) statusOf(name string) ipc.TunnelStatus {
	e.t.Helper()
	var all []ipc.TunnelStatus
	if err := e.call(ipc.MethodTunnelStatus, ipc.TunnelName{Name: name}, &all); err != nil || len(all) != 1 {
		e.t.Fatalf("tunnel.status %s: %v %+v", name, err, all)
	}
	return all[0]
}

// cfgFor returns the newest Configurer made for tunnel name (nil: none).
func (f *netFactory) cfgFor(name string) *recCfg {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.names) - 1; i >= 0; i-- {
		if f.names[i] == name {
			return f.cfgs[i]
		}
	}
	return nil
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func wantRefused(t *testing.T, err error, want string) {
	t.Helper()
	var ie *ipc.Error
	if !errors.As(err, &ie) {
		t.Fatalf("connect error %v, want an ipc.Error", err)
	}
	if ie.Code != ipc.CodeBadRequest || ie.Message != want {
		t.Fatalf("connect refused with %s %q, want %s %q", ie.Code, ie.Message, ipc.CodeBadRequest, want)
	}
}

// A second tunnel that would break the first is refused before anything of
// it is built: the first tunnel's Configurer is not called again, no device
// is made, the kill switch is not touched, and both keep their states.
func TestSecondTunnelConflictsRefusedFirstUntouched(t *testing.T) {
	port := freeUDPPort(t)
	for _, tc := range []struct {
		name                    string
		first, second           string // AllowedIPs
		firstIface, secondIface string
		want                    string
	}{
		{"second full tunnel", "0.0.0.0/0", "::/0, 10.5.0.0/16", "", "",
			fmt.Sprintf(msg.DaemonConflictFullFmt, "one")},
		{"overlapping AllowedIPs", "10.1.0.0/16", "10.2.0.0/16, 10.1.2.0/24", "", "",
			fmt.Sprintf(msg.DaemonConflictAllowedIPsFmt, "10.1.2.0/24", "10.1.0.0/16", "one")},
		{"same ListenPort", "10.1.0.0/16", "10.2.0.0/16", fmt.Sprintf("ListenPort = %d\n", port), fmt.Sprintf("ListenPort = %d\n", port),
			fmt.Sprintf(msg.DaemonConflictListenPortFmt, port, "one")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := multiEnv(t, false)
			e.addTunnel("one", tc.first, tc.firstIface)
			e.addTunnel("two", tc.second, tc.secondIface)
			e.mustConnect("one")
			first := e.f.cfgFor("one")
			calls, devices, sets := first.calls(), e.f.count(), len(e.fw.all())

			_, err := e.connectTunnel("two")
			wantRefused(t, err, tc.want)

			if n := first.calls(); n != calls {
				t.Errorf("the first tunnel's Configurer was called %d more time(s)", n-calls)
			}
			if n := e.f.count(); n != devices {
				t.Errorf("%d device(s) made for the refused tunnel", n-devices)
			}
			if n := len(e.fw.all()); n != sets {
				t.Errorf("the kill switch was set %d more time(s): %+v", n-sets, e.fw.all())
			}
			if st := e.statusOf("one"); st.State != StateConnected {
				t.Errorf("first tunnel %q, want connected", st.State)
			}
			if st := e.statusOf("two"); st.State != StateDisconnected {
				t.Errorf("refused tunnel %q, want disconnected", st.State)
			}
		})
	}

	// A split tunnel next to a full tunnel does not conflict: its more
	// specific routes win; nor do different ports or disjoint AllowedIPs.
	e := multiEnv(t, false)
	e.addTunnel("full", "0.0.0.0/0, ::/0", fmt.Sprintf("ListenPort = %d\n", port))
	e.addTunnel("lab", "10.1.0.0/16", "")
	e.addTunnel("corp", "10.2.0.0/16, fd00::/64", "")
	e.mustConnect("full")
	e.mustConnect("lab")
	e.mustConnect("corp")
}

// Two conflicting connects racing each other: exactly one wins, whatever
// the order in which their agents answer.
func TestConflictingConnectsRaceOneWins(t *testing.T) {
	for range 5 {
		e := multiEnv(t, false)
		e.addTunnel("a", "10.1.0.0/16", "")
		e.addTunnel("b", "10.1.0.0/24", "")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, n := range []string{"a", "b"} {
			wg.Go(func() { _, errs[i] = e.connectTunnel(n) })
		}
		wg.Wait()
		if (errs[0] == nil) == (errs[1] == nil) {
			t.Fatalf("errors %v, want exactly one refusal", errs)
		}
		if e.f.count() != 1 {
			t.Fatalf("%d devices, want 1", e.f.count())
		}
		e.stop()
	}
}

// The first tunnel to claim it (or a full tunnel) answers every name; later
// ones with search domains get them scoped, the others' servers are not
// applied (status "ignored"). Nobody is promoted when the owner goes; the
// next tunnel to connect takes it.
func TestDNSOwnership(t *testing.T) {
	e := multiEnv(t, false)
	e.addTunnel("first", "10.1.0.0/16", "DNS = 10.1.0.53\n")
	e.addTunnel("scoped", "10.2.0.0/16", "DNS = 10.2.0.53, corp.example\n")
	e.addTunnel("ignored", "10.3.0.0/16", "DNS = 10.3.0.53\n")
	e.addTunnel("nodns", "10.4.0.0/16", "")
	for _, n := range []string{"first", "scoped", "ignored", "nodns"} {
		e.mustConnect(n)
	}
	for _, tc := range []struct {
		name   string
		role   netcfg.DNSRole
		status string
	}{
		{"first", netcfg.DNSPrimary, "primary"},
		{"scoped", netcfg.DNSScoped, "scoped"},
		{"ignored", netcfg.DNSNone, "ignored"},
		{"nodns", netcfg.DNSNone, "none"},
	} {
		c := e.f.cfgFor(tc.name)
		c.mu.Lock()
		role := c.dnsRole
		c.mu.Unlock()
		if role != tc.role {
			t.Errorf("%s: role %v, want %v", tc.name, role, tc.role)
		}
		if st := e.statusOf(tc.name); st.DNS != tc.status {
			t.Errorf("%s: status DNS %q, want %q", tc.name, st.DNS, tc.status)
		}
	}

	// The owner goes: the others keep their roles; the next to connect
	// answers every name.
	if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: "first"}, nil); err != nil {
		t.Fatal(err)
	}
	if st := e.statusOf("ignored"); st.DNS != "ignored" {
		t.Errorf("after the owner left: %q, want ignored (no promotion)", st.DNS)
	}
	e.addTunnel("next", "10.5.0.0/16", "DNS = 10.5.0.53\n")
	e.mustConnect("next")
	if st := e.statusOf("next"); st.DNS != "primary" {
		t.Errorf("next: %q, want primary", st.DNS)
	}

	// A full tunnel answers every name, a split one beside it does not.
	e2 := multiEnv(t, false)
	e2.addTunnel("full", "0.0.0.0/0", "DNS = 10.9.0.53\n")
	e2.addTunnel("split", "10.1.0.0/16", "DNS = 10.1.0.53\n")
	e2.mustConnect("full")
	e2.mustConnect("split")
	if st := e2.statusOf("full"); st.DNS != "primary" {
		t.Errorf("full: %q, want primary", st.DNS)
	}
	if st := e2.statusOf("split"); st.DNS != "ignored" || st.Warning != msg.DaemonWarnDNSIgnored {
		t.Errorf("split beside full: %q, want ignored", st.DNS)
	}

	// P18: a full tunnel connecting after a split owner demotes it before
	// its own Apply: scoped with search domains, else ignored.
	for _, tc := range []struct {
		line, status string
		role         netcfg.DNSRole
	}{
		{"DNS = 10.1.0.53\n", "ignored", netcfg.DNSNone},
		{"DNS = 10.1.0.53, corp.example\n", "scoped", netcfg.DNSScoped},
	} {
		e3 := multiEnv(t, false)
		e3.addTunnel("split", "10.1.0.0/16", tc.line)
		e3.addTunnel("full", "0.0.0.0/0", "DNS = 10.9.0.53\n")
		e3.mustConnect("split")
		e3.mustConnect("full")
		sc, fc := e3.f.cfgFor("split"), e3.f.cfgFor("full")
		sc.mu.Lock()
		sets, srole := slices.Clone(sc.roleSets), sc.dnsRole
		sc.mu.Unlock()
		fc.mu.Lock()
		frole := fc.dnsRole
		fc.mu.Unlock()
		if !slices.Equal(sets, []netcfg.DNSRole{tc.role}) || srole != tc.role {
			t.Errorf("%q: split SetDNSRole %v (role %v), want [%v]", tc.line, sets, srole, tc.role)
		}
		if frole != netcfg.DNSPrimary {
			t.Errorf("%q: full role %v, want primary", tc.line, frole)
		}
		if st := e3.statusOf("full"); st.DNS != "primary" || st.Warning != "" {
			t.Errorf("%q: full status %+v", tc.line, st)
		}
		if st := e3.statusOf("split"); st.DNS != tc.status {
			t.Errorf("%q: split status %q, want %q", tc.line, st.DNS, tc.status)
		}
		e3.stop()
	}
}

// P18: when the split tunnel's DNS cannot be demoted, the full tunnel is
// refused before anything of it is built, and its reservation undone.
func TestFullTunnelRefusedWhenDemotionFails(t *testing.T) {
	e := multiEnv(t, false)
	e.addTunnel("split", "10.1.0.0/16", "DNS = 10.1.0.53\n")
	e.addTunnel("full", "0.0.0.0/0", "DNS = 10.9.0.53\n")
	e.mustConnect("split")
	sc := e.f.cfgFor("split")
	sc.mu.Lock()
	sc.roleErr = errors.New("resolvectl revert wg0: exit status 1")
	sc.mu.Unlock()
	devices, sets := e.f.count(), len(e.fw.all())

	_, err := e.connectTunnel("full")
	var ie *ipc.Error
	want := fmt.Sprintf(msg.DaemonDemoteFailedFmt, "split", "resolvectl revert wg0: exit status 1")
	if !errors.As(err, &ie) || ie.Code != ipc.CodeInternal || ie.Message != want {
		t.Fatalf("connect error %v, want %s %q", err, ipc.CodeInternal, want)
	}
	if n := e.f.count(); n != devices {
		t.Errorf("%d device(s) made for the refused tunnel", n-devices)
	}
	if n := len(e.fw.all()); n != sets {
		t.Errorf("the kill switch was set: %+v", e.fw.all()[sets:])
	}
	if st := e.statusOf("full"); st.State != StateDisconnected || st.Identity != "" || st.KillSwitch != "off" {
		t.Errorf("refused full tunnel: %+v", st)
	}
	if st := e.statusOf("split"); st.State != StateConnected || st.DNS != "primary" {
		t.Errorf("split after the failed demotion: %+v", st)
	}
	// It works once the split tunnel's DNS can be changed.
	sc.mu.Lock()
	sc.roleErr = nil
	sc.mu.Unlock()
	e.mustConnect("full")
	if st := e.statusOf("split"); st.DNS != "ignored" || st.Warning != msg.DaemonWarnDNSIgnored {
		t.Errorf("split after the demotion: %+v", st)
	}
}

// A split tunnel that is still connecting (its Apply not run yet) is
// demoted by changing the role its build reads; one that is going down
// is left alone.
func TestDemoteBeforeApplyAndAfterTeardown(t *testing.T) {
	m := NewManager(Options{})
	cfg := tunnelWith([]string{"10.1.0.0/16"})
	cfg.DNS, cfg.DNSSearch = []netip.Addr{netip.MustParseAddr("10.1.0.53")}, []string{"corp.example"}
	o := newTunnel("split", cfg, defaultPolicy())
	o.state, o.dnsRole = StateConnecting, netcfg.DNSPrimary
	m.tunnels["split"] = o
	if err := m.demote(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if o.dnsRole != netcfg.DNSScoped {
		t.Errorf("connecting split: role %v, want scoped", o.dnsRole)
	}
	o.state, o.dnsRole = StateDisconnected, netcfg.DNSPrimary
	if err := m.demote(context.Background(), o); err != nil || o.dnsRole != netcfg.DNSPrimary {
		t.Errorf("down split: %v, role %v", err, o.dnsRole)
	}
}

// A tunnel whose device is still being closed (state already
// disconnected) keeps its routes, port and DNS until then: it still
// counts for conflicts and the DNS role.
func TestTeardownWindowStillActive(t *testing.T) {
	m := NewManager(Options{})
	old := newTunnel("old", tunnelWith([]string{"10.1.0.0/16"}), defaultPolicy())
	old.cfg.Name = "old"
	old.cfg.DNS = []netip.Addr{netip.MustParseAddr("10.1.0.53")}
	old.state, old.dev, old.dnsRole = StateDisconnected, &device.Device{}, netcfg.DNSPrimary
	m.tunnels["old"] = old
	next := newTunnel("next", tunnelWith([]string{"10.1.2.0/24"}), defaultPolicy())
	m.tunnels["next"] = next
	m.mu.Lock()
	err := m.conflictLocked(next)
	next.cfg.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}
	next.cfg.DNS = []netip.Addr{netip.MustParseAddr("10.2.0.53")}
	role, _ := m.dnsRoleLocked(next)
	m.mu.Unlock()
	if err == nil {
		t.Error("no conflict with a tunnel whose device is still open")
	}
	if role != netcfg.DNSNone {
		t.Errorf("role %v next to a primary still closing, want none", role)
	}
}

func TestStatusShowsNetworkFields(t *testing.T) {
	e := multiEnv(t, false)
	e.addTunnel("full", "0.0.0.0/0", "DNS = 10.9.0.53\n")
	e.addTunnel("lab", "10.1.0.0/16", "")

	if st := e.statusOf("full"); st.KillSwitch != "off" || st.Interface != "" || st.MTU != 0 || st.DNS != "" || !st.FullTunnel {
		t.Errorf("disconnected full tunnel: %+v", st)
	}
	e.mustConnect("full")
	e.mustConnect("lab")
	c := e.f.cfgFor("full")
	c.mu.Lock()
	iface := c.iface
	c.mu.Unlock()
	want := ipc.TunnelStatus{Name: "full", State: StateConnected, Identity: refA.String(), Keys: []string{refA.String()},
		Interface: iface, MTU: 1420, FullTunnel: true, DNS: "primary", KillSwitch: "armed"}
	if st := e.statusOf("full"); !st.Equal(want) {
		t.Errorf("full:\n got %+v\nwant %+v", st, want)
	}
	lab := e.statusOf("lab")
	if lab.Interface == "" || lab.MTU != 1420 || lab.FullTunnel || lab.DNS != "none" || lab.KillSwitch != "off" || lab.Warning != "" {
		t.Errorf("lab: %+v", lab)
	}

	// The card goes: the full tunnel's kill switch blocks everything.
	e.b.setPresent(serialA, false)
	deadline := time.Now().Add(5 * time.Second)
	for e.statusOf("full").State != StateCardRemoved {
		if time.Now().After(deadline) {
			t.Fatal("card_removed not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := e.statusOf("full"); st.KillSwitch != "blocking" || st.Interface != "" || st.DNS != "" {
		t.Errorf("card removed: %+v", st)
	}

	// What the user should know: shared DNS, no reverse-path filter.
	e2 := multiEnv(t, true)
	e2.f.mu.Lock()
	e2.f.outcome, e2.f.noRPFilter = netcfg.DNSOutcomeResolvconfShared, true
	e2.f.mu.Unlock()
	e2.addTunnel("full", "0.0.0.0/0", "DNS = 10.9.0.53\n")
	e2.mustConnect("full")
	st := e2.statusOf("full")
	if st.DNS != "shared" || st.Warning != msg.DaemonWarnDNSShared+"; "+msg.DaemonWarnNoRPFilter {
		t.Errorf("shared DNS without rp filter: %+v", st)
	}
}

func TestDNSStatusMapping(t *testing.T) {
	for _, tc := range []struct {
		role    netcfg.DNSRole
		servers bool
		outcome string
		want    string
		warn    string
	}{
		{netcfg.DNSNone, false, netcfg.DNSOutcomeNone, "none", ""},
		{netcfg.DNSNone, true, netcfg.DNSOutcomeNone, "ignored", msg.DaemonWarnDNSIgnored},
		{netcfg.DNSPrimary, true, netcfg.DNSOutcomeResolved, "primary", ""},
		{netcfg.DNSPrimary, true, netcfg.DNSOutcomeResolvconf, "primary", ""},
		{netcfg.DNSPrimary, true, netcfg.DNSOutcomeScutilPrimary, "primary", ""},
		{netcfg.DNSPrimary, true, "", "ignored", msg.DaemonWarnDNSNotApplied},
		{netcfg.DNSScoped, true, "", "ignored", msg.DaemonWarnDNSNotApplied},
		{netcfg.DNSPrimary, true, netcfg.DNSOutcomeResolvconfShared, "shared", msg.DaemonWarnDNSShared},
		{netcfg.DNSPrimary, true, netcfg.DNSOutcomeScutilPrimaryOverridden, "overridden", msg.DaemonWarnDNSOverridden},
		{netcfg.DNSPrimary, true, netcfg.DNSOutcomePrimaryBusy, "busy", msg.DaemonWarnDNSBusy},
		{netcfg.DNSScoped, true, netcfg.DNSOutcomeResolved, "scoped", ""},
		{netcfg.DNSScoped, true, netcfg.DNSOutcomeScutilScoped, "scoped", ""},
		{netcfg.DNSScoped, true, netcfg.DNSOutcomeScopedUnsupported, "ignored", msg.DaemonWarnDNSScopedUnsupported},
	} {
		got, warn := dnsStatus(tc.role, tc.servers, tc.outcome)
		if got != tc.want || warn != tc.warn {
			t.Errorf("dnsStatus(%v, %v, %q) = %q, %q; want %q, %q", tc.role, tc.servers, tc.outcome, got, warn, tc.want, tc.warn)
		}
	}
}

// roleOf returns the DNS role tunnel name's newest Configurer has and the
// SetDNSRole calls it got.
func (e *env) roleOf(name string) (netcfg.DNSRole, []netcfg.DNSRole) {
	e.t.Helper()
	c := e.f.cfgFor(name)
	if c == nil {
		e.t.Fatalf("no Configurer for %s", name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dnsRole, slices.Clone(c.roleSets)
}

// P19: a full tunnel takes the role of answering every name from a split
// tunnel even without DNS servers of its own, in both orders: an existing
// split owner is demoted, and a split tunnel connecting beside it does not
// become primary. When the full tunnel goes, the split tunnel gets the role
// back.
func TestDNSLessFullTunnelHoldsDNS(t *testing.T) {
	for _, order := range []string{"split first", "full first"} {
		t.Run(order, func(t *testing.T) {
			e := multiEnv(t, false)
			e.addTunnel("split", "10.1.0.0/16", "DNS = 10.1.0.53\n")
			e.addTunnel("full", "0.0.0.0/0", "")
			if order == "split first" {
				e.mustConnect("split")
				if st := e.statusOf("split"); st.DNS != "primary" {
					t.Fatalf("split alone: %+v", st)
				}
				e.mustConnect("full")
				if role, sets := e.roleOf("split"); role != netcfg.DNSNone || !slices.Equal(sets, []netcfg.DNSRole{netcfg.DNSNone}) {
					t.Errorf("split after the full tunnel: role %v, SetDNSRole %v; want demoted to none", role, sets)
				}
			} else {
				e.mustConnect("full")
				e.mustConnect("split")
				if role, sets := e.roleOf("split"); role != netcfg.DNSNone || len(sets) != 0 {
					t.Errorf("split beside the full tunnel: role %v, SetDNSRole %v; want none", role, sets)
				}
			}
			if st := e.statusOf("split"); st.DNS != "ignored" || st.Warning != msg.DaemonWarnDNSIgnored {
				t.Errorf("split beside a DNS-less full tunnel: %+v", st)
			}
			if st := e.statusOf("full"); st.DNS != "none" {
				t.Errorf("full without DNS servers: %+v", st)
			}

			// The full tunnel goes: the split tunnel answers every name
			// again.
			if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: "full"}, nil); err != nil {
				t.Fatal(err)
			}
			role, sets := e.roleOf("split")
			if role != netcfg.DNSPrimary || len(sets) == 0 || sets[len(sets)-1] != netcfg.DNSPrimary {
				t.Errorf("split after the full tunnel left: role %v, SetDNSRole %v; want promoted", role, sets)
			}
			if st := e.statusOf("split"); st.DNS != "primary" || st.Warning != "" {
				t.Errorf("split after the full tunnel left: %+v", st)
			}
		})
	}
}

// A split tunnel demoted by a full tunnel with DNS servers is promoted back
// when the full tunnel disconnects (no other tunnel holds the role), with
// its search domains too; a split owner leaving still promotes nobody
// (TestDNSOwnership).
func TestDemotedSplitPromotedWhenFullTunnelLeaves(t *testing.T) {
	e := multiEnv(t, false)
	e.addTunnel("split", "10.1.0.0/16", "DNS = 10.1.0.53, corp.example\n")
	e.addTunnel("other", "10.2.0.0/16", "DNS = 10.2.0.53\n")
	e.addTunnel("full", "0.0.0.0/0", "DNS = 10.9.0.53\n")
	e.mustConnect("split")
	e.mustConnect("other") // ignored: split answers every name
	e.mustConnect("full")
	if st := e.statusOf("split"); st.DNS != "scoped" {
		t.Fatalf("demoted split: %+v", st)
	}
	if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: "full"}, nil); err != nil {
		t.Fatal(err)
	}
	if role, sets := e.roleOf("split"); role != netcfg.DNSPrimary || !slices.Equal(sets, []netcfg.DNSRole{netcfg.DNSScoped, netcfg.DNSPrimary}) {
		t.Errorf("split: role %v, SetDNSRole %v; want scoped then primary", role, sets)
	}
	if st := e.statusOf("split"); st.DNS != "primary" {
		t.Errorf("split after the full tunnel left: %+v", st)
	}
	// "other" never yielded to the full tunnel: it keeps its role.
	if role, sets := e.roleOf("other"); role != netcfg.DNSNone || len(sets) != 0 {
		t.Errorf("other: role %v, SetDNSRole %v; want untouched", role, sets)
	}
	// The full tunnel back: the split tunnel is demoted again.
	e.mustConnect("full")
	if role, _ := e.roleOf("split"); role != netcfg.DNSScoped {
		t.Errorf("split after the full tunnel came back: role %v, want scoped", role)
	}
}
