package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/netcfg"
	"github.com/Kodviva/latchwire/internal/netmon"
)

const (
	netHome = "0123456789abcdef" // trusted in these tests
	netCafe = "fedcba9876543210"
	netAir  = "00112233445566ff"
)

// fakeNet is the network the daemon sees (Manager.networkID). The answers
// set are given in turn; the last one repeats.
type fakeNet struct {
	mu    sync.Mutex
	ids   []string
	calls int
}

func (n *fakeNet) set(ids ...string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = ids
}

func (n *fakeNet) id(context.Context) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	id := n.ids[0]
	if len(n.ids) > 1 {
		n.ids = n.ids[1:]
	}
	return id, nil
}

func (n *fakeNet) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls
}

// waitCalls waits until the network was looked up at least want times.
func (n *fakeNet) waitCalls(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for n.count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("network looked up %d times, want %d", n.count(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// quiet waits until the network has not been looked up for 500 ms and
// returns the number of lookups; lookups that go on for 5 s are a loop.
func (n *fakeNet) quiet(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c := n.count()
		time.Sleep(500 * time.Millisecond)
		if n.count() == c {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("the network is still looked up again and again (%d times)", n.count())
		}
	}
}

// odEnv is an env whose daemon sees net and gets the network notifications
// sent to the returned source. The P9 re-check waits 50 ms.
func odEnv(t *testing.T, o envOpts, net *fakeNet) (*env, chanSource) {
	t.Helper()
	notes := make(chanSource)
	hook := o.hook
	o.hook = func(m *Manager) {
		m.netSource = func() (netmon.Source, error) { return notes, nil }
		m.networkID = net.id
		m.odRecheck = 50 * time.Millisecond
		if hook != nil {
			hook(m)
		}
	}
	return newEnv(t, o), notes
}

// setOnDemand turns on-demand on for the test tunnel, trusting trust.
func setOnDemand(t *testing.T, m *Manager, trust ...string) {
	t.Helper()
	yes := true
	if _, err := m.setPolicy(ipc.TunnelPolicySet{Name: tunName, OnDemand: &yes, Trust: trust}); err != nil {
		t.Fatal(err)
	}
}

// change reports a network change and waits until the daemon has looked
// the network up (at least) n more times.
func change(t *testing.T, notes chanSource, net *fakeNet, n int) {
	t.Helper()
	before := net.count()
	notes <- "en0"
	net.waitCalls(t, before+n)
}

// stays checks that the tunnel is (still) in state a moment later.
func (e *env) stays(state string) {
	e.t.Helper()
	time.Sleep(300 * time.Millisecond)
	if st := e.status(); st.State != state {
		e.t.Fatalf("state %q, want %q", st.State, state)
	}
}

func (e *env) onDemandBound() bool {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return e.m.tunnels[tunName].odConnected
}

// On a network that is not trusted, an on-demand tunnel connects when the
// network changes and when an agent registers with its card; on a trusted
// one it does not. "none" (no network) connects nothing; "unknown" is not
// trusted (P10).
func TestOnDemandConnectsOnUntrusted(t *testing.T) {
	net := &fakeNet{}
	net.set(netHome)
	e, notes := odEnv(t, envOpts{present: []uint32{serialA}, noAgent: true}, net)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	setOnDemand(t, e.m, netHome)

	e.startAgent()
	e.waitAgentRegistered(uidA)
	net.waitCalls(t, 1)
	e.stays(StateDisconnected)
	change(t, notes, net, 1)
	e.stays(StateDisconnected)
	net.set(netmon.NoNetwork)
	change(t, notes, net, 1)
	e.stays(StateDisconnected)
	if n := e.p.count(); n != 0 {
		t.Fatalf("asked for the PIN %d times on a trusted network / no network", n)
	}

	net.set(netCafe)
	change(t, notes, net, 1)
	e.waitState(StateConnected, 5*time.Second)
	if !e.onDemandBound() {
		t.Fatal("not marked as connected on demand")
	}
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	// At login: the agent registering connects it.
	e2 := newEnvOD(t, netmon.UnknownNetwork)
	e2.startAgent()
	e2.waitState(StateConnected, 5*time.Second)
	if !e2.onDemandBound() {
		t.Fatal("not marked as connected on demand")
	}
}

// newEnvOD is an on-demand tunnel on card A (allowed: A) whose daemon sees
// the network id; no agent runs yet.
func newEnvOD(t *testing.T, id string) *env {
	t.Helper()
	net := &fakeNet{}
	net.set(id)
	e, _ := odEnv(t, envOpts{present: []uint32{serialA}, noAgent: true}, net)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	setOnDemand(t, e.m, netHome)
	return e
}

// On a trusted network a tunnel connected on demand is taken down as by
// down: the kill switch stops blocking. A tunnel connected by hand stays.
func TestOnDemandDisconnectsOnTrusted(t *testing.T) {
	net := &fakeNet{}
	net.set(netCafe)
	e, notes := odEnv(t, envOpts{present: []uint32{serialA}}, net)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, KillSwitch: KillSwitchOn}); err != nil {
		t.Fatal(err)
	}
	setOnDemand(t, e.m, netHome)
	e.waitCard(serialA, true)
	change(t, notes, net, 1)
	e.waitState(StateConnected, 5*time.Second)
	if st := e.status(); st.KillSwitch != ipc.KillSwitchStatusArmed {
		t.Fatalf("kill switch %q, want armed", st.KillSwitch)
	}

	net.set(netHome)
	change(t, notes, net, 1)
	e.waitState(StateDisconnected, 5*time.Second)
	if st := e.status(); st.KillSwitch != ipc.KillSwitchStatusOff {
		t.Fatalf("kill switch %q after the on-demand disconnect, want off", st.KillSwitch)
	}
	sets := e.fw.all()
	if len(sets) == 0 || sets[len(sets)-1].Block {
		t.Fatalf("kill switch still blocking on the trusted network: %+v", sets)
	}

	// Connected by hand on the trusted network: on-demand leaves it, here
	// and after a round trip through an untrusted network.
	e.connect()
	if e.onDemandBound() {
		t.Fatal("a connect by hand marked as on demand")
	}
	change(t, notes, net, 1)
	e.stays(StateConnected)
	net.set(netCafe)
	change(t, notes, net, 1)
	net.set(netHome)
	change(t, notes, net, 1)
	e.stays(StateConnected)
}

// A down by hand keeps on-demand from connecting the tunnel again on the
// same network, also when the card comes back or the network briefly
// cannot be identified; on another network it connects again.
func TestManualDownSuppressesUntilNetworkChanges(t *testing.T) {
	net := &fakeNet{}
	net.set(netCafe)
	e, notes := odEnv(t, envOpts{present: []uint32{serialA}}, net)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	setOnDemand(t, e.m, netHome)
	e.waitCard(serialA, true)
	change(t, notes, net, 1)
	e.waitState(StateConnected, 5*time.Second)

	if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	change(t, notes, net, 1)
	e.stays(StateDisconnected)
	e.b.setPresent(serialA, false)
	e.waitAgentCard(uidA, serialA, false)
	e.b.setPresent(serialA, true)
	e.waitAgentCard(uidA, serialA, true)
	e.stays(StateDisconnected)
	net.set(netmon.UnknownNetwork, netCafe)
	change(t, notes, net, 2)
	e.stays(StateDisconnected)
	net.set(netmon.NoNetwork)
	change(t, notes, net, 1)
	net.set(netCafe)
	change(t, notes, net, 1)
	e.stays(StateDisconnected)

	net.set(netAir)
	change(t, notes, net, 1)
	e.waitState(StateConnected, 5*time.Second)
}

// On-demand connects only for an allowed user (or an administrator): a user
// who is not allowed reporting the card, even with the key, connects
// nothing and is not asked for anything (P20).
func TestOnDemandRespectsAllowedUsers(t *testing.T) {
	net := &fakeNet{}
	net.set(netCafe)
	e, notes := odEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin}, net)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), 0); err != nil {
		t.Fatal(err)
	}
	setOnDemand(t, e.m)
	e.waitAgentCard(uidA, serialA, true)
	fb := newFakeAgent(t, e, uidB, e.b.cards[serialA].key, serialA)
	change(t, notes, net, 1)
	e.stays(StateDisconnected)
	if n := fb.publics.Load(); n != 0 {
		t.Fatalf("B's agent was asked %d times", n)
	}
	if n := e.p.count(); n != 0 {
		t.Fatalf("A was asked for its PIN %d times", n)
	}
	if n := e.f.count(); n != 0 {
		t.Fatalf("%d devices made", n)
	}

	e.allow(uidA)
	change(t, notes, net, 1)
	e.waitState(StateConnected, 5*time.Second)
	if u := e.boundUID(); u != uidA {
		t.Fatalf("bound to %d, want A", u)
	}
	if n := fb.publics.Load(); n != 0 {
		t.Fatalf("B's agent was asked %d times", n)
	}
}

// P9: an unidentified network is looked up again before anything is done;
// a trusted network found then connects nothing. Still unknown, it is
// untrusted (P10).
func TestOnDemandRechecksUnknownNetwork(t *testing.T) {
	net := &fakeNet{}
	net.set(netHome)
	e, notes := odEnv(t, envOpts{present: []uint32{serialA}}, net)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	setOnDemand(t, e.m, netHome)
	e.waitCard(serialA, true)

	net.set(netmon.UnknownNetwork, netHome)
	change(t, notes, net, 2)
	e.stays(StateDisconnected)
	if n := e.p.count(); n != 0 {
		t.Fatalf("asked for the PIN %d times", n)
	}

	net.set(netmon.UnknownNetwork)
	change(t, notes, net, 2)
	e.waitState(StateConnected, 5*time.Second)
}

// A failed on-demand connect (here: the agent's key is not the configured
// one; in life a cancelled PIN) is not retried at every network event or
// tick, nor when the same agent registers again with the same cards; a card
// reported again or another network retries it once.
func TestOnDemandFailsOnce(t *testing.T) {
	net := &fakeNet{}
	net.set(netCafe)
	e, notes := odEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin, verifyEvery: 50 * time.Millisecond}, net)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), uidB); err != nil {
		t.Fatal(err)
	}
	setOnDemand(t, e.m)
	fb := newFakeAgent(t, e, uidB, otherKey(t), serialA)
	waitCount := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for fb.publics.Load() < want {
			if time.Now().After(deadline) {
				t.Fatalf("%d attempts, want %d", fb.publics.Load(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(300 * time.Millisecond)
		if n := fb.publics.Load(); n != want {
			t.Fatalf("%d attempts, want %d", n, want)
		}
	}
	waitCount(1) // at registration
	for range 3 {
		change(t, notes, net, 1)
	}
	e.m.agentRegister(fb.dc, uidB, []uint32{serialA})
	waitCount(1)
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardRemoved, Serial: serialA})
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardInserted, Serial: serialA})
	waitCount(2)
	net.set(netAir)
	change(t, notes, net, 1)
	waitCount(3)
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q after failed attempts, want disconnected", st.State)
	}
}

// The evaluation is idempotent: the route changes of its own connect and
// disconnect, and a burst of notifications, do not set off further
// connects or disconnects (no loop, no flapping), and a burst is looked at
// once or twice, not per notification.
func TestOnDemandNoLoopOnOwnRouteChanges(t *testing.T) {
	net := &fakeNet{}
	net.set(netCafe)
	var notes chanSource
	echo := func() { // what our own routes do to the routing socket
		go func() {
			select {
			case notes <- "en0":
			case <-time.After(5 * time.Second):
			}
		}()
	}
	hook := func(m *Manager) {
		inner := m.tun
		m.tun = func(name string, mtu int) (tun.Device, netcfg.Configurer, error) {
			d, c, err := inner(name, mtu)
			echo()
			return d, c, err
		}
	}
	e, n := odEnv(t, envOpts{present: []uint32{serialA}, hook: hook}, net)
	notes = n
	e.f.onRemove = echo
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	setOnDemand(t, e.m, netHome)
	e.waitCard(serialA, true)

	change(t, notes, net, 1)
	e.waitState(StateConnected, 5*time.Second)
	if c := net.quiet(t); c > 3 {
		t.Fatalf("network looked up %d times for one change and one connect", c)
	}

	before := net.count()
	for range 20 {
		notes <- "en0"
	}
	if c := net.quiet(t) - before; c < 1 || c > 2 {
		t.Fatalf("a burst of 20 notifications looked the network up %d times", c)
	}
	if n := e.f.count(); n != 1 {
		t.Fatalf("%d devices made, want 1", n)
	}

	net.set(netHome)
	change(t, notes, net, 1)
	e.waitState(StateDisconnected, 5*time.Second)
	before = net.count()
	if c := net.quiet(t) - before; c > 2 {
		t.Fatalf("network looked up %d times after one change and one disconnect", c)
	}
	if n := e.f.count(); n != 1 {
		t.Fatalf("%d devices made after the disconnect, want 1", n)
	}
}

// network.current answers the network ID (with the P9 re-check) to users
// who may see the status.
func TestNetworkCurrent(t *testing.T) {
	net := &fakeNet{}
	net.set(netmon.UnknownNetwork, netCafe)
	e, _ := odEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin}, net)
	e.waitAgentRegistered(uidA)
	var got ipc.NetworkCurrent
	if err := e.call(ipc.MethodNetworkCurrent, nil, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != netCafe {
		t.Fatalf("network.current %q, want %q", got.ID, netCafe)
	}

	e2 := newEnv(t, envOpts{present: []uint32{}, notAdmin: true, noAgent: true})
	assertCode(t, e2.call(ipc.MethodNetworkCurrent, nil, nil), ipc.CodeForbidden)
}
