package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/ipc/ipctest"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/killswitch"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

const testNetwork = "0123456789abcdef"

// A missing policy is the default (kill switch auto, nothing else, only
// administrators); a saved one reads back the same from a 0600 file written
// without leftovers; "unknown" and "none" are never trusted networks (P10).
func TestPolicyDefaultsAndPersistence(t *testing.T) {
	s := &store{dir: t.TempDir()}
	p, err := s.loadPolicy(tunName)
	if want := (Policy{KillSwitch: KillSwitchAuto}); err != nil || !reflect.DeepEqual(p, want) {
		t.Fatalf("missing policy: %+v, %v; want %+v", p, err, want)
	}

	full := Policy{KillSwitch: KillSwitchOn, AutoConnect: true, OnDemand: true,
		TrustedNetworks: []string{testNetwork}, AllowedUsers: []uint32{501, 1000}}
	if err := s.savePolicy(tunName, full); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, tunName+".policy")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !modeIs(fi, 0o600) {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Errorf("store holds %d files after the write, want only the policy", len(ents))
	}
	got, err := s.loadPolicy(tunName)
	if err != nil || !reflect.DeepEqual(got, full) {
		t.Fatalf("read back %+v, %v; want %+v", got, err, full)
	}

	for _, id := range []string{"unknown", "none", "", "0123", "0123456789ABCDEF", "0123456789abcdeg"} {
		bad := Policy{KillSwitch: KillSwitchAuto, TrustedNetworks: []string{id}}
		if err := s.savePolicy(tunName, bad); err == nil {
			t.Errorf("saved a policy trusting %q", id)
		}
		if err := os.WriteFile(path, []byte(`{"trusted_networks":["`+id+`"]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.loadPolicy(tunName); err == nil {
			t.Errorf("loaded a policy trusting %q", id)
		}
		// Unusable: fail closed (kill switch on, nobody but administrators,
		// nothing automatic).
		if p := s.policyFor(tunName); !reflect.DeepEqual(p, failClosedPolicy()) {
			t.Errorf("policy trusting %q used as %+v", id, p)
		}
	}
}

// tunnel.add records the owner it is given (the CLI sends SUDO_UID) as the
// only allowed user and replaces whatever policy file was there; owner 0
// leaves the tunnel to administrators. remove deletes the policy.
func TestAddRecordsOwnerAsAllowedUser(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, noAgent: true})
	cfg := e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, &server{port: 51820}, "")
	path := filepath.Join(e.store, tunName+".policy")
	if err := os.MkdirAll(e.store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"kill_switch":"off","auto_connect":true,"allowed_users":[7]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: tunName, Config: cfg, Owner: uidB}, nil); err != nil {
		t.Fatal(err)
	}
	p, err := e.m.store.loadPolicy(tunName)
	if want := (Policy{KillSwitch: KillSwitchAuto, AllowedUsers: []uint32{uidB}}); err != nil || !reflect.DeepEqual(p, want) {
		t.Fatalf("policy after add: %+v, %v; want %+v", p, err, want)
	}
	if fi, err := os.Stat(path); err != nil || !modeIs(fi, 0o600) {
		t.Fatalf("policy file: %v, %v", fi, err)
	}
	if err := e.call(ipc.MethodTunnelRemove, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("policy file after remove: %v", err)
	}

	if err := e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: tunName, Config: cfg}, nil); err != nil {
		t.Fatal(err)
	}
	p, err = e.m.store.loadPolicy(tunName)
	want := Policy{KillSwitch: KillSwitchAuto}
	if runtime.GOOS == "windows" && len(p.AllowedUsers) == 1 {
		want.AllowedUsers = p.AllowedUsers // the user behind an elevated client
	}
	if err != nil || !reflect.DeepEqual(p, want) {
		t.Fatalf("policy after add without owner: %+v, %v; want %+v", p, err, want)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("add without owner wrote no policy: %v", err)
	}
}

// A user who is not in AllowedUsers cannot connect, even with the card in
// its own agent: refused before the agent is asked. Allowed, it can;
// denied again, it cannot; an administrator always can.
func TestNonAllowedUserCannotConnect(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), uidB); err != nil {
		t.Fatal(err)
	}
	e.waitCard(serialA, true)

	err := e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil)
	assertCode(t, err, ipc.CodeForbidden)
	if want := fmt.Sprintf(msg.DaemonNotAllowedUserFmt, tunName); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q, want %q", err, want)
	}
	e.unbound()
	if n := e.p.count(); n != 0 {
		t.Errorf("a refused user was asked for its PIN %d times", n)
	}
	if n := e.f.count(); n != 0 {
		t.Errorf("%d devices made for a refused user", n)
	}
	// An unknown tunnel is still "not found".
	assertCode(t, e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: "nope"}, nil), ipc.CodeNotFound)

	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Allow: []uint32{uidA}}); err != nil {
		t.Fatal(err)
	}
	if st := e.connect(); st.State != StateConnected {
		t.Fatalf("allowed user's connect: %+v", st)
	}
	if u := e.boundUID(); u != uidA {
		t.Fatalf("bound to %d, want A", u)
	}
	if _, err := e.m.requestDisconnect(uidA, tunName); err != nil {
		t.Fatal(err)
	}

	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Deny: []uint32{uidA}}); err != nil {
		t.Fatal(err)
	}
	_, err = e.m.requestConnect(context.Background(), uidA, tunName)
	assertCode(t, err, ipc.CodeForbidden)

	// The administrator is on nobody's list and connects through A's agent.
	st, err := e.m.requestConnect(context.Background(), uidAdmin, tunName)
	if err != nil || st.State != StateConnected {
		t.Fatalf("administrator's connect: %+v, %v", st, err)
	}
}

// waitAgentCard waits until uid's agent reports serial (want) or not.
func (e *env) waitAgentCard(uid, serial uint32, want bool) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for (e.m.agentFor(serial, uid) != nil) != want {
		if time.Now().After(deadline) {
			e.t.Fatalf("agent of uid %d reporting card %d: want %v", uid, serial, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func setAutoConnect(t *testing.T, m *Manager) {
	t.Helper()
	yes := true
	if _, err := m.setPolicy(ipc.TunnelPolicySet{Name: tunName, AutoConnect: &yes}); err != nil {
		t.Fatal(err)
	}
}

// Auto-connect: a user who is not allowed reporting the card connects
// nothing (whether or not it holds the key); an allowed user's agent
// reporting it connects the tunnel with that user's card; so does an
// administrator's agent.
func TestAutoConnectRespectsAllowedUsers(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), 0); err != nil {
		t.Fatal(err)
	}
	setAutoConnect(t, e.m)
	e.waitAgentRegistered(uidA)

	// B holds the card (the real key) but is not allowed; neither is A.
	fb := newFakeAgent(t, e, uidB, e.b.cards[serialA].key, serialA)
	e.b.setPresent(serialA, true)
	e.waitAgentCard(uidA, serialA, true)
	time.Sleep(300 * time.Millisecond)
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q after users who are not allowed reported the card", st.State)
	}
	if n := fb.publics.Load(); n != 0 {
		t.Fatalf("B's agent was asked %d times", n)
	}
	if n := e.p.count(); n != 0 {
		t.Fatalf("A was asked for its PIN %d times", n)
	}
	if n := e.f.count(); n != 0 {
		t.Fatalf("%d devices made", n)
	}

	// A is allowed: its agent reporting the card connects the tunnel.
	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Allow: []uint32{uidA}}); err != nil {
		t.Fatal(err)
	}
	e.b.setPresent(serialA, false)
	e.waitAgentCard(uidA, serialA, false)
	e.b.setPresent(serialA, true)
	e.waitState(StateConnected, 5*time.Second)
	if u := e.boundUID(); u != uidA {
		t.Fatalf("bound to %d, want A", u)
	}
	if n := fb.publics.Load(); n != 0 {
		t.Fatalf("B's agent was asked %d times", n)
	}
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	// An administrator's agent counts as allowed.
	if _, err := e.m.requestDisconnect(uidAdmin, tunName); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Deny: []uint32{uidA}}); err != nil {
		t.Fatal(err)
	}
	newFakeAgent(t, e, uidAdmin, e.b.cards[serialA].key, serialA)
	e.waitState(StateConnected, 5*time.Second)
	if u := e.boundUID(); u != uidAdmin {
		t.Fatalf("bound to %d, want the administrator", u)
	}
}

// A failed auto-connect is not retried until the card is reported again: a
// re-registration with the same cards or a repeated card_inserted does not
// count. A tunnel taken down by hand is not auto-connected again while the
// agents of that time stay; the next agent session connects it.
func TestAutoConnectOncePerEventAndNotAfterDown(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), uidB); err != nil {
		t.Fatal(err)
	}
	setAutoConnect(t, e.m)
	// B is allowed, but its agent holds another key: every attempt fails.
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
		time.Sleep(200 * time.Millisecond)
		if n := fb.publics.Load(); n != want {
			t.Fatalf("%d attempts, want %d", n, want)
		}
	}
	waitCount(1)
	e.m.agentRegister(fb.dc, uidB, []uint32{serialA})
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardInserted, Serial: serialA})
	waitCount(1)
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardRemoved, Serial: serialA})
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardInserted, Serial: serialA})
	waitCount(2)

	// A, allowed, logs in with the card: connected at once.
	e2 := newEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin, noAgent: true})
	srv2 := newServer(t, e2.b.pub(serialA), "10.0.0.2")
	if err := e2.m.add(tunName, e2.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv2, ""), uidA); err != nil {
		t.Fatal(err)
	}
	e2.allow(uidA) // owner 0 (tests run as root) is nobody
	setAutoConnect(t, e2.m)
	e2.startAgent()
	e2.waitAgentRegistered(uidA)
	e2.waitState(StateConnected, 5*time.Second)
	if err := e2.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	e2.b.setPresent(serialA, false)
	e2.waitAgentCard(uidA, serialA, false)
	e2.b.setPresent(serialA, true)
	e2.waitAgentCard(uidA, serialA, true)
	time.Sleep(300 * time.Millisecond)
	if st := e2.status(); st.State != StateDisconnected {
		t.Fatalf("state %q: auto-connected after a manual down", st.State)
	}
	e2.stopAgent()
	// The old agent's connection is gone before the next session starts.
	deadline := time.Now().Add(5 * time.Second)
	for e2.m.agentUser(uidA) {
		if time.Now().After(deadline) {
			t.Fatal("the stopped agent is still registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e2.startAgent()
	e2.waitAgentRegistered(uidA)
	e2.waitState(StateConnected, 5*time.Second)
}

// tunnel.policy.set is for administrators only; tunnel.policy.get for
// anyone who may see the status. Values are checked (P10: "unknown" and
// "none" are never trusted).
func TestPolicySetAdminOnly(t *testing.T) {
	var admin atomic.Bool
	e := newEnv(t, envOpts{present: []uint32{serialA}, admin: func(uint32) bool { return admin.Load() }})
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, &server{port: 51820}, ""), 0); err != nil {
		t.Fatal(err)
	}
	e.waitAgentRegistered(uidA)
	yes := true
	set := ipc.TunnelPolicySet{Name: tunName, AutoConnect: &yes, Allow: []uint32{uidA}}

	assertCode(t, e.call(ipc.MethodTunnelPolicySet, set, nil), ipc.CodeForbidden)
	if p, err := e.m.store.loadPolicy(tunName); err != nil || !reflect.DeepEqual(p, Policy{KillSwitch: KillSwitchAuto}) {
		t.Fatalf("policy after a refused set: %+v, %v", p, err)
	}
	var got ipc.TunnelPolicy
	if err := e.call(ipc.MethodTunnelPolicyGet, ipc.TunnelName{Name: tunName}, &got); err != nil {
		t.Fatalf("get as the agent's user: %v", err)
	}
	if want := (ipc.TunnelPolicy{Name: tunName, KillSwitch: KillSwitchAuto}); !reflect.DeepEqual(got, want) {
		t.Fatalf("get: %+v, want %+v", got, want)
	}

	admin.Store(true)
	if err := e.call(ipc.MethodTunnelPolicySet, set, &got); err != nil {
		t.Fatal(err)
	}
	if want := (ipc.TunnelPolicy{Name: tunName, KillSwitch: KillSwitchAuto, AutoConnect: true, AllowedUsers: []uint32{uidA}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("set: %+v, want %+v", got, want)
	}
	before, err := os.ReadFile(filepath.Join(e.store, tunName+".policy"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []ipc.TunnelPolicySet{
		{Name: tunName, Trust: []string{"unknown"}},
		{Name: tunName, Trust: []string{"none"}},
		{Name: tunName, Trust: []string{"office-wifi"}},
		{Name: tunName, KillSwitch: "maybe"},
	} {
		assertCode(t, e.call(ipc.MethodTunnelPolicySet, bad, nil), ipc.CodeBadRequest)
	}
	assertCode(t, e.call(ipc.MethodTunnelPolicySet, ipc.TunnelPolicySet{Name: "nope", AutoConnect: &yes}, nil), ipc.CodeNotFound)
	if after, _ := os.ReadFile(filepath.Join(e.store, tunName+".policy")); string(after) != string(before) {
		t.Fatalf("a refused set changed the file: %s", after)
	}

	no := false
	got = ipc.TunnelPolicy{}
	if err := e.call(ipc.MethodTunnelPolicySet, ipc.TunnelPolicySet{Name: tunName, KillSwitch: KillSwitchOn, OnDemand: &yes,
		AutoConnect: &no, Trust: []string{testNetwork, testNetwork}, Allow: []uint32{uidB, uidB}, Deny: []uint32{uidA}}, &got); err != nil {
		t.Fatal(err)
	}
	want := ipc.TunnelPolicy{Name: tunName, KillSwitch: KillSwitchOn, OnDemand: true, TrustedNetworks: []string{testNetwork}, AllowedUsers: []uint32{uidB}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("set: %+v, want %+v", got, want)
	}
	got = ipc.TunnelPolicy{}
	if err := e.call(ipc.MethodTunnelPolicySet, ipc.TunnelPolicySet{Name: tunName, Untrust: []string{testNetwork}}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.TrustedNetworks) != 0 {
		t.Fatalf("untrust left %v", got.TrustedNetworks)
	}
}

// P20: denying a user revokes: its binding goes down at once, and the card
// coming back reconnects nothing (no PIN asked). The connect gate also
// refuses the reconnect when the policy file changed without
// tunnel.policy.set.
func TestDenyRevokesUserBinding(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), 0); err != nil {
		t.Fatal(err)
	}
	e.allow(uidA)
	e.waitCard(serialA, true)
	e.connect()

	if got, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Deny: []uint32{uidA}}); err != nil || got.RevokedBlocking {
		t.Fatalf("deny: %+v, %v (no kill switch: nothing stays blocking)", got, err)
	}
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q after denying the bound user, want disconnected", st.State)
	}
	prompts := e.p.count()
	e.b.setPresent(serialA, false)
	e.waitAgentCard(uidA, serialA, false)
	e.b.setPresent(serialA, true)
	e.waitAgentCard(uidA, serialA, true)
	time.Sleep(300 * time.Millisecond)
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q after the card came back, want disconnected", st.State)
	}
	if n := e.p.count(); n != prompts {
		t.Fatalf("denied user asked for its PIN %d times", n-prompts)
	}

	// Card removed while allowed; the file then denies A (edited by hand):
	// the reconnect is refused by connect itself.
	e.allow(uidA)
	e.connect()
	e.b.setPresent(serialA, false)
	e.waitState(StateCardRemoved, 3*time.Second)
	if err := os.WriteFile(filepath.Join(e.store, tunName+".policy"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prompts = e.p.count()
	e.b.setPresent(serialA, true)
	e.waitAgentCard(uidA, serialA, true)
	time.Sleep(300 * time.Millisecond)
	if st := e.status(); st.State != StateCardRemoved {
		t.Fatalf("state %q after the card came back to a denied user, want card_removed", st.State)
	}
	if n := e.p.count(); n != prompts {
		t.Fatalf("denied user asked for its PIN %d times", n-prompts)
	}
}

// P20: a binding an administrator made (sudo up through B's agent) is not
// revoked by denying B and reconnects when B's card comes back.
func TestAdminBindingSurvivesDeny(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), 0); err != nil {
		t.Fatal(err)
	}
	fb := newFakeAgent(t, e, uidB, e.b.cards[serialA].key, serialA)
	if st, err := e.m.requestConnect(context.Background(), uidAdmin, tunName); err != nil || st.State != StateConnected {
		t.Fatalf("administrator's connect: %+v, %v", st, err)
	}
	if u := e.boundUID(); u != uidB {
		t.Fatalf("bound to %d, want B", u)
	}
	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Allow: []uint32{uidA}, Deny: []uint32{uidB}}); err != nil {
		t.Fatal(err)
	}
	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q: an administrator's binding was revoked", st.State)
	}
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardRemoved, Serial: serialA})
	e.waitState(StateCardRemoved, 3*time.Second)
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardInserted, Serial: serialA})
	e.waitState(StateConnected, 5*time.Second)
	if u := e.boundUID(); u != uidB {
		t.Fatalf("reconnected bound to %d, want B", u)
	}
}

// connect itself re-checks what autoConnect saw: a down marked since the
// report wins, and a tunnel replaced under the same name is not connected.
func TestAutoConnectRechecksInConnect(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	cfg := e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, "")
	if err := e.m.add(tunName, cfg, uidB); err != nil {
		t.Fatal(err)
	}
	fb := newFakeAgent(t, e, uidB, e.b.cards[serialA].key, serialA)
	e.m.mu.Lock()
	a := e.m.agents[fb.dc]
	old := e.m.tunnels[tunName]
	a.noAuto[tunName] = true
	e.m.mu.Unlock()
	ctx := context.Background()
	st, err := e.m.connect(ctx, tunName, uidB, false, connectOpts{onlyFrom: StateDisconnected, want: old, auto: a})
	if err != nil || st.State != StateDisconnected {
		t.Fatalf("auto-connect after a down: %+v, %v", st, err)
	}

	e.m.mu.Lock()
	delete(a.noAuto, tunName)
	e.m.mu.Unlock()
	if err := e.m.remove(tunName); err != nil {
		t.Fatal(err)
	}
	if err := e.m.add(tunName, cfg, uidB); err != nil {
		t.Fatal(err)
	}
	_, err = e.m.connect(ctx, tunName, uidB, false, connectOpts{onlyFrom: StateDisconnected, want: old, auto: a})
	assertCode(t, err, ipc.CodeUnavailable)
	if n := fb.publics.Load(); n != 0 {
		t.Fatalf("B's agent was asked %d times", n)
	}
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("replacement tunnel state %q", st.State)
	}
}

// tunnel.policy.get reports the kill switch a running tunnel still uses
// when the file now says otherwise.
func TestPolicyReportsKillSwitchInEffect(t *testing.T) {
	e, _ := connected(t, envOpts{})
	got, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, KillSwitch: KillSwitchOn})
	if err != nil {
		t.Fatal(err)
	}
	if got.KillSwitch != KillSwitchOn || got.KillSwitchInEffect != KillSwitchAuto {
		t.Fatalf("policy %+v, want on with auto in effect", got)
	}
	if _, err := e.m.requestDisconnect(uidA, tunName); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.getPolicy(tunName); got.KillSwitchInEffect != "" {
		t.Fatalf("disconnected tunnel reports %q in effect", got.KillSwitchInEffect)
	}
}

// A deny while the user's proof is in progress (the PIN being typed) is
// seen when the tunnel is reserved: refused, nothing bound, no device. The
// same for an auto-connect.
func TestDenyDuringProofRefused(t *testing.T) {
	for _, auto := range []bool{false, true} {
		e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
		srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
		if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), uidB); err != nil {
			t.Fatal(err)
		}
		if auto {
			setAutoConnect(t, e.m)
		}
		gate := make(chan struct{})
		fb := newLyingAgent(t, e, uidB, e.b.pub(serialA), e.b.cards[serialA].key, gate, serialA)
		done := make(chan error, 1)
		if !auto {
			go func() {
				_, err := e.m.requestConnect(context.Background(), uidB, tunName)
				done <- err
			}()
		}
		deadline := time.Now().Add(5 * time.Second)
		for fb.x25519s.Load() == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("auto %v: the proof never reached B's agent", auto)
			}
			time.Sleep(5 * time.Millisecond)
		}
		if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Deny: []uint32{uidB}}); err != nil {
			t.Fatal(err)
		}
		close(gate)
		if !auto {
			select {
			case err := <-done:
				assertCode(t, err, ipc.CodeForbidden)
				if want := fmt.Sprintf(msg.DaemonNotAllowedUserFmt, tunName); !strings.Contains(err.Error(), want) {
					t.Errorf("error %q, want %q", err, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("connect did not return")
			}
		} else {
			deadline := time.Now().Add(5 * time.Second)
			for {
				e.m.mu.Lock()
				pending := e.m.tunnels[tunName].autoPending
				e.m.mu.Unlock()
				if !pending {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("auto-connect did not end")
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		e.unbound()
		if n := e.f.count(); n != 0 {
			t.Fatalf("auto %v: %d devices made for a denied user", auto, n)
		}
	}
}

// P21: denying the user of a tunnel whose kill switch is on leaves it
// blocking but unbound (card_removed, no key, no user, also in the kill
// switch record); the denied user's card reconnects nothing and that user
// cannot take it down; an administrator's down lifts it.
func TestRevokeArmedTunnelKeepsBlocking(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, KillSwitch: KillSwitchOn, Allow: []uint32{uidA}}); err != nil {
		t.Fatal(err)
	}
	e.waitCard(serialA, true)
	e.connect()
	e.fw.waitLast(t, "armed", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 1 })

	got, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Deny: []uint32{uidA}})
	if err != nil || !got.RevokedBlocking {
		t.Fatalf("deny: %+v, %v; want RevokedBlocking", got, err)
	}
	st := e.status()
	if st.State != StateCardRemoved || st.Identity != "" || st.KillSwitch != ipc.KillSwitchStatusBlocking {
		t.Fatalf("status %+v, want card_removed, unbound, blocking", st)
	}
	if tn := e.tunnel(); tn.hasRef || tn.adminBound || tn.dev != nil {
		t.Fatalf("tunnel still bound or up: hasRef %v adminBound %v dev %v", tn.hasRef, tn.adminBound, tn.dev != nil)
	}
	e.fw.waitLast(t, "blocking, nothing passing", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 0 })
	rec, err := e.m.store.loadKillSwitchTunnels()
	if err != nil || !reflect.DeepEqual(rec, []ksTunnel{{Name: tunName}}) {
		t.Fatalf("kill switch record %+v, %v; want the tunnel unbound", rec, err)
	}

	prompts := e.p.count()
	e.b.setPresent(serialA, false)
	e.waitAgentCard(uidA, serialA, false)
	e.b.setPresent(serialA, true)
	e.waitAgentCard(uidA, serialA, true)
	time.Sleep(300 * time.Millisecond)
	if st := e.status(); st.State != StateCardRemoved {
		t.Fatalf("state %q after the denied user's card came back", st.State)
	}
	if n := e.p.count(); n != prompts {
		t.Fatalf("denied user asked for its PIN %d times", n-prompts)
	}
	assertCode(t, e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeForbidden)

	if _, err := e.m.requestDisconnect(uidAdmin, tunName); err != nil {
		t.Fatal(err)
	}
	e.fw.waitLast(t, "released", released)
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q after the administrator's down", st.State)
	}
}

// P21 for a failed tunnel: denying the user an armed tunnel in state error
// is bound to unbinds it too (it keeps blocking, in error), and the kill
// switch record says so, so a restart after a crash restores it unbound:
// the denied user's card reconnects nothing and that user cannot take it
// down.
func TestRevokeArmedErrorTunnelUnbinds(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, KillSwitch: KillSwitchOn, Allow: []uint32{uidA}}); err != nil {
		t.Fatal(err)
	}
	e.waitCard(serialA, true)
	// The kill switch cannot be set: the connect fails, bound to uidA.
	e.fw.setErr(errors.New("pfctl: /dev/pf: Permission denied"))
	assertCode(t, e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeInternal)
	if tn := e.tunnel(); tn.state != StateError || !tn.hasRef || tn.uid != uidA {
		t.Fatalf("failed connect: state %q hasRef %v uid %d", tn.state, tn.hasRef, tn.uid)
	}
	e.fw.setErr(nil)

	got, err := e.m.setPolicy(ipc.TunnelPolicySet{Name: tunName, Deny: []uint32{uidA}})
	if err != nil || !got.RevokedBlocking {
		t.Fatalf("deny: %+v, %v; want RevokedBlocking", got, err)
	}
	st := e.status()
	if st.State != StateError || st.Identity != "" || st.KillSwitch != ipc.KillSwitchStatusBlocking {
		t.Fatalf("status %+v, want error, unbound, blocking", st)
	}
	if tn := e.tunnel(); tn.hasRef || tn.uid != 0 || tn.adminBound {
		t.Fatalf("tunnel still bound: hasRef %v uid %d adminBound %v", tn.hasRef, tn.uid, tn.adminBound)
	}
	e.fw.waitLast(t, "blocking", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 0 })
	rec, err := e.m.store.loadKillSwitchTunnels()
	if err != nil || !reflect.DeepEqual(rec, []ksTunnel{{Name: tunName}}) {
		t.Fatalf("kill switch record %+v, %v; want the tunnel unbound", rec, err)
	}
	assertCode(t, e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeForbidden)

	// A crash now (the record and the journaled kill switch stay), then a
	// restart: the tunnel waits unbound.
	e.stop()
	if err := e.m.store.saveKillSwitchTunnels(rec); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(e.store)
	j, err := netcfg.OpenJournal(filepath.Join(dir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(killswitch.JournalOwner, []netcfg.Step{{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte("x"), Persistent: true}}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Options{Socket: ipctest.Path(t), StoreDir: e.store, JournalPath: filepath.Join(dir, "journal.json"),
		Runner: &cmdRunner{}, TUN: (&netFactory{}).make, Firewall: &fakeFirewall{},
		IsAdmin: func(uid uint32) (bool, error) { return onlyAdmin(uid), nil }})
	serveManager(t, m)
	m.mu.Lock()
	tn := m.tunnels[tunName]
	state, hasRef, uid := tn.state, tn.hasRef, tn.uid
	m.mu.Unlock()
	if state != StateCardRemoved || hasRef || uid != 0 {
		t.Fatalf("after the restart: state %q hasRef %v uid %d; want card_removed, unbound", state, hasRef, uid)
	}
}

// P23 (a): a user who gives up on its own connect after the tunnel was
// reserved (Ctrl-C during up, after the PIN) leaves the tunnel as it was,
// not failed: an armed tunnel that was disconnected stops blocking.
func TestCancelledConnectRestoresPriorState(t *testing.T) {
	var cancelCaller atomic.Pointer[context.CancelFunc]
	hook := func(m *Manager) {
		orig := m.tun
		m.tun = func(name string, mtu int) (tun.Device, netcfg.Configurer, error) {
			if c := cancelCaller.Load(); c != nil {
				(*c)() // the requester leaves while the device is made
				return nil, nil, context.Canceled
			}
			return orig(name, mtu)
		}
	}
	var setup atomic.Bool // the test process adds the tunnel as an administrator
	setup.Store(true)
	fe := newFullTunnelEnvOpts(t, true, true, envOpts{admin: func(uid uint32) bool { return uid == uidAdmin || uid == uidA && setup.Load() }, hook: hook})
	setup.Store(false)
	fe.allow(uidA)
	ctx, cancel := context.WithCancel(context.Background())
	cancelCaller.Store(&cancel)
	if _, err := fe.m.requestConnect(ctx, uidA, tunName); err == nil {
		t.Fatal("cancelled connect: no error")
	}
	if tn := fe.tunnel(); tn.state != StateDisconnected || tn.hasRef || tn.uid != 0 || tn.cancel != nil {
		t.Fatalf("after the cancelled connect: state %q hasRef %v uid %d", tn.state, tn.hasRef, tn.uid)
	}
	if st := fe.status(); st.KillSwitch != ipc.KillSwitchStatusOff {
		t.Fatalf("status %+v, want the kill switch off", st)
	}
	fe.fw.waitLast(t, "a release", released)

	// The same failure without the requester leaving is an error (the kill
	// switch keeps blocking, fail-closed).
	cancelCaller.Store(nil)
	fe.fw.setErr(errors.New("pfctl: /dev/pf: Permission denied"))
	if _, err := fe.m.requestConnect(context.Background(), uidA, tunName); err == nil {
		t.Fatal("failing connect: no error")
	}
	if tn := fe.tunnel(); tn.state != StateError {
		t.Fatalf("failed connect: state %q, want error", tn.state)
	}
}

// P23 (b): the user a failed connect was recorded for may take the failed
// tunnel down (lifting its kill switch) while still an allowed user;
// another allowed user may not, nor the same user once the policy file no
// longer allows it; an administrator always may.
func TestFailedTunnelDownByItsUser(t *testing.T) {
	var setup atomic.Bool // the test process adds the tunnel as an administrator
	setup.Store(true)
	fe := newFullTunnelEnvOpts(t, true, true, envOpts{admin: func(uid uint32) bool { return uid == uidAdmin || uid == uidA && setup.Load() }})
	setup.Store(false)
	fe.allow(uidA, uidB)
	newFakeAgent(t, fe.env, uidB, otherKey(t), serialB) // registered, other card
	fail := func() {
		t.Helper()
		fe.fw.setErr(errors.New("pfctl: /dev/pf: Permission denied"))
		if _, err := fe.m.requestConnect(context.Background(), uidA, tunName); err == nil {
			t.Fatal("failing connect: no error")
		}
		fe.fw.setErr(nil)
		if tn := fe.tunnel(); tn.state != StateError || !tn.hasRef || tn.uid != uidA {
			t.Fatalf("failed connect: state %q hasRef %v uid %d", tn.state, tn.hasRef, tn.uid)
		}
		if st := fe.status(); st.KillSwitch != ipc.KillSwitchStatusBlocking {
			t.Fatalf("failed armed tunnel: %+v, want blocking", st)
		}
	}
	fail()
	if _, err := fe.m.requestDisconnect(uidB, tunName); err == nil {
		t.Fatal("another allowed user took the failed tunnel down")
	}
	if st, err := fe.m.requestDisconnect(uidA, tunName); err != nil || st.State != StateDisconnected {
		t.Fatalf("its user's down: %+v, %v", st, err)
	}
	fe.fw.waitLast(t, "a release", released)

	// The policy file no longer allows A (edited by hand: nothing revoked).
	fail()
	if err := os.WriteFile(filepath.Join(fe.store, tunName+".policy"), []byte(`{"allowed_users":[`+fmt.Sprint(uidB)+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fe.m.requestDisconnect(uidA, tunName); err == nil {
		t.Fatal("a user no longer allowed took the failed tunnel down")
	}
	if st, err := fe.m.requestDisconnect(uidAdmin, tunName); err != nil || st.State != StateDisconnected {
		t.Fatalf("administrator's down: %+v, %v", st, err)
	}
}

// Upgrading from Plan 1: a stored tunnel without a policy file loads
// admin-only, and says how to give a user access back; a stored
// configuration that no longer parses (an MTU outside 1280-9000) is not
// loaded, and the log names it and why.
func TestLoadLogsPlan1Leftovers(t *testing.T) {
	logs := &syncBuffer{}
	log.SetOutput(logs)
	defer log.SetOutput(io.Discard)
	dir := t.TempDir()
	writeFullTunnelNamed(t, dir, "old", [32]byte{1})
	var peer [32]byte
	peer[0] = 9
	bad := fmt.Sprintf("[Interface]\nMTU = 1000\n[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = 10.0.0.2/32\n"+
		"[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.1.0.0/16\n",
		refA, base64.StdEncoding.EncodeToString(peer[:]), base64.StdEncoding.EncodeToString(peer[:]))
	if err := (&store{dir: dir}).writeAtomic("tiny.conf", bad); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Options{StoreDir: dir})
	if err := m.load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.tunnels["tiny"]; ok {
		t.Error("a configuration with MTU 1000 was loaded")
	}
	if tn := m.tunnels["old"]; tn == nil || len(tn.policy.AllowedUsers) != 0 {
		t.Fatalf("tunnel without a policy file: %+v", tn)
	}
	l := logs.String()
	for _, want := range []string{
		"tunnel old has no policy file: only administrators may connect it; allow a user with: sudo latchwire policy old --allow-user NAME",
		"WARNING: tunnel tiny is not loaded: " + filepath.Join(dir, "tiny.conf") + ": line 2: " + msg.ConfigMTURange,
	} {
		if !strings.Contains(l, want) {
			t.Errorf("log lacks %q:\n%s", want, l)
		}
	}
}
