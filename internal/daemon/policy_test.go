package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
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
	if fi.Mode().Perm() != 0o600 {
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
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
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
	if want := (Policy{KillSwitch: KillSwitchAuto}); err != nil || !reflect.DeepEqual(p, want) {
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
