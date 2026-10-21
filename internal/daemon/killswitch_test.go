package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/killswitch"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

// fakeFirewall records the kill switch states the daemon sets. err, when
// set, fails every Set that blocks.
type fakeFirewall struct {
	mu   sync.Mutex
	sets []killswitch.State
	err  error
}

func (f *fakeFirewall) Set(_ context.Context, s killswitch.State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, s)
	if s.Block && f.err != nil {
		return f.err
	}
	return nil
}

func (f *fakeFirewall) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeFirewall) all() []killswitch.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sets)
}

// last returns the newest state set (ok false: none).
func (f *fakeFirewall) last() (killswitch.State, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sets) == 0 {
		return killswitch.State{}, false
	}
	return f.sets[len(f.sets)-1], true
}

// waitLast waits until the newest state set satisfies cond.
func (f *fakeFirewall) waitLast(t *testing.T, what string, cond func(killswitch.State) bool) killswitch.State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, ok := f.last()
		if ok && cond(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("kill switch never got %s; sets %+v", what, f.all())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func blocking(s killswitch.State) bool { return s.Block }
func released(s killswitch.State) bool { return !s.Block }

func tunnelWith(allowed ...[]string) *config.Tunnel {
	cfg := &config.Tunnel{Name: tunName}
	for _, a := range allowed {
		var p config.Peer
		for _, s := range a {
			p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix(s))
		}
		cfg.Peers = append(cfg.Peers, p)
	}
	return cfg
}

func TestKillSwitchAutoOnlyForSingleFullPeer(t *testing.T) {
	full4 := []string{"0.0.0.0/0"}
	full6 := []string{"10.0.0.0/8", "::/0"}
	split := []string{"10.0.0.0/8"}
	for _, tc := range []struct {
		name   string
		policy string
		cfg    *config.Tunnel
		want   bool
	}{
		{"auto, one full peer", KillSwitchAuto, tunnelWith(full4), true},
		{"auto, one ::/0 peer", KillSwitchAuto, tunnelWith(full6), true},
		{"default is auto", "", tunnelWith(full4), true},
		{"auto, split peer", KillSwitchAuto, tunnelWith(split), false},
		{"auto, two peers one full", KillSwitchAuto, tunnelWith(full4, split), false},
		{"auto, no peer", KillSwitchAuto, tunnelWith(), false},
		{"on, split", KillSwitchOn, tunnelWith(split), true},
		{"off, full", KillSwitchOff, tunnelWith(full4), false},
	} {
		if got := (Policy{KillSwitch: tc.policy}).armed(tc.cfg); got != tc.want {
			t.Errorf("%s: armed = %v, want %v", tc.name, got, tc.want)
		}
	}

	// Through the daemon: a full tunnel blocks from the moment it connects
	// and passes its own interface, endpoint and listen port; a split
	// tunnel never touches the firewall.
	fe := newFullTunnelEnv(t, true)
	if st := fe.connect(); st.State != StateConnected {
		t.Fatalf("connect state %q", st.State)
	}
	_, rc := fe.f.last()
	rc.mu.Lock()
	iface := rc.iface
	rc.mu.Unlock()
	port := uapiInt(t, fe.clientDev(), "listen_port")
	want := killswitch.State{Block: true, FwMark: 51820, Tunnels: []killswitch.TunnelRule{{
		Iface:      iface,
		Endpoints:  []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(fe.srv.port))},
		ListenPort: uint16(port),
	}}}
	sets := fe.fw.all()
	if len(sets) != 2 {
		t.Fatalf("sets %+v, want connecting then connected", sets)
	}
	// While connecting (endpoints resolved, no device yet) everything but
	// the marked resolver and link setup is blocked.
	if s := sets[0]; !s.Block || len(s.Tunnels) != 0 || s.FwMark != 51820 {
		t.Errorf("connecting state %+v, want blocking without tunnels, mark 51820", s)
	}
	if !statesEqual(sets[1], want) {
		t.Errorf("connected state %+v, want %+v", sets[1], want)
	}
	if want.Tunnels[0].ListenPort == 0 {
		t.Error("no listen port")
	}
	// The resolved endpoint passes the kill switch while traffic flows.
	tnet, _ := fe.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET over the full tunnel: %v", err)
	}

	e, _ := connected(t, envOpts{})
	if sets := e.fw.all(); len(sets) != 0 {
		t.Errorf("split tunnel set the kill switch: %+v", sets)
	}
}

// A policy file turns the kill switch on for a split tunnel, or off for a
// full one; a policy that cannot be read counts as on (fail closed).
func TestKillSwitchPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, policy string
		want         bool
	}{
		{"on", `{"kill_switch":"on"}`, true},
		{"off", `{"kill_switch":"off"}`, false},
		{"auto", `{"kill_switch":"auto"}`, false},
		{"bad value", `{"kill_switch":"maybe"}`, true},
		{"garbage", `{`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, envOpts{present: []uint32{serialA}})
			srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
			if err := os.MkdirAll(e.store, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(e.store, tunName+".policy"), []byte(tc.policy), 0o600); err != nil {
				t.Fatal(err)
			}
			e.add(e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""))
			e.waitCard(serialA, true)
			e.connect()
			s, _ := e.fw.last()
			if s.Block != tc.want {
				t.Fatalf("Block = %v (sets %+v), want %v", s.Block, e.fw.all(), tc.want)
			}
		})
	}
}

func TestLoadPolicy(t *testing.T) {
	s := &store{dir: t.TempDir()}
	p, err := s.loadPolicy(tunName)
	if err != nil || p.KillSwitch != KillSwitchAuto {
		t.Fatalf("missing policy: %+v, %v; want auto", p, err)
	}
	path := filepath.Join(s.dir, tunName+".policy")
	for text, ok := range map[string]bool{
		`{"kill_switch":"on"}`:             true,
		`{"kill_switch":"off"}`:            true,
		`{}`:                               true,
		`{"kill_switch":"ON"}`:             false,
		`{"kill_switch":"on","x":1}`:       false,
		`{"kill_switch":"on"} {}`:          false,
		`["on"]`:                           false,
		strings.Repeat(" ", 70<<10) + "{}": false,
	} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.loadPolicy(tunName); (err == nil) != ok {
			t.Errorf("loadPolicy(%.40q) = %v, want ok %v", text, err, ok)
		}
	}
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadPolicy(tunName); err == nil {
		t.Error("a policy writable by others was accepted")
	}
}

func TestCardRemovedKeepsBlocking(t *testing.T) {
	fe := newFullTunnelEnv(t, true)
	fe.connect()
	fe.b.setPresent(serialA, false)
	fe.waitState(StateCardRemoved, 3*time.Second)
	s := fe.fw.waitLast(t, "card_removed blocking", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 0 })
	if s.FwMark != 0 {
		t.Errorf("mark %d without a tunnel", s.FwMark)
	}
	// The card comes back: the tunnel reconnects behind the kill switch,
	// which never lets go in between.
	fe.b.setPresent(serialA, true)
	fe.waitState(StateConnected, 5*time.Second)
	fe.fw.waitLast(t, "the tunnel passing again", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 1 })
	for _, s := range fe.fw.all() {
		if !s.Block {
			t.Fatalf("the kill switch was released between card removal and reconnect: %+v", fe.fw.all())
		}
	}
}

// Only down, remove and a graceful shutdown release the kill switch.
func TestDownReleasesBlocking(t *testing.T) {
	fe := newFullTunnelEnv(t, true)
	fe.connect()
	if err := fe.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	fe.fw.waitLast(t, "a release after down", released)

	fe.connect()
	fe.fw.waitLast(t, "blocking", blocking)
	if err := fe.call(ipc.MethodTunnelRemove, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	fe.fw.waitLast(t, "a release after remove", released)

	fe2 := newFullTunnelEnv(t, true)
	fe2.connect()
	fe2.b.setPresent(serialA, false)
	fe2.waitState(StateCardRemoved, 3*time.Second)
	fe2.fw.waitLast(t, "blocking", blocking)
	fe2.stop()
	if s, _ := fe2.fw.last(); s.Block {
		t.Fatalf("graceful shutdown left the kill switch on: %+v", fe2.fw.all())
	}
}

// A firewall that cannot block (no nft, a custom pf.conf) refuses a
// tunnel whose kill switch is on, before any device exists; with the kill
// switch off by policy the same tunnel connects.
func TestKillSwitchUnsupportedRefusesConnect(t *testing.T) {
	fe := newFullTunnelEnv(t, true)
	fe.fw.setErr(killswitch.ErrUnsupported)
	err := fe.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil)
	assertCode(t, err, ipc.CodeBadRequest)
	if !strings.Contains(err.Error(), msg.KillSwitchUnsupported) {
		t.Errorf("error %q lacks the reason", err)
	}
	if n := fe.f.count(); n != 0 {
		t.Errorf("%d devices made, want 0", n)
	}
	if st := fe.status(); st.State != StateError {
		t.Errorf("state %q, want error", st.State)
	}

	// Any other failure to put the kill switch in place also refuses.
	fe.fw.setErr(errors.New("pfctl: /dev/pf: Permission denied"))
	assertCode(t, fe.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeInternal)

	if err := os.WriteFile(filepath.Join(fe.store, tunName+".policy"), []byte(`{"kill_switch":"off"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fe.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	if st := fe.connect(); st.State != StateConnected {
		t.Fatalf("connect with the kill switch off: %q", st.State)
	}
}

// writeFullTunnel stores a full-tunnel configuration for tunName whose
// identity uses card A's slot with pub.
func writeFullTunnel(t *testing.T, dir string, pub [32]byte) {
	t.Helper()
	var peer [32]byte
	peer[0] = 9
	cfg := fmt.Sprintf("[Interface]\nMTU = 1420\n[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = 10.0.0.2/32\n"+
		"[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n",
		refA, base64.StdEncoding.EncodeToString(pub[:]), base64.StdEncoding.EncodeToString(peer[:]))
	if err := (&store{dir: dir}).save(tunName, cfg); err != nil {
		t.Fatal(err)
	}
}

// serveManager starts m and waits for its socket; the returned func stops
// it.
func serveManager(t *testing.T, m *Manager) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- m.Serve(ctx) }()
	var (
		once sync.Once
		done bool // Serve's result already received
	)
	stop := func() {
		once.Do(func() {
			cancel()
			if !done {
				<-served
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := ipc.Dial(m.socket)
		if err == nil {
			c.Close()
			return stop
		}
		select {
		case err := <-served:
			done = true
			t.Fatalf("Serve returned: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon socket: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// shortDir is a temporary directory with a path short enough for a unix
// socket (t.TempDir carries the test's name).
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// A daemon that crashed with the kill switch on finds it in the journal:
// the startup cleanup leaves it, the armed tunnels load in card_removed,
// and blocking goes on until down.
func TestStartupKeepsKillSwitchBlocking(t *testing.T) {
	dir := shortDir(t)
	jpath := filepath.Join(dir, "run", "journal.json")
	j, err := netcfg.OpenJournal(jpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(killswitch.JournalOwner, []netcfg.Step{{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte("x"), Persistent: true}}); err != nil {
		t.Fatal(err)
	}
	if err := j.Record("utun7", []netcfg.Step{{Name: "route", Args: []string{"-q", "-n", "delete", "-inet", "0.0.0.0/1", "-interface", "utun7"}}}); err != nil {
		t.Fatal(err)
	}
	stdir := filepath.Join(dir, "tunnels")
	writeFullTunnel(t, stdir, [32]byte{1})
	r := &cmdRunner{}
	fw := &fakeFirewall{}
	m := NewManager(Options{Socket: filepath.Join(dir, "s"), StoreDir: stdir, JournalPath: jpath, Runner: r,
		TUN: (&netFactory{}).make, Firewall: fw})
	serveManager(t, m)

	r.mu.Lock()
	cmds := slices.Clone(r.cmds)
	r.mu.Unlock()
	for _, c := range cmds {
		if strings.HasPrefix(c, "nft") {
			t.Errorf("startup cleanup removed the kill switch: %q", cmds)
		}
	}
	if len(cmds) == 0 {
		t.Error("startup cleanup did not undo the tunnel's leftovers")
	}
	j2, err := netcfg.OpenJournal(jpath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := j2.Entries()[killswitch.JournalOwner]; !ok {
		t.Error("the kill switch left the journal at startup")
	}
	m.mu.Lock()
	state := m.tunnels[tunName].state
	m.mu.Unlock()
	if state != StateCardRemoved {
		t.Fatalf("tunnel state %q, want card_removed", state)
	}
	s, ok := fw.last()
	if !ok || !s.Block || len(s.Tunnels) != 0 {
		t.Fatalf("kill switch at startup %+v (sets %+v), want blocking without tunnels", s, fw.all())
	}

	if _, err := m.disconnect(tunName, nil); err != nil {
		t.Fatal(err)
	}
	if s, _ := fw.last(); s.Block {
		t.Fatalf("down left the kill switch on: %+v", fw.all())
	}
}

// Without a journaled kill switch the startup neither blocks nor touches
// the firewall, even for a tunnel whose kill switch would be on.
func TestStartupWithoutKillSwitchLeavesFirewall(t *testing.T) {
	dir := shortDir(t)
	stdir := filepath.Join(dir, "tunnels")
	writeFullTunnel(t, stdir, [32]byte{1})
	fw := &fakeFirewall{}
	m := NewManager(Options{Socket: filepath.Join(dir, "s"), StoreDir: stdir, JournalPath: filepath.Join(dir, "journal.json"),
		Runner: &cmdRunner{}, TUN: (&netFactory{}).make, Firewall: fw})
	stop := serveManager(t, m)
	m.mu.Lock()
	state := m.tunnels[tunName].state
	m.mu.Unlock()
	if state != StateDisconnected {
		t.Errorf("tunnel state %q, want disconnected", state)
	}
	stop()
	if sets := fw.all(); len(sets) != 0 {
		t.Errorf("firewall sets %+v, want none", sets)
	}
}

// P6: a journal that could not be read may have held an active kill
// switch: its well-known objects are released at startup (fail open on
// corruption), with nothing left blocking.
func TestStartupReleasesKillSwitchAfterCorruptJournal(t *testing.T) {
	dir := shortDir(t)
	jpath := filepath.Join(dir, "journal.json")
	if err := os.WriteFile(jpath, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdir := filepath.Join(dir, "tunnels")
	writeFullTunnel(t, stdir, [32]byte{1})
	fw := &fakeFirewall{}
	m := NewManager(Options{Socket: filepath.Join(dir, "s"), StoreDir: stdir, JournalPath: jpath,
		Runner: &cmdRunner{}, TUN: (&netFactory{}).make, Firewall: fw})
	serveManager(t, m)
	if sets := fw.all(); len(sets) != 1 || sets[0].Block {
		t.Fatalf("firewall sets %+v, want one release", sets)
	}
	m.mu.Lock()
	state := m.tunnels[tunName].state
	m.mu.Unlock()
	if state != StateDisconnected {
		t.Errorf("tunnel state %q, want disconnected", state)
	}
}

// With the platform firewall (no Options.Firewall), the release after a
// corrupt journal runs the platform's removal of the well-known objects.
func TestStartupCorruptJournalReleasesPlatformObjects(t *testing.T) {
	dir := shortDir(t)
	jpath := filepath.Join(dir, "journal.json")
	if err := os.WriteFile(jpath, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &cmdRunner{}
	m := NewManager(Options{Socket: filepath.Join(dir, "s"), StoreDir: filepath.Join(dir, "tunnels"), JournalPath: jpath,
		Runner: r, TUN: (&netFactory{}).make})
	serveManager(t, m)
	r.mu.Lock()
	cmds := slices.Clone(r.cmds)
	r.mu.Unlock()
	var want []string
	switch runtime.GOOS {
	case "darwin":
		want = []string{"pfctl -a com.apple/250.latchwire -F all"}
	case "linux":
		want = []string{"nft --version", "nft -f -"}
	}
	if !slices.Equal(cmds, want) {
		t.Fatalf("startup ran %q, want %q", cmds, want)
	}
}
