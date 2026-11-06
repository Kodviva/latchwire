package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/ipc/ipctest"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/killswitch"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
	"github.com/Kodviva/latchwire/internal/netmon"
)

// fakeFirewall records the kill switch states the daemon sets. err, when
// set, fails every Set that blocks. It is a killswitch.Verifier whose
// answer is lost (false: the blocking is gone) until the next Set.
type fakeFirewall struct {
	mu       sync.Mutex
	sets     []killswitch.State
	err      error
	lost     bool
	verifies int
	// verifyErr, when set, fails every Verify (ok false).
	verifyErr error
}

func (f *fakeFirewall) Verify(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies++
	if f.verifyErr != nil {
		return false, f.verifyErr
	}
	return !f.lost, nil
}

func (f *fakeFirewall) setVerifyErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyErr = err
}

func (f *fakeFirewall) verifyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifies
}

func (f *fakeFirewall) lose() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lost = true
}

func (f *fakeFirewall) Set(_ context.Context, s killswitch.State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, s)
	if s.Block && f.err != nil {
		return f.err
	}
	f.lost = false
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
	// While connecting (endpoints resolved, no device yet) the endpoint
	// passes outbound only (no interface, no listen port: P17), so the
	// first handshake leaves at once; the rest but the marked resolver and
	// link setup is blocked.
	wantConnecting := killswitch.State{Block: true, FwMark: 51820, Tunnels: []killswitch.TunnelRule{{Endpoints: want.Tunnels[0].Endpoints}}}
	if !statesEqual(sets[0], wantConnecting) {
		t.Errorf("connecting state %+v, want %+v", sets[0], wantConnecting)
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
			e.add(e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""))
			// add wrote the default policy; connect reads the file again.
			if err := os.WriteFile(filepath.Join(e.store, tunName+".policy"), []byte(tc.policy), 0o600); err != nil {
				t.Fatal(err)
			}
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
	if runtime.GOOS == "windows" {
		return // no mode bits: the data directory's ACL protects the file
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
	fe.fw.waitLast(t, "the tunnel passing again", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 1 && s.Tunnels[0].Iface != "" })
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
	// It blocks nothing, and status says so.
	wantWarn := fmt.Sprintf(msg.DaemonWarnKillSwitchNoEffectFmt, killswitch.ErrUnsupported)
	if st := fe.status(); st.State != StateError || st.KillSwitch != ipc.KillSwitchStatusBlocking || st.Warning != wantWarn {
		t.Errorf("status %+v, want error with %q", st, wantWarn)
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
	writeFullTunnelNamed(t, dir, tunName, pub)
}

func writeFullTunnelNamed(t *testing.T, dir, name string, pub [32]byte) {
	t.Helper()
	var peer [32]byte
	peer[0] = 9
	cfg := fmt.Sprintf("[Interface]\nMTU = 1420\n[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = 10.0.0.2/32\n"+
		"[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n",
		refA, base64.StdEncoding.EncodeToString(pub[:]), base64.StdEncoding.EncodeToString(peer[:]))
	if err := (&store{dir: dir}).save(name, cfg); err != nil {
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
// the startup cleanup leaves it; the tunnels it blocked for (the store's
// record) load in card_removed, bound to their key and user, so their user
// can take them down; other tunnels load disconnected; blocking goes on
// until down (P17).
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
	writeFullTunnelNamed(t, stdir, "spare", [32]byte{2}) // armed, but was not up
	const owner = 501
	if err := (&store{dir: stdir}).saveKillSwitchTunnels([]ksTunnel{{Name: tunName, Ref: refA.String(), UID: owner}, {Name: "gone"}}); err != nil {
		t.Fatal(err)
	}
	r := &cmdRunner{}
	fw := &fakeFirewall{}
	m := NewManager(Options{Socket: ipctest.Path(t), StoreDir: stdir, JournalPath: jpath, Runner: r,
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
	tun, spare := m.tunnels[tunName], m.tunnels["spare"]
	state, ref, hasRef, uid, spareState := tun.state, tun.ref, tun.hasRef, tun.uid, spare.state
	m.mu.Unlock()
	if state != StateCardRemoved || !hasRef || ref != refA || uid != owner {
		t.Fatalf("tunnel %s, ref %v %v, uid %d; want card_removed bound to %v of uid %d", state, hasRef, ref, uid, refA, owner)
	}
	if spareState != StateDisconnected {
		t.Errorf("tunnel spare is %s, want disconnected (it was not blocking)", spareState)
	}
	s, ok := fw.last()
	if !ok || !s.Block || len(s.Tunnels) != 0 {
		t.Fatalf("kill switch at startup %+v (sets %+v), want blocking without tunnels", s, fw.all())
	}

	// Another user may not take it down; its owner may (requestDisconnect
	// with a registered agent of the owner checks exactly this).
	if m.teardown(tun, StateDisconnected, func(t *tunnel) bool { return t.boundTo(owner + 1) }) {
		t.Fatal("another user took the tunnel down")
	}
	if _, err := m.disconnect(tunName, func(t *tunnel) bool { return t.boundTo(owner) }); err != nil {
		t.Fatalf("down by its owner: %v", err)
	}
	if s, _ := fw.last(); s.Block {
		t.Fatalf("down left the kill switch on: %+v", fw.all())
	}
	if _, err := os.Stat(filepath.Join(stdir, ksTunnelsFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("record still there after the release: %v", err)
	}
}

// A journaled kill switch whose record is unusable restores nothing: the
// kill switch is removed (logged), the tunnels load disconnected.
func TestStartupUnusableRecordReleases(t *testing.T) {
	dir := shortDir(t)
	jpath := filepath.Join(dir, "journal.json")
	j, err := netcfg.OpenJournal(jpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(killswitch.JournalOwner, []netcfg.Step{{Name: "nft", Args: []string{"-f", "-"}, Persistent: true}}); err != nil {
		t.Fatal(err)
	}
	stdir := filepath.Join(dir, "tunnels")
	writeFullTunnel(t, stdir, [32]byte{1})
	if err := os.WriteFile(filepath.Join(stdir, ksTunnelsFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	fw := &fakeFirewall{}
	m := NewManager(Options{Socket: ipctest.Path(t), StoreDir: stdir, JournalPath: jpath,
		Runner: &cmdRunner{}, TUN: (&netFactory{}).make, Firewall: fw})
	serveManager(t, m)
	if sets := fw.all(); len(sets) != 1 || sets[0].Block {
		t.Fatalf("sets %+v, want one release", sets)
	}
}

func TestLoadKillSwitchTunnels(t *testing.T) {
	s := &store{dir: t.TempDir()}
	if r, err := s.loadKillSwitchTunnels(); err != nil || r != nil {
		t.Fatalf("missing record: %v, %v", r, err)
	}
	want := []ksTunnel{{Name: "office", Ref: refA.String(), UID: 501}}
	if err := s.saveKillSwitchTunnels(want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(s.dir, ksTunnelsFile))
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("record mode %v, %v; want 0600", fi.Mode(), err)
	}
	if got, err := s.loadKillSwitchTunnels(); err != nil || !slices.Equal(got, want) {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	p := filepath.Join(s.dir, ksTunnelsFile)
	for _, bad := range []string{
		`{"version":2,"tunnels":[]}`,
		`{"version":1,"tunnels":[{"name":"../x","uid":0}]}`,
		`{"version":1,"tunnels":[],"x":1}`,
		`{"version":1,"tunnels":[]} {}`,
	} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.loadKillSwitchTunnels(); err == nil {
			t.Errorf("record %q accepted", bad)
		}
	}
	if err := os.WriteFile(p, []byte(`{"version":1,"tunnels":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return // no mode bits: the data directory's ACL protects the file
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadKillSwitchTunnels(); err == nil {
		t.Error("a record writable by others was accepted")
	}
}

// The daemon records the tunnels it blocks for; after a crash a new daemon
// restores them, and the card's return (an agent reporting it) reconnects
// the tunnel behind the kill switch (P17).
func TestRestartRestoresKillSwitchTunnelAndReconnects(t *testing.T) {
	fe := newFullTunnelEnv(t, true)
	fe.connect()
	rec := filepath.Join(fe.store, ksTunnelsFile)
	got, err := (&store{dir: fe.store}).loadKillSwitchTunnels()
	// An administrator connected it (everyone is one in this env): the
	// restarted daemon, where nobody is, still reconnects it (P20).
	if err != nil || len(got) != 1 || got[0] != (ksTunnel{Name: tunName, Ref: refA.String(), UID: fe.boundUID(), Admin: true}) {
		t.Fatalf("record %+v, %v", got, err)
	}

	// The "crash": a second daemon starts on a copy of the store, with
	// the kill switch in its journal.
	dir := shortDir(t)
	stdir := filepath.Join(dir, "tunnels")
	if err := os.MkdirAll(stdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{tunName + ".conf", tunName + ".endpoints", ksTunnelsFile} {
		b, err := os.ReadFile(filepath.Join(fe.store, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stdir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	jpath := filepath.Join(dir, "journal.json")
	j, err := netcfg.OpenJournal(jpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Record(killswitch.JournalOwner, []netcfg.Step{{Name: "nft", Args: []string{"-f", "-"}, Persistent: true}}); err != nil {
		t.Fatal(err)
	}
	fw := &fakeFirewall{}
	sock := ipctest.Path(t)
	m := NewManager(Options{Socket: sock, StoreDir: stdir, JournalPath: jpath, Runner: &cmdRunner{},
		TUN: (&netFactory{addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}).make, Firewall: fw,
		IsAdmin: func(uint32) (bool, error) { return false, nil }})
	m.netSource = func() (netmon.Source, error) { return make(chanSource), nil }
	m.fullTunnel = true
	m.pickTable = func(context.Context) (uint32, error) { return 51820, nil }
	m.resolve = func(context.Context, string, uint32) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	real := m.ops.ipcSet
	m.ops.ipcSet = func(d *device.Device, s string) error {
		s, _ = strings.CutPrefix(s, "fwmark=51820\n") // no CAP_NET_ADMIN for SO_MARK
		return real(d, s)
	}
	serveManager(t, m)
	if s, ok := fw.last(); !ok || !s.Block {
		t.Fatalf("restarted daemon not blocking: %+v", fw.all())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a := agent.New(sock, fe.b, fe.p, fastPoll)
	go func() { a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(10 * time.Second)
	for {
		m.mu.Lock()
		st := m.tunnels[tunName].state
		m.mu.Unlock()
		if st == StateConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restored tunnel did not reconnect when the card was reported (state %s)", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	fw.waitLast(t, "the reconnected tunnel passing", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 1 && s.Tunnels[0].Iface != "" })
	if _, err := os.Stat(rec); err != nil {
		t.Errorf("first daemon's record: %v", err)
	}
}

// While the kill switch blocks, a reconnect's failed lookup of any kind
// (macOS reports "no such host" when no DNS server is reachable) uses the
// endpoint cache; without it, NXDOMAIN still never does (P17).
func TestBlockedLookupUsesCacheOnAnyError(t *testing.T) {
	var (
		mu      sync.Mutex
		failErr error
	)
	hook := func(m *Manager) {
		m.resolve = func(context.Context, string, uint32) ([]netip.Addr, error) {
			mu.Lock()
			defer mu.Unlock()
			if failErr != nil {
				return nil, failErr
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
	}
	e := newEnv(t, envOpts{present: []uint32{serialA}, hook: hook})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.add(e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, fmt.Sprintf("vpn.example.test:%d", srv.port)))
	if err := os.WriteFile(filepath.Join(e.store, tunName+".policy"), []byte(`{"kill_switch":"on"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.waitCard(serialA, true)
	e.connect()

	mu.Lock()
	failErr = &net.DNSError{Err: "no such host", Name: "vpn.example.test", IsNotFound: true}
	mu.Unlock()
	e.b.setPresent(serialA, false)
	e.waitState(StateCardRemoved, 3*time.Second)
	e.fw.waitLast(t, "blocking", blocking)
	e.b.setPresent(serialA, true)
	e.waitState(StateConnected, 5*time.Second)
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET via the cached endpoint: %v", err)
	}

	// Released (down): NXDOMAIN is final again.
	if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	e.fw.waitLast(t, "a release", released)
	assertCode(t, e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeUnavailable)
}

// The verification tick asks the firewall whether the blocking is still in
// effect and sets it again when not (P17).
func TestVerifyTickReappliesKillSwitch(t *testing.T) {
	fe := newFullTunnelEnvOpts(t, true, true, envOpts{verifyEvery: 20 * time.Millisecond})
	fe.connect()
	want := fe.fw.waitLast(t, "the tunnel passing", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 1 && s.Tunnels[0].Iface != "" })
	n := len(fe.fw.all())
	deadline := time.Now().Add(5 * time.Second)
	for {
		fe.fw.mu.Lock()
		v := fe.fw.verifies
		fe.fw.mu.Unlock()
		if v >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the tick never verified the kill switch")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(fe.fw.all()); got != n {
		t.Fatalf("a kill switch in effect was set again: %+v", fe.fw.all()[n:])
	}
	fe.fw.lose() // pfctl -d, nft delete table
	deadline = time.Now().Add(5 * time.Second)
	for len(fe.fw.all()) == n {
		if time.Now().After(deadline) {
			t.Fatal("a lost kill switch was not set again")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s, _ := fe.fw.last(); !statesEqual(s, want) {
		t.Errorf("set again with %+v, want %+v", s, want)
	}

	// Nothing is verified while not blocking.
	if err := fe.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	fe.fw.waitLast(t, "a release", released)
	fe.fw.mu.Lock()
	v := fe.fw.verifies
	fe.fw.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	fe.fw.mu.Lock()
	defer fe.fw.mu.Unlock()
	if fe.fw.verifies != v {
		t.Errorf("verified %d times while released", fe.fw.verifies-v)
	}
}

// A kill switch whose rules are in place but cannot take effect (macOS: a
// main pf ruleset without the com.apple anchor point) is not set again at
// every tick, which would not help: it is logged once, and status warns
// for every tunnel whose kill switch is on, until Verify sees it in effect
// again.
func TestVerifyTickKillSwitchNotInEffect(t *testing.T) {
	logs := &syncBuffer{}
	log.SetOutput(logs)
	defer log.SetOutput(io.Discard)
	fe := newFullTunnelEnvOpts(t, true, true, envOpts{verifyEvery: 20 * time.Millisecond})
	fe.connect()
	fe.fw.waitLast(t, "the tunnel passing", func(s killswitch.State) bool { return s.Block && len(s.Tunnels) == 1 && s.Tunnels[0].Iface != "" })
	n := len(fe.fw.all())
	why := errors.New(msg.KillSwitchPfNoAnchor)
	fe.fw.setVerifyErr(fmt.Errorf("%w", unsupported(why)))
	v := fe.fw.verifyCount()
	deadline := time.Now().Add(5 * time.Second)
	for fe.fw.verifyCount() < v+4 {
		if time.Now().After(deadline) {
			t.Fatal("the tick stopped verifying")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(fe.fw.all()); got != n {
		t.Errorf("a kill switch that cannot take effect was set again: %+v", fe.fw.all()[n:])
	}
	const warning = "WARNING: the kill switch is NOT in effect"
	if c := strings.Count(logs.String(), warning); c != 1 {
		t.Errorf("logged %d times, want once:\n%s", c, logs.String())
	}
	wantWarn := fmt.Sprintf(msg.DaemonWarnKillSwitchNoEffectFmt, why)
	if st := fe.status(); st.KillSwitch != ipc.KillSwitchStatusArmed || st.Warning != wantWarn {
		t.Errorf("status %+v, want armed with %q", st, wantWarn)
	}

	// Fixed (pfctl -f /etc/pf.conf): the warning goes, logged once.
	fe.fw.setVerifyErr(nil)
	deadline = time.Now().Add(5 * time.Second)
	for fe.status().Warning != "" {
		if time.Now().After(deadline) {
			t.Fatal("the warning stayed after the kill switch took effect again")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "the kill switch is in effect again") {
		t.Errorf("the end is not logged:\n%s", logs.String())
	}
}

// unsupported wraps err as killswitch.ErrUnsupported (errors.Is), as the
// firewalls report what setting the rules again cannot fix.
func unsupported(err error) error { return unsupportedErr{err} }

type unsupportedErr struct{ error }

func (unsupportedErr) Is(target error) bool { return target == killswitch.ErrUnsupported }

// Without a journaled kill switch the startup neither blocks nor touches
// the firewall, even for a tunnel whose kill switch would be on.
func TestStartupWithoutKillSwitchLeavesFirewall(t *testing.T) {
	dir := shortDir(t)
	stdir := filepath.Join(dir, "tunnels")
	writeFullTunnel(t, stdir, [32]byte{1})
	if err := (&store{dir: stdir}).saveKillSwitchTunnels([]ksTunnel{{Name: tunName}}); err != nil {
		t.Fatal(err)
	}
	fw := &fakeFirewall{}
	m := NewManager(Options{Socket: ipctest.Path(t), StoreDir: stdir, JournalPath: filepath.Join(dir, "journal.json"),
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
	// A record without a journaled kill switch is stale (a reboot cleared
	// the journal) and goes.
	if _, err := os.Stat(filepath.Join(stdir, ksTunnelsFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale record kept: %v", err)
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
	m := NewManager(Options{Socket: ipctest.Path(t), StoreDir: stdir, JournalPath: jpath,
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
	m := NewManager(Options{Socket: ipctest.Path(t), StoreDir: filepath.Join(dir, "tunnels"), JournalPath: jpath,
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

// A Linux full tunnel reconnecting behind its own blocking kill switch
// (card back after card_removed) lets its mark pass before it looks up its
// endpoint, so the marked lookup gets through instead of relying on the
// endpoint cache.
func TestBlockedReconnectMarkPassesBeforeLookup(t *testing.T) {
	fe := newFullTunnelEnvTable(t, true)
	fe.connect()
	fe.b.setPresent(serialA, false)
	fe.waitState(StateCardRemoved, 3*time.Second)
	fe.fw.waitLast(t, "blocking", func(s killswitch.State) bool { return s.Block && s.FwMark == 0 })
	fe.mu.Lock()
	n := len(fe.atResolve)
	fe.mu.Unlock()
	fe.b.setPresent(serialA, true)
	fe.waitState(StateConnected, 5*time.Second)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if len(fe.atResolve) <= n {
		t.Fatal("the reconnect looked nothing up")
	}
	if s := fe.atResolve[n]; !s.Block || s.FwMark != 51820 {
		t.Errorf("kill switch at the reconnect's lookup %+v, want blocking with FwMark 51820 passing", s)
	}
	if fe.marks[n] != 51820 {
		t.Errorf("lookup mark %d, want 51820", fe.marks[n])
	}
}
