package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/softkey"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

const (
	serialA = 40727512
	serialB = 40727513

	testPIN  = "731905"
	wrongPIN = "135799"

	fastPoll = 50 * time.Millisecond
	tunName  = "office"
)

var (
	refA = keyref.Ref{Serial: serialA, Slot: 0x82}
	refB = keyref.Ref{Serial: serialB, Slot: 0x82}

	serverIP = netip.MustParseAddr("10.0.0.1")
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard) // the daemon and agent log every event
	os.Exit(m.Run())
}

// ---- fake cards, behind a real agent.Agent ----

type fakeCard struct {
	key      *softkey.Key
	verified bool
}

// fakeBackend is a softkey-backed agent.Backend. Every card needs the PIN
// once after it is inserted; removing it forgets the verification.
type fakeBackend struct {
	mu      sync.Mutex
	present map[uint32]bool
	cards   map[uint32]*fakeCard
	calls   map[[32]byte]int // X25519 calls by peer point
}

func newFakeBackend(t *testing.T, present ...uint32) *fakeBackend {
	b := &fakeBackend{present: map[uint32]bool{}, cards: map[uint32]*fakeCard{}, calls: map[[32]byte]int{}}
	for _, s := range []uint32{serialA, serialB} {
		k, err := softkey.New()
		if err != nil {
			t.Fatal(err)
		}
		b.cards[s] = &fakeCard{key: k}
	}
	for _, s := range present {
		b.present[s] = true
	}
	return b
}

func (b *fakeBackend) pub(serial uint32) [32]byte { return b.cards[serial].key.PublicKey() }

func (b *fakeBackend) setPresent(serial uint32, on bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.present[serial] = on
	if !on {
		b.cards[serial].verified = false
	}
}

// callsFor counts X25519 calls whose peer is in peers.
func (b *fakeBackend) callsFor(peers ...[32]byte) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, p := range peers {
		n += b.calls[p]
	}
	return n
}

func (b *fakeBackend) Serials() ([]uint32, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []uint32
	for s, on := range b.present {
		if on {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (b *fakeBackend) Provider(ref keyref.Ref, prompt func(int) (string, error)) (keyprovider.Provider, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.present[ref.Serial] || ref.Slot != 0x82 {
		return nil, keyprovider.ErrUnavailable
	}
	return &fakeProvider{b: b, serial: ref.Serial, prompt: prompt}, nil
}

type fakeProvider struct {
	b      *fakeBackend
	serial uint32
	prompt func(int) (string, error)
}

func (p *fakeProvider) PublicKey() [32]byte { return p.b.pub(p.serial) }

func (p *fakeProvider) Describe() keyprovider.Description {
	return keyprovider.Description{Kind: "fake", Serial: p.serial, Slot: 0x82, Tier: keyprovider.Tier1}
}

func (p *fakeProvider) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	b := p.b
	b.mu.Lock()
	c := b.cards[p.serial]
	if !b.present[p.serial] {
		b.mu.Unlock()
		return [32]byte{}, keyprovider.ErrUnavailable
	}
	if !c.verified {
		b.mu.Unlock()
		pin, err := p.prompt(3)
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: %w", keyprovider.ErrPINRequired, err)
		}
		if pin != testPIN {
			return [32]byte{}, &keyprovider.PINError{RetriesLeft: 2}
		}
		b.mu.Lock()
		c.verified = true
	}
	b.calls[peer]++
	b.mu.Unlock()
	return c.key.X25519(ctx, peer)
}

type fakePrompter struct {
	mu  sync.Mutex
	pin string
	n   int
}

func (p *fakePrompter) PIN(keyprovider.Description, int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	return p.pin, nil
}

func (p *fakePrompter) Warn(string) {}

func (p *fakePrompter) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// ---- client TUN: netstack plus a recording Configurer ----

type recCfg struct {
	mu       sync.Mutex
	iface    string
	addrs    []netip.Prefix
	routes   []netip.Prefix
	applied  bool
	removed  int
	onRemove func()
}

func (c *recCfg) Apply(iface string, addrs, routes []netip.Prefix) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.iface, c.addrs, c.routes, c.applied = iface, addrs, routes, true
	return nil
}

func (c *recCfg) Remove() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removed++
	if c.onRemove != nil {
		c.onRemove()
	}
	return nil
}

type netFactory struct {
	addrs    []netip.Addr
	onRemove func() // given to every Configurer

	mu   sync.Mutex
	nets []*netstack.Net
	cfgs []*recCfg
}

func (f *netFactory) make(name string, mtu int) (tun.Device, netcfg.Configurer, error) {
	tdev, tnet, err := netstack.CreateNetTUN(f.addrs, nil, mtu)
	if err != nil {
		return nil, nil, err
	}
	c := &recCfg{onRemove: f.onRemove}
	f.mu.Lock()
	f.nets = append(f.nets, tnet)
	f.cfgs = append(f.cfgs, c)
	f.mu.Unlock()
	return tdev, c, nil
}

func (f *netFactory) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.nets)
}

func (f *netFactory) last() (*netstack.Net, *recCfg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.nets) == 0 {
		return nil, nil
	}
	return f.nets[len(f.nets)-1], f.cfgs[len(f.cfgs)-1]
}

// ---- WireGuard server: stock device, software key, HTTP over netstack ----

type server struct {
	dev  *device.Device
	pub  [32]byte
	port int
}

func newServer(t *testing.T, clientPub [32]byte, clientAddr string) *server {
	t.Helper()
	// The server is a stock wireguard-go peer with an ordinary private key.
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	sk := softkey.FromPrivate(priv)

	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(priv[:]), hex.EncodeToString(clientPub[:]), clientAddr)
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)

	l, err := tnet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	return &server{dev: dev, pub: sk.PublicKey(), port: uapiInt(t, dev, "listen_port")}
}

// uapiInt reads the first value of key from a device's UAPI dump.
func uapiInt(t *testing.T, dev *device.Device, key string) int {
	t.Helper()
	s, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatalf("%s not in UAPI dump", key)
	return 0
}

// get fetches http://10.0.0.1/ through tnet.
func get(tnet *netstack.Net, timeout time.Duration) error {
	if tnet == nil {
		return errors.New("no client network")
	}
	c := http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: tnet.DialContext}}
	resp, err := c.Get("http://" + serverIP.String() + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		return fmt.Errorf("status %d body %q", resp.StatusCode, body)
	}
	return nil
}

// ---- environment ----

type env struct {
	t      *testing.T
	m      *Manager
	socket string
	store  string
	b      *fakeBackend
	p      *fakePrompter
	f      *netFactory
	cli    *ipc.Conn
	poll   time.Duration
	admin  func(uint32) bool

	agentMu     sync.Mutex
	agentCancel context.CancelFunc
	agentDone   chan struct{}
}

type envOpts struct {
	present    []uint32
	clientAddr []string // netstack addresses; default 10.0.0.2
	notAdmin   bool
	admin      func(uint32) bool // overrides notAdmin
	poll       time.Duration
	pin        string
	noAgent    bool
	hook       func(m *Manager) // runs before Serve
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	if o.clientAddr == nil {
		o.clientAddr = []string{"10.0.0.2"}
	}
	if o.poll == 0 {
		o.poll = fastPoll
	}
	if o.pin == "" {
		o.pin = testPIN
	}
	dir, err := os.MkdirTemp("", "lw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	e := &env{t: t, socket: filepath.Join(dir, "s"), store: filepath.Join(dir, "tunnels"),
		b: newFakeBackend(t, o.present...), p: &fakePrompter{pin: o.pin}, f: &netFactory{},
		poll: o.poll, admin: o.admin}
	if e.admin == nil {
		all := !o.notAdmin
		e.admin = func(uint32) bool { return all }
	}
	for _, a := range o.clientAddr {
		e.f.addrs = append(e.f.addrs, netip.MustParseAddr(a))
	}
	e.m = NewManager(Options{
		Socket:   e.socket,
		StoreDir: e.store,
		TUN:      e.f.make,
		IsAdmin:  func(uid uint32) (bool, error) { return e.admin(uid), nil },
	})
	if o.hook != nil {
		o.hook(e.m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- e.m.Serve(ctx) }()
	t.Cleanup(func() {
		e.stopAgent()
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := ipc.Dial(e.socket)
		if err == nil {
			e.cli = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon socket: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	go e.cli.Serve(context.Background())
	t.Cleanup(func() { e.cli.Close() })

	if !o.noAgent {
		e.startAgent()
	}
	return e
}

func (e *env) startAgent() {
	e.agentMu.Lock()
	defer e.agentMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a := agent.New(e.socket, e.b, e.p, e.poll)
	go func() { a.Run(ctx); close(done) }()
	e.agentCancel, e.agentDone = cancel, done
}

func (e *env) stopAgent() {
	e.agentMu.Lock()
	defer e.agentMu.Unlock()
	if e.agentCancel == nil {
		return
	}
	e.agentCancel()
	<-e.agentDone
	e.agentCancel = nil
}

// waitCard waits until some registered agent reports serial.
func (e *env) waitCard(serial uint32, want bool) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.m.cardRegistered(serial) != want {
		if time.Now().After(deadline) {
			e.t.Fatalf("card %d registered=%v not reached", serial, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *env) call(method string, params, result any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return e.cli.Call(ctx, method, params, result)
}

func (e *env) add(cfg string) {
	e.t.Helper()
	if err := e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: tunName, Config: cfg}, nil); err != nil {
		e.t.Fatalf("tunnel.add: %v", err)
	}
}

func (e *env) connect() ipc.TunnelStatus {
	e.t.Helper()
	var st ipc.TunnelStatus
	if err := e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, &st); err != nil {
		e.t.Fatalf("tunnel.connect: %v", err)
	}
	return st
}

func (e *env) status() ipc.TunnelStatus {
	e.t.Helper()
	var all []ipc.TunnelStatus
	if err := e.call(ipc.MethodTunnelStatus, nil, &all); err != nil {
		e.t.Fatalf("tunnel.status: %v", err)
	}
	for _, s := range all {
		if s.Name == tunName {
			return s
		}
	}
	e.t.Fatalf("tunnel %s not in status %+v", tunName, all)
	return ipc.TunnelStatus{}
}

// waitState polls the status until it is state and returns the time taken.
func (e *env) waitState(state string, timeout time.Duration) time.Duration {
	e.t.Helper()
	start := time.Now()
	for {
		st := e.status()
		if st.State == state {
			return time.Since(start)
		}
		if time.Since(start) > timeout {
			e.t.Fatalf("state %q not reached in %v (now %q)", state, timeout, st.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// clientDev returns the tunnel's live device (white box).
func (e *env) clientDev() *device.Device {
	e.t.Helper()
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	t := e.m.tunnels[tunName]
	if t == nil || t.dev == nil {
		e.t.Fatal("tunnel has no device")
	}
	return t.dev
}

// config renders a client configuration whose identities carry the fake
// cards' public keys.
func (e *env) config(ids []keyref.Ref, addrs []string, srv *server, endpoint string) string {
	var b strings.Builder
	b.WriteString("[Interface]\nMTU = 1420\n")
	for i, r := range ids {
		pub := e.b.pub(r.Serial)
		fmt.Fprintf(&b, "[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = %s/32\n",
			r, base64.StdEncoding.EncodeToString(pub[:]), addrs[i])
	}
	if endpoint == "" {
		endpoint = fmt.Sprintf("127.0.0.1:%d", srv.port)
	}
	fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s/32\n",
		base64.StdEncoding.EncodeToString(srv.pub[:]), endpoint, serverIP)
	return b.String()
}

// connected sets up a server for card A and a connected tunnel.
func connected(t *testing.T, o envOpts) (*env, *server) {
	t.Helper()
	if o.present == nil {
		o.present = []uint32{serialA}
	}
	e := newEnv(t, o)
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	cfg := e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, "")
	if e.admin(uidA) {
		e.add(cfg)
	} else if err := e.m.add(tunName, cfg); err != nil {
		t.Fatal(err)
	}
	e.waitCard(serialA, true)
	if st := e.connect(); st.State != StateConnected {
		t.Fatalf("connect state %q, want connected", st.State)
	}
	return e, srv
}

// ---- tests from the brief ----

func TestConnectHTTPOverTunnel(t *testing.T) {
	e, _ := connected(t, envOpts{})
	tnet, cfg := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET over tunnel: %v", err)
	}
	st := e.status()
	if st.State != StateConnected || st.Identity != refA.String() {
		t.Fatalf("status %+v, want connected with %s", st, refA)
	}
	if st.LastHandshake == "" {
		t.Error("status has no last handshake after traffic")
	}
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	if !cfg.applied || !slices.Equal(cfg.addrs, []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}) ||
		!slices.Equal(cfg.routes, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}) {
		t.Fatalf("Configurer.Apply got addrs %v routes %v", cfg.addrs, cfg.routes)
	}
	if n := e.p.count(); n != 1 {
		t.Errorf("PIN asked %d times, want 1 (warm-up at connect)", n)
	}
}

func TestCardRemovalTearsDownWithin2s(t *testing.T) {
	var (
		mu    sync.Mutex
		order []string
	)
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	hook := func(m *Manager) {
		real := m.ops.close
		m.ops.close = func(d *device.Device) { note("close"); real(d) }
	}
	// Production poll interval: the 2 s budget includes the agent's poll.
	e, _ := connected(t, envOpts{poll: time.Second, hook: hook})
	e.f.mu.Lock()
	for _, c := range e.f.cfgs {
		c.mu.Lock()
		c.onRemove = func() { note("remove") }
		c.mu.Unlock()
	}
	e.f.mu.Unlock()
	tnet, cfg := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET before removal: %v", err)
	}
	start := time.Now()
	e.b.setPresent(serialA, false)
	e.waitState(StateCardRemoved, 3*time.Second)
	// The teardown is done once the routes are removed (after the device
	// is closed): that is what must happen within 2 s.
	for {
		cfg.mu.Lock()
		removed := cfg.removed
		cfg.mu.Unlock()
		if removed > 0 {
			break
		}
		if time.Since(start) > 3*time.Second {
			t.Fatal("Configurer.Remove not called")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("teardown took %v, want <= 2s", d)
	}
	t.Logf("teardown complete %v after removal", time.Since(start).Round(time.Millisecond))
	if err := get(tnet, time.Second); err == nil {
		t.Fatal("GET succeeded after the card was removed")
	}
	cfg.mu.Lock()
	removed := cfg.removed
	cfg.mu.Unlock()
	if removed != 1 {
		t.Errorf("Configurer.Remove called %d times, want 1", removed)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(order, []string{"close", "remove"}) {
		t.Errorf("teardown order %v, want [close remove]: the device stops before routes go", order)
	}
}

func TestCardReinsertReconnects(t *testing.T) {
	e, _ := connected(t, envOpts{})
	e.b.setPresent(serialA, false)
	e.waitState(StateCardRemoved, 3*time.Second)
	e.b.setPresent(serialA, true)
	e.waitState(StateConnected, 5*time.Second)
	if n := e.f.count(); n != 2 {
		t.Fatalf("%d TUN devices made, want 2 (reconnect builds a new device)", n)
	}
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET after reinsert: %v", err)
	}
	if n := e.p.count(); n != 2 {
		t.Errorf("PIN asked %d times, want 2 (once per insertion)", n)
	}
}

// withGrace sets how long the daemon waits for a gone agent's user to come
// back before it tears that user's tunnels down.
func withGrace(d time.Duration) func(*Manager) {
	return func(m *Manager) { m.agentGrace = d }
}

func TestAgentGoneFailsHandshakeDuringGrace(t *testing.T) {
	e, srv := connected(t, envOpts{hook: withGrace(time.Minute)})
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET: %v", err)
	}
	e.stopAgent()
	e.waitCard(serialA, false)

	// Force a fresh handshake from the client: its UseInitiator DH must go
	// to the (gone) agent and fail.
	peer := e.clientDev().LookupPeer(device.NoisePublicKey(srv.pub))
	if peer == nil {
		t.Fatal("client has no server peer")
	}
	peer.ExpireCurrentKeypairs()
	if err := get(tnet, 2*time.Second); err == nil {
		t.Fatal("GET succeeded without an agent")
	}

	// Within the grace period the daemon keeps the tunnel configured, so an
	// agent restart does not cost a reconnect.
	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q during the grace period, want connected", st.State)
	}
}

func TestAgentExitTearsDownAfterGrace(t *testing.T) {
	const grace = 300 * time.Millisecond
	e, _ := connected(t, envOpts{hook: withGrace(grace)})
	tnet, cfg := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET: %v", err)
	}
	start := time.Now()
	e.stopAgent()
	e.waitState(StateCardRemoved, grace+3*time.Second)
	if d := time.Since(start); d < grace {
		t.Errorf("torn down %v after the agent left, want >= grace %v", d, grace)
	}
	// The state changes before the device is closed; wait for the routes to
	// go, which happens after the close.
	for deadline := time.Now().Add(3 * time.Second); ; {
		cfg.mu.Lock()
		removed := cfg.removed
		cfg.mu.Unlock()
		if removed == 1 {
			break
		}
		if removed > 1 || time.Now().After(deadline) {
			t.Fatalf("Configurer.Remove called %d times, want 1 (device closed)", removed)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := get(tnet, time.Second); err == nil {
		t.Fatal("GET succeeded after the tunnel was torn down")
	}

	// A later agent of the same user reports the card again: the tunnel
	// comes back on a new device, without a PIN (the card is still verified).
	e.startAgent()
	e.waitState(StateConnected, 5*time.Second)
	if n := e.f.count(); n != 2 {
		t.Fatalf("%d TUN devices made, want 2 (reconnect builds a new device)", n)
	}
	tnet, _ = e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET after the agent returned: %v", err)
	}
	if n := e.p.count(); n != 1 {
		t.Errorf("PIN asked %d times, want 1 (card stayed verified)", n)
	}
}

func TestAgentRestartWithinGraceKeepsTunnel(t *testing.T) {
	const grace = 500 * time.Millisecond
	e, srv := connected(t, envOpts{hook: withGrace(grace)})
	tnet, cfg := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET: %v", err)
	}
	e.stopAgent()
	e.waitCard(serialA, false)
	e.startAgent()
	e.waitCard(serialA, true)

	// Let the grace timer of the old agent fire: the new agent reports the
	// card, so nothing is torn down.
	time.Sleep(grace + 300*time.Millisecond)
	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q after a restart within the grace period, want connected", st.State)
	}
	cfg.mu.Lock()
	removed := cfg.removed
	cfg.mu.Unlock()
	if removed != 0 {
		t.Errorf("Configurer.Remove called %d times, want 0", removed)
	}

	// Handshakes work again on the same device.
	e.clientDev().LookupPeer(device.NoisePublicKey(srv.pub)).ExpireCurrentKeypairs()
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := get(tnet, time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery after the agent returned: %v", err)
		}
	}
	if n := e.f.count(); n != 1 {
		t.Errorf("%d devices made, want 1", n)
	}
	if n := e.p.count(); n != 1 {
		t.Errorf("PIN asked %d times, want 1 (card stayed verified)", n)
	}
}

func TestInitiationFloodDoesNotStarveHandshake(t *testing.T) {
	e, srv := connected(t, envOpts{})
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET: %v", err)
	}
	clientPub := e.b.pub(serialA)
	port := uapiInt(t, e.clientDev(), "listen_port")

	udp, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	// Initiations with random content and a valid mac1 for the client's
	// public key: each one makes the client do UseResponder DH with the
	// (random) ephemeral before anything can be authenticated.
	var gen device.CookieGenerator
	gen.Init(device.NoisePublicKey(clientPub))
	var (
		mu    sync.Mutex
		ephs  [][32]byte
		sent  int
		stop  = make(chan struct{})
		flood = make(chan struct{})
	)
	const rate = 200
	start := time.Now()
	go func() {
		defer close(flood)
		// Paced by the clock rather than by ticks, so a slow scheduler (race
		// detector) still sends rate packets per second on average.
		tick := time.NewTicker(time.Second / rate)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			due := int(time.Since(start).Seconds() * rate)
			mu.Lock()
			behind := due - sent
			mu.Unlock()
			for ; behind > 0; behind-- {
				pkt := make([]byte, device.MessageInitiationSize)
				binary.LittleEndian.PutUint32(pkt, device.MessageInitiationType)
				rand.Read(pkt[4:116])
				gen.AddMacs(pkt)
				var eph [32]byte
				copy(eph[:], pkt[8:40])
				mu.Lock()
				ephs = append(ephs, eph)
				sent++
				mu.Unlock()
				udp.Write(pkt)
			}
		}
	}()

	time.Sleep(time.Second)
	// Our own handshake, started in the middle of the flood.
	peer := e.clientDev().LookupPeer(device.NoisePublicKey(srv.pub))
	peer.ExpireCurrentKeypairs()
	hsStart := time.Now()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("own handshake during flood: %v", err)
	}
	hs := time.Since(hsStart)
	time.Sleep(2 * time.Second)
	close(stop)
	<-flood
	floodDur := time.Since(start)
	time.Sleep(500 * time.Millisecond) // let in-flight calls land

	mu.Lock()
	n := e.b.callsFor(ephs...)
	total := sent
	mu.Unlock()
	achieved := float64(total) / floodDur.Seconds()
	limit := 10 + int(5*(floodDur+500*time.Millisecond).Seconds()) + 1
	t.Logf("flood: %d initiations in %v (%.0f/s); responder card calls %d (limit %d); own handshake %v",
		total, floodDur.Round(time.Millisecond), achieved, n, limit, hs.Round(time.Millisecond))
	if achieved < 150 {
		t.Errorf("flood rate %.0f/s, want about %d/s", achieved, rate)
	}
	if n < 5 {
		t.Fatalf("only %d flood initiations reached the card: the flood is not exercising the responder path", n)
	}
	if n > limit {
		t.Fatalf("%d responder card calls, limit %d (5/s + burst 10)", n, limit)
	}
	if hs > 5*time.Second {
		t.Fatalf("own handshake took %v under flood, want <= 5s", hs)
	}
}

func TestNonAdminCannotAddTunnel(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialA}, notAdmin: true, noAgent: true})
	cfg := e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, &server{port: 51820}, "")
	err := e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: tunName, Config: cfg}, nil)
	assertCode(t, err, ipc.CodeForbidden)
	assertCode(t, e.call(ipc.MethodTunnelRemove, ipc.TunnelName{Name: tunName}, nil), ipc.CodeForbidden)
	// Neither an admin nor an agent's user yet.
	assertCode(t, e.call(ipc.MethodTunnelStatus, nil, nil), ipc.CodeForbidden)
	assertCode(t, e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeForbidden)

	e.startAgent()
	e.waitCard(serialA, true)
	var all []ipc.TunnelStatus
	if err := e.call(ipc.MethodTunnelStatus, nil, &all); err != nil {
		t.Fatalf("status as the agent's user: %v", err)
	}
	err = e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: tunName, Config: cfg}, nil)
	assertCode(t, err, ipc.CodeForbidden)
}

func TestSelectsFirstPresentIdentity(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialB}, clientAddr: []string{"10.0.0.3"}})
	srv := newServer(t, e.b.pub(serialB), "10.0.0.3")
	e.add(e.config([]keyref.Ref{refA, refB}, []string{"10.0.0.2", "10.0.0.3"}, srv, ""))
	e.waitCard(serialB, true)
	st := e.connect()
	if st.Identity != refB.String() {
		t.Fatalf("identity %q, want %s", st.Identity, refB)
	}
	tnet, cfg := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET with the second identity: %v", err)
	}
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	if !slices.Equal(cfg.addrs, []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32")}) {
		t.Fatalf("addresses %v, want the second identity's", cfg.addrs)
	}
}

// ---- rulings and extra coverage ----

// R7: SetStaticKey exactly once per device, before Up, never on a live
// device; a reconnect builds a new device. UAPI never sets a private key.
func TestStaticKeySetOnceBeforeUp(t *testing.T) {
	var (
		mu  sync.Mutex
		ops = map[*device.Device][]string{}
		seq []*device.Device
	)
	rec := func(d *device.Device, op string) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := ops[d]; !ok {
			seq = append(seq, d)
		}
		ops[d] = append(ops[d], op)
	}
	hook := func(m *Manager) {
		real := m.ops
		m.ops.setStaticKey = func(d *device.Device, k device.StaticKey) error {
			rec(d, "setStaticKey")
			return real.setStaticKey(d, k)
		}
		m.ops.ipcSet = func(d *device.Device, s string) error {
			if strings.Contains(s, "private_key") {
				rec(d, "private_key!")
			}
			rec(d, "ipcSet")
			return real.ipcSet(d, s)
		}
		m.ops.up = func(d *device.Device) error {
			rec(d, "up")
			return real.up(d)
		}
	}
	e, _ := connected(t, envOpts{hook: hook})
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// pin_ready on the live device must recompute, not set the key.
	e.m.pinReady(serialA, uint32(os.Getuid()))
	e.b.setPresent(serialA, false)
	e.waitState(StateCardRemoved, 3*time.Second)
	e.b.setPresent(serialA, true)
	e.waitState(StateConnected, 5*time.Second)
	tnet, _ = e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seq) != 2 {
		t.Fatalf("%d devices, want 2", len(seq))
	}
	for i, d := range seq {
		if got := ops[d]; !slices.Equal(got, []string{"setStaticKey", "ipcSet", "up"}) {
			t.Errorf("device %d ops %v, want [setStaticKey ipcSet up]", i, got)
		}
	}
}

// R17/R21: the PIN is asked by the proof-of-possession X25519 before any
// device exists, and agent error codes reach the caller.
func TestProofOfPossessionBeforeDeviceAndWrongPIN(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialA}, pin: wrongPIN})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.add(e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""))
	e.waitCard(serialA, true)
	err := e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil)
	assertCode(t, err, ipc.CodeWrongPIN)
	if !strings.Contains(err.Error(), "2 attempts left") {
		t.Errorf("error %q does not carry the retries left", err)
	}
	if n := e.f.count(); n != 0 {
		t.Fatalf("%d TUN devices made after a failed warm-up, want 0", n)
	}
	if st := e.status(); st.State != StateDisconnected || st.Identity != "" {
		t.Fatalf("status %+v, want an unbound disconnected tunnel", st)
	}

	// The right PIN then connects. The proof of possession used a fresh
	// ephemeral key, so the only DH with the server key is the precompute.
	e.p.mu.Lock()
	e.p.pin = testPIN
	e.p.mu.Unlock()
	if st := e.connect(); st.State != StateConnected {
		t.Fatalf("state %q", st.State)
	}
	if n := e.b.callsFor(srv.pub); n != 1 {
		t.Errorf("%d DH calls against the server key, want 1 (precompute)", n)
	}
}

func TestPinReadyRecomputesStaticStatic(t *testing.T) {
	e, srv := connected(t, envOpts{})
	before := e.b.callsFor(srv.pub)
	// Only the agent's own user may trigger it for its card.
	e.m.pinReady(serialA, uint32(os.Getuid())+1)
	time.Sleep(100 * time.Millisecond)
	if n := e.b.callsFor(srv.pub); n != before {
		t.Fatalf("pin_ready from another uid recomputed (%d -> %d calls)", before, n)
	}
	e.m.pinReady(serialA, uint32(os.Getuid()))
	deadline := time.Now().Add(3 * time.Second)
	for e.b.callsFor(srv.pub) != before+1 {
		if time.Now().After(deadline) {
			t.Fatalf("pin_ready did not recompute static-static (%d calls, want %d)", e.b.callsFor(srv.pub), before+1)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// R11: endpoint hostnames are resolved at every connect.
func TestEndpointHostnameResolvedAtConnect(t *testing.T) {
	var (
		mu      sync.Mutex
		lookups []string
		fail    bool
	)
	hook := func(m *Manager) {
		m.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			mu.Lock()
			defer mu.Unlock()
			lookups = append(lookups, host)
			if fail {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
		}
	}
	e := newEnv(t, envOpts{present: []uint32{serialA}, hook: hook})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.add(e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, fmt.Sprintf("vpn.example.test:%d", srv.port)))
	e.waitCard(serialA, true)
	e.connect()
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET via resolved endpoint: %v", err)
	}
	e.b.setPresent(serialA, false)
	e.waitState(StateCardRemoved, 3*time.Second)
	e.b.setPresent(serialA, true)
	e.waitState(StateConnected, 5*time.Second)
	mu.Lock()
	n := len(lookups)
	fail = true
	mu.Unlock()
	if n != 2 || lookups[0] != "vpn.example.test" {
		t.Fatalf("lookups %q, want vpn.example.test twice (once per connect)", lookups)
	}

	if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	err := e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil)
	assertCode(t, err, ipc.CodeUnavailable)
	if !strings.Contains(err.Error(), "vpn.example.test") {
		t.Errorf("error %q does not name the host", err)
	}
	if n := e.f.count(); n != 2 {
		t.Errorf("%d devices, want no new device after a failed lookup", n)
	}
}

func TestStorePersistsTunnels(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	cfg := e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, &server{port: 51820}, "")
	e.add(cfg)
	assertCode(t, e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: tunName, Config: cfg}, nil), ipc.CodeBadRequest)
	assertCode(t, e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: "../x", Config: cfg}, nil), ipc.CodeBadRequest)
	assertCode(t, e.call(ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: "y", Config: "PrivateKey = abc"}, nil), ipc.CodeBadRequest)

	fi, err := os.Stat(filepath.Join(e.store, tunName+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(e.store); di.Mode().Perm() != 0o700 {
		t.Errorf("store mode %v, want 0700", di.Mode().Perm())
	}

	m2 := NewManager(Options{Socket: e.socket + "2", StoreDir: e.store, TUN: e.f.make})
	if err := m2.load(); err != nil {
		t.Fatal(err)
	}
	if m2.tunnels[tunName] == nil {
		t.Fatal("tunnel not loaded from the store")
	}

	if err := e.call(ipc.MethodTunnelRemove, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.store, tunName+".conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config still on disk after remove: %v", err)
	}
	assertCode(t, e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeNotFound)
}

func TestConnectWithoutCard(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialB}})
	cfg := e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, &server{port: 51820}, "")
	e.add(cfg)
	e.waitCard(serialB, true)
	assertCode(t, e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeUnavailable)
	if n := e.f.count(); n != 0 {
		t.Fatalf("%d devices made without a card", n)
	}
}

func TestRemoteKeyErrorMapping(t *testing.T) {
	cases := []struct {
		in   error
		want error
	}{
		{&ipc.Error{Code: ipc.CodePINBlocked, Message: "x"}, keyprovider.ErrPINBlocked},
		{&ipc.Error{Code: ipc.CodePINRequired, Message: "x"}, keyprovider.ErrPINRequired},
		{&ipc.Error{Code: ipc.CodeLowOrderPoint, Message: "x"}, keyprovider.ErrLowOrderPoint},
		{&ipc.Error{Code: ipc.CodeUnavailable, Message: "x"}, keyprovider.ErrUnavailable},
		{&ipc.Error{Code: ipc.CodeBadRequest, Message: "x"}, keyprovider.ErrUnavailable},
		{&ipc.Error{Code: "something_new", Message: "x"}, keyprovider.ErrUnavailable},
		{ipc.ErrClosed, keyprovider.ErrUnavailable},
		{context.DeadlineExceeded, context.DeadlineExceeded},
	}
	for _, c := range cases {
		if got := mapKeyErr(c.in); !errors.Is(got, c.want) {
			t.Errorf("mapKeyErr(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	got := mapKeyErr(&ipc.Error{Code: ipc.CodeWrongPIN, Message: "wrong PIN, 1 attempts left"})
	var pe *keyprovider.PINError
	if !errors.As(got, &pe) || pe.RetriesLeft != 1 {
		t.Errorf("wrong_pin mapped to %v, want *PINError{1}", got)
	}
	var ie *ipc.Error
	if !errors.As(got, &ie) || ie.Code != ipc.CodeWrongPIN {
		t.Errorf("mapped error lost the agent's ipc.Error: %v", got)
	}
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	var ie *ipc.Error
	if !errors.As(err, &ie) || ie.Code != code {
		t.Fatalf("error %v, want code %q", err, code)
	}
}

// ---- several users (R19, R20) ----

var (
	uidA     = uint32(os.Getuid()) // the test process: CLI and real agent
	uidB     = uidA + 1000         // another local user, fake agent
	uidAdmin = uint32(4242)        // an administrator without an agent
)

func onlyAdmin(uid uint32) bool { return uid == uidAdmin }

// fakeAgent is an agent connection registered as uid. It answers key.public
// with pub and key.x25519 with key's DH, whatever the card serial: it may be
// lying about either. gate, if set, holds every key.x25519 until closed.
type fakeAgent struct {
	dc      *ipc.Conn // daemon side
	ac      *ipc.Conn // agent side
	publics atomic.Int32
	x25519s atomic.Int32
	gate    chan struct{}
}

func newFakeAgent(t *testing.T, e *env, uid uint32, key *softkey.Key, serials ...uint32) *fakeAgent {
	return newLyingAgent(t, e, uid, key.PublicKey(), key, nil, serials...)
}

func newLyingAgent(t *testing.T, e *env, uid uint32, pub [32]byte, key *softkey.Key, gate chan struct{}, serials ...uint32) *fakeAgent {
	t.Helper()
	path := filepath.Join(filepath.Dir(e.socket), fmt.Sprintf("f%d", uid))
	l, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *ipc.Conn, 1)
	go func() {
		c, err := ipc.Accept(l)
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	ac, err := ipc.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	dc := <-accepted
	l.Close()
	if dc == nil {
		t.Fatal("accept failed")
	}
	fa := &fakeAgent{dc: dc, ac: ac, gate: gate}
	ac.Handle(ipc.MethodKeyPublic, func(context.Context, uint32, json.RawMessage) (any, error) {
		fa.publics.Add(1)
		return ipc.KeyPublicResult{Public: base64.StdEncoding.EncodeToString(pub[:])}, nil
	})
	ac.Handle(ipc.MethodKeyX25519, func(ctx context.Context, _ uint32, params json.RawMessage) (any, error) {
		fa.x25519s.Add(1)
		if fa.gate != nil {
			select {
			case <-fa.gate:
			case <-ctx.Done():
				return nil, &ipc.Error{Code: ipc.CodeUnavailable, Message: "x"}
			}
		}
		var req ipc.KeyRequest
		json.Unmarshal(params, &req)
		b, _ := base64.StdEncoding.DecodeString(req.Peer)
		var peer [32]byte
		copy(peer[:], b)
		ss, err := key.X25519(ctx, peer)
		if err != nil {
			return nil, &ipc.Error{Code: ipc.CodeLowOrderPoint, Message: "x"}
		}
		return ipc.KeyX25519Result{Shared: base64.StdEncoding.EncodeToString(ss[:])}, nil
	})
	go ac.Serve(context.Background())
	go func() { dc.Serve(context.Background()); e.m.dropAgent(dc) }()
	t.Cleanup(func() { ac.Close(); dc.Close() })
	e.m.agentRegister(dc, uid, serials)
	return fa
}

func (e *env) tunnel() *tunnel {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return e.m.tunnels[tunName]
}

func (e *env) boundUID() uint32 {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return e.m.tunnels[tunName].uid
}

func otherKey(t *testing.T) *softkey.Key {
	k, err := softkey.New()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// B's agent claims A's card: B can neither take the tunnel over nor touch
// it, and B's card events and pin_ready do not affect it.
func TestOtherUserCannotTouchTunnel(t *testing.T) {
	e, srv := connected(t, envOpts{admin: onlyAdmin})
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	fb := newFakeAgent(t, e, uidB, otherKey(t), serialA)
	ctx := context.Background()

	_, err := e.m.requestDisconnect(uidB, tunName)
	assertCode(t, err, ipc.CodeForbidden)
	_, err = e.m.requestConnect(ctx, uidB, tunName)
	assertCode(t, err, ipc.CodeForbidden)

	before := e.b.callsFor(srv.pub)
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardRemoved, Serial: serialA})
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventCardInserted, Serial: serialA})
	e.m.agentEvent(fb.dc, uidB, ipc.AgentEvent{Type: ipc.EventPINReady, Serial: serialA})
	e.m.agentRegister(fb.dc, uidB, nil) // B "loses" the card
	time.Sleep(200 * time.Millisecond)

	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q after B's events, want connected", st.State)
	}
	if u := e.boundUID(); u != uidA {
		t.Fatalf("tunnel bound to uid %d, want %d", u, uidA)
	}
	if n := e.b.callsFor(srv.pub); n != before {
		t.Errorf("B's pin_ready caused %d DH calls on A's card", n-before)
	}
	if n := fb.publics.Load() + fb.x25519s.Load(); n != 0 {
		t.Errorf("B's agent got %d key calls", n)
	}
	if n := e.f.count(); n != 1 {
		t.Errorf("%d devices, want 1", n)
	}
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("A's tunnel broken: %v", err)
	}
}

// A non-admin connect uses only the caller's own agent, in both directions.
func TestNonAdminConnectUsesOnlyOwnAgent(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, "")); err != nil {
		t.Fatal(err)
	}
	e.waitAgentRegistered(uidA)
	// B holds the card (the real key); A's agent sees nothing.
	fb := newFakeAgent(t, e, uidB, e.b.cards[serialA].key, serialA)

	assertCode(t, e.call(ipc.MethodTunnelConnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeUnavailable)
	if n := fb.publics.Load(); n != 0 {
		t.Fatalf("A's connect asked B's agent (%d key.public)", n)
	}

	st, err := e.m.requestConnect(context.Background(), uidB, tunName)
	if err != nil || st.State != StateConnected {
		t.Fatalf("B's connect with its own agent: %+v %v", st, err)
	}
	if u := e.boundUID(); u != uidB {
		t.Fatalf("bound to %d, want B", u)
	}
	// A may not disconnect B's tunnel.
	assertCode(t, e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil), ipc.CodeForbidden)
	if _, err := e.m.requestDisconnect(uidB, tunName); err != nil {
		t.Fatalf("B disconnects its own tunnel: %v", err)
	}

	// Now only A's agent has the card: B's connect must not use it.
	e.m.agentRegister(fb.dc, uidB, nil)
	e.b.setPresent(serialA, true)
	e.waitCard(serialA, true)
	prompts := e.p.count()
	_, err = e.m.requestConnect(context.Background(), uidB, tunName)
	assertCode(t, err, ipc.CodeUnavailable)
	if n := e.p.count(); n != prompts {
		t.Fatalf("B's connect made A's agent prompt for a PIN")
	}
	if n := e.b.callsFor(srv.pub); n != 0 {
		t.Fatalf("B's connect used A's card (%d DH calls)", n)
	}
}

// R20: an agent that comes back without the card (pulled while the agent
// was down) takes the tunnel down at registration.
func TestReregisterWithoutCardTearsDown(t *testing.T) {
	e, _ := connected(t, envOpts{})
	e.stopAgent()
	e.waitCard(serialA, false)
	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q", st.State)
	}
	e.b.setPresent(serialA, false)
	start := time.Now()
	e.startAgent()
	e.waitAgentRegistered(uidA)
	e.waitState(StateCardRemoved, 3*time.Second)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("teardown %v after the agent came back, want <= 2s", d)
	}

	// Same with the card still there: nothing changes.
	e2, _ := connected(t, envOpts{})
	e2.stopAgent()
	e2.waitCard(serialA, false)
	e2.startAgent()
	e2.waitCard(serialA, true)
	time.Sleep(200 * time.Millisecond)
	if st := e2.status(); st.State != StateConnected {
		t.Fatalf("state %q after re-register with the card, want connected", st.State)
	}
}

// waitAgentRegistered waits until an agent of uid has registered.
func (e *env) waitAgentRegistered(uid uint32) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !e.m.agentUser(uid) {
		if time.Now().After(deadline) {
			e.t.Fatalf("no agent of uid %d registered", uid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- configured identity keys and proof of possession (R21) ----

// unbound asserts the tunnel was never bound by a failed connect.
func (e *env) unbound() {
	e.t.Helper()
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	t := e.m.tunnels[tunName]
	if t.hasRef || t.state != StateDisconnected || t.dev != nil {
		e.t.Fatalf("tunnel touched by a failed connect: state %q hasRef %v uid %d", t.state, t.hasRef, t.uid)
	}
}

func (e *env) addA(srv *server) {
	e.t.Helper()
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, "")); err != nil {
		e.t.Fatal(err)
	}
}

func TestFakeAgentWithWrongPublicKeyRefused(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	fb := newFakeAgent(t, e, uidB, otherKey(t), serialA)
	ctx := context.Background()

	for _, uid := range []uint32{uidB, uidAdmin} {
		_, err := e.m.requestConnect(ctx, uid, tunName)
		assertCode(t, err, ipc.CodeForbidden)
		if !strings.Contains(err.Error(), refA.String()) || !strings.Contains(err.Error(), "PublicKey") {
			t.Errorf("uid %d: error %q does not name the KeyRef and the configured key", uid, err)
		}
		e.unbound()
	}
	if fb.publics.Load() != 2 || fb.x25519s.Load() != 0 {
		t.Errorf("fake agent got %d key.public, %d x25519; want 2, 0", fb.publics.Load(), fb.x25519s.Load())
	}
	if n := e.f.count(); n != 0 {
		t.Fatalf("%d devices made", n)
	}
}

// The fake agent echoes the configured public key but cannot do the DH: the
// proof fails, nothing is bound, and the real owner then connects.
func TestFakeAgentEchoingRightPublicKeyFailsPoP(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	fb := newLyingAgent(t, e, uidB, e.b.pub(serialA), otherKey(t), nil, serialA)
	ctx := context.Background()

	for _, uid := range []uint32{uidB, uidAdmin} {
		_, err := e.m.requestConnect(ctx, uid, tunName)
		assertCode(t, err, ipc.CodeForbidden)
		if !strings.Contains(err.Error(), "prove") {
			t.Errorf("uid %d: error %q is not the proof failure", uid, err)
		}
		e.unbound()
	}
	if fb.x25519s.Load() != 2 {
		t.Errorf("fake agent got %d x25519 (the proofs), want 2", fb.x25519s.Load())
	}
	if n := e.f.count(); n != 0 {
		t.Fatalf("%d devices made for an unproven agent", n)
	}
	// The DH it was asked for was never the server's key: an agent learns
	// nothing that helps it pose as the server.
	if n := e.b.callsFor(srv.pub); n != 0 {
		t.Fatalf("server key used %d times", n)
	}

	e.b.setPresent(serialA, true)
	e.waitAgentRegistered(uidA)
	deadline := time.Now().Add(5 * time.Second)
	for e.m.agentFor(serialA, uidA) == nil {
		if time.Now().After(deadline) {
			t.Fatal("A's agent never reported the card")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := e.connect(); st.State != StateConnected {
		t.Fatalf("owner connect: %+v", st)
	}
	if u := e.boundUID(); u != uidA {
		t.Fatalf("bound to %d, want A", u)
	}
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// A non-admin's failing connect never binds the tunnel, and one stalled in
// its proof (a fake agent "waiting for a PIN") does not block the owner.
func TestNonAdminCannotSquatTunnel(t *testing.T) {
	e := newEnv(t, envOpts{present: []uint32{serialA}, admin: onlyAdmin})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.addA(srv)
	e.waitAgentRegistered(uidA)
	gate := make(chan struct{})
	fb := newLyingAgent(t, e, uidB, e.b.pub(serialA), otherKey(t), gate, serialA)

	bDone := make(chan error, 1)
	go func() {
		_, err := e.m.requestConnect(context.Background(), uidB, tunName)
		bDone <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for fb.x25519s.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("B's proof never reached its agent")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := e.status(); st.State != StateDisconnected || st.Identity != "" {
		t.Fatalf("status %+v while B is proving, want untouched", st)
	}
	// B cannot disconnect what it does not hold.
	_, err := e.m.requestDisconnect(uidB, tunName)
	assertCode(t, err, ipc.CodeForbidden)

	// The owner connects while B is stalled.
	if st := e.connect(); st.State != StateConnected {
		t.Fatalf("owner connect during B's stalled proof: %+v", st)
	}
	close(gate)
	select {
	case err := <-bDone:
		assertCode(t, err, ipc.CodeForbidden)
	case <-time.After(5 * time.Second):
		t.Fatal("B's connect did not return")
	}
	if u := e.boundUID(); u != uidA {
		t.Fatalf("bound to %d, want A", u)
	}
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := e.f.count(); n != 1 {
		t.Errorf("%d devices, want 1", n)
	}
}

// An administrator's own agents come first across all identities, even when
// an earlier identity is offered (truthfully) by another user's agent.
func TestAdminTriesOwnAgentsAcrossAllIdentitiesFirst(t *testing.T) {
	isA := func(uid uint32) bool { return uid == uidA }
	e := newEnv(t, envOpts{present: []uint32{serialB}, clientAddr: []string{"10.0.0.3"}, admin: isA})
	srv := newServer(t, e.b.pub(serialB), "10.0.0.3")
	if err := e.m.add(tunName, e.config([]keyref.Ref{refA, refB}, []string{"10.0.0.2", "10.0.0.3"}, srv, "")); err != nil {
		t.Fatal(err)
	}
	e.waitCard(serialB, true)
	// B really holds card A (right key, can prove it).
	fb := newFakeAgent(t, e, uidB, e.b.cards[serialA].key, serialA)

	st := e.connect() // A is the admin
	if st.Identity != refB.String() {
		t.Fatalf("identity %q, want %s from the admin's own agent", st.Identity, refB)
	}
	if u := e.boundUID(); u != uidA {
		t.Fatalf("bound to %d, want the admin's uid", u)
	}
	if n := fb.publics.Load() + fb.x25519s.Load(); n != 0 {
		t.Fatalf("other user's agent was asked %d times", n)
	}
	tnet, _ := e.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	// Without its own card the admin falls back to B's agent, which proves
	// its key: identity A, bound to B.
	if _, err := e.m.requestDisconnect(uidA, tunName); err != nil {
		t.Fatal(err)
	}
	e.b.setPresent(serialB, false)
	e.waitCard(serialB, false)
	st, err := e.m.requestConnect(context.Background(), uidA, tunName)
	if err != nil || st.Identity != refA.String() {
		t.Fatalf("admin fallback: %+v %v, want identity %s", st, err, refA)
	}
	if u := e.boundUID(); u != uidB {
		t.Fatalf("bound to %d, want B (whose agent proved the key)", u)
	}
	if fb.x25519s.Load() < 1 {
		t.Fatal("B's agent did not get the proof")
	}
}
