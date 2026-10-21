// Package daemon is Latchwire's privileged tunnel manager. It owns the TUN
// devices and wireguard-go devices, and serves the CLI and the per-user
// agents on one unix socket.
//
// A device's static key is a remoteKey: every X25519 goes to the agent of
// the user whose card holds the key. When that agent reports the card
// removed, the device is closed; when the card comes back, the tunnel is
// rebuilt from scratch with a new device (SetStaticKey is only ever called
// once per device, before Up). When the agent itself goes away, its user's
// tunnels are torn down the same way after agentGrace unless an agent of
// that user reports the card again.
package daemon

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/wgadapter"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/killswitch"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
	"github.com/Kodviva/latchwire/internal/netmon"
)

// Tunnel states reported by tunnel.status.
const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateCardRemoved  = "card_removed"
	StateError        = "error"
)

const (
	resolveTimeout = 10 * time.Second
	// netDebounce is how long the network must be quiet before its
	// changes are acted on.
	netDebounce = 500 * time.Millisecond
	// verifyEvery is how often the connected tunnels' network
	// configuration is checked without a network change (P12): DHCP lease
	// renewals and router advertisements rewrite the DNS (macOS) without
	// a route or link event.
	verifyEvery = 30 * time.Second

	// agentGrace is how long a user's tunnels stay up after that user's
	// agent connection closes. An agent restarted within it keeps them; after
	// it, every tunnel of that user whose card no agent reports is torn down
	// to card_removed (spec §5.5).
	agentGrace = 10 * time.Second

	// killSwitchTimeout bounds one Firewall.Set (pf runs up to four
	// commands).
	killSwitchTimeout = 45 * time.Second
)

// TUNFactory creates the TUN device for a tunnel and the Configurer for its
// addresses and routes.
type TUNFactory func(name string, mtu int) (tun.Device, netcfg.Configurer, error)

// Options configures a Manager. Zero fields get production defaults.
type Options struct {
	Socket   string     // DefaultSocket
	StoreDir string     // DefaultStoreDir()
	TUN      TUNFactory // nil = DefaultTUN(Runner, journal), made by Serve
	Bind     func() conn.Bind
	IsAdmin  func(uid uint32) (bool, error) // nil = ipc.IsAdmin
	// JournalPath is the file that records system changes for cleanup after
	// a crash; empty = netcfg.DefaultJournalPath.
	JournalPath string
	// Runner runs the system commands of the default TUN factory and of
	// the startup cleanup; nil = netcfg.ExecRunner().
	Runner netcfg.Runner
	// VerifyEvery is how often the connected tunnels' network
	// configuration is checked when nothing signals a network change;
	// 0 = 30 s.
	VerifyEvery time.Duration
	// Firewall is the kill switch; nil = killswitch.New(Runner, journal),
	// made the first time the kill switch is needed.
	Firewall killswitch.Firewall
}

// DefaultTUN returns the factory that creates kernel TUN devices (utunN on
// macOS, the tunnel's name on Linux) configured with the platform's network
// commands, run by r and journaled in j.
func DefaultTUN(r netcfg.Runner, j *netcfg.Journal) TUNFactory {
	return func(name string, mtu int) (tun.Device, netcfg.Configurer, error) {
		ifname := name
		if runtime.GOOS == "darwin" {
			ifname = "utun"
		}
		d, err := tun.CreateTUN(ifname, mtu)
		if err != nil {
			return nil, nil, err
		}
		return d, netcfg.New(r, j), nil
	}
}

// devOps are the device calls whose order matters (R7); tests wrap them.
type devOps struct {
	setStaticKey func(*device.Device, device.StaticKey) error
	ipcSet       func(*device.Device, string) error
	up           func(*device.Device) error
	close        func(*device.Device)
}

var defaultOps = devOps{
	setStaticKey: (*device.Device).SetStaticKey,
	ipcSet:       (*device.Device).IpcSet,
	up:           (*device.Device).Up,
	close:        (*device.Device).Close,
}

// Manager runs tunnels. Create it with NewManager and run Serve.
type Manager struct {
	socket  string
	store   *store
	tun     TUNFactory // nil until Serve: the default needs the journal
	runner  netcfg.Runner
	jpath   string
	bind    func() conn.Bind
	isAdmin func(uint32) (bool, error)
	// resolve looks up an endpoint host; mark != 0 marks its queries
	// (SO_MARK, Linux) so they leave outside a full tunnel.
	resolve func(ctx context.Context, host string, mark uint32) ([]netip.Addr, error)
	// fullTunnel says whether this platform routes 0.0.0.0/0 and ::/0
	// (Linux, macOS). pickTable chooses a full tunnel's routing table,
	// which is also its fwmark (Linux; nil: no table and no mark).
	fullTunnel bool
	pickTable  func(ctx context.Context) (uint32, error)
	// netSource opens the network change notifications; netDebounce is
	// the netDebounce constant (tests shorten it).
	netSource   func() (netmon.Source, error)
	netDebounce time.Duration
	verifyEvery time.Duration // Options.VerifyEvery
	ops         devOps
	// agentGrace is the agentGrace constant; tests shorten it.
	agentGrace time.Duration
	journal    *netcfg.Journal // set by Serve

	// The kill switch. ksMu serializes Firewall.Set calls (and orders
	// them: the state set is computed inside); it is never taken with mu
	// held. fw is Options.Firewall or made on first use (fwErr: the
	// platform has none). ksLast is the state in place (nil: unknown,
	// the next sync sets it whatever it is).
	ksMu   sync.Mutex
	fw     killswitch.Firewall
	fwErr  error
	ksLast *killswitch.State
	// ksSaved is what the kill switch's tunnel record (store) holds.
	ksSaved []ksTunnel
	// ksBlocking says that blocking rules may be in place: a blocking Set
	// was attempted and no release has succeeded since. Endpoint lookups
	// behind them may fail in any way, so any failure may use the cache.
	ksBlocking atomic.Bool

	mu      sync.Mutex
	ctx     context.Context // Serve's ctx; tunnel lifetimes derive from it
	tunnels map[string]*tunnel
	agents  map[*ipc.Conn]*agentState
	nextSeq uint64
}

// agentState is one agent connection. seq orders registrations (0: not
// registered yet).
type agentState struct {
	uid     uint32
	seq     uint64
	serials map[uint32]bool
}

// tunnel is one configured tunnel.
//
// Every intent that changes the state (connect, teardown) increments gen. A
// device belongs to the attempt that built it (devGen) and is closed by
// whoever holds op once devGen != gen. op is held for a whole connect and
// while closing a device, so a new device is never built while an old one of
// the same tunnel is still open. A teardown cancels the running attempt
// before waiting for op, so a connect stuck on the agent gives way at once.
type tunnel struct {
	name string
	cfg  *config.Tunnel
	op   sync.Mutex

	// guarded by Manager.mu
	state  string
	ref    keyref.Ref
	hasRef bool
	uid    uint32 // user whose agent serves the key
	gen    uint64
	cancel context.CancelFunc // ends the attempt and the device's key calls
	dev    *device.Device
	cfgr   netcfg.Configurer
	iface  string // the device's interface (utunN on macOS)
	devGen uint64
	// policy is the tunnel's policy, read at load, add and every connect.
	policy Policy
	// What the kill switch passes for the device: the resolved endpoints,
	// the UDP port the device is bound to, and the mark of its socket and
	// endpoint lookups (Linux full tunnel; set while connecting).
	endpoints  []netip.AddrPort
	listenPort uint16
	mark       uint32
	// dnsRole is the part the tunnel's DNS servers were given when it
	// last started connecting (dnsRoleLocked); applied is what the
	// Configurer of dev put in place (zero without dev).
	dnsRole netcfg.DNSRole
	applied netcfg.Applied
	// abort is cancelled by every teardown: a connect still proving an
	// agent (and maybe waiting for a PIN) then gives up.
	abort       context.Context
	abortCancel context.CancelFunc
}

func newTunnel(name string, cfg *config.Tunnel, pol Policy) *tunnel {
	t := &tunnel{name: name, cfg: cfg, state: StateDisconnected, policy: pol}
	t.abort, t.abortCancel = context.WithCancel(context.Background())
	return t
}

// NewManager returns a manager; it does nothing until Serve.
func NewManager(o Options) *Manager {
	m := &Manager{
		socket:      o.Socket,
		store:       &store{dir: o.StoreDir},
		tun:         o.TUN,
		runner:      o.Runner,
		jpath:       o.JournalPath,
		bind:        o.Bind,
		isAdmin:     o.IsAdmin,
		ops:         defaultOps,
		agentGrace:  agentGrace,
		ctx:         context.Background(),
		tunnels:     map[string]*tunnel{},
		agents:      map[*ipc.Conn]*agentState{},
		resolve:     lookupHost,
		fullTunnel:  runtime.GOOS == "linux" || runtime.GOOS == "darwin",
		netSource:   netmon.NewSource,
		netDebounce: netDebounce,
		verifyEvery: o.VerifyEvery,
		fw:          o.Firewall,
		ksLast:      &killswitch.State{}, // Serve finds out what a crash left
	}
	if m.verifyEvery <= 0 {
		m.verifyEvery = verifyEvery
	}
	if runtime.GOOS == "linux" {
		m.pickTable = func(ctx context.Context) (uint32, error) { return netcfg.LinuxTable(ctx, m.runner) }
	}
	if m.socket == "" {
		m.socket = DefaultSocket
	}
	if m.store.dir == "" {
		m.store.dir = DefaultStoreDir()
	}
	if m.runner == nil {
		m.runner = netcfg.ExecRunner()
	}
	if m.jpath == "" {
		m.jpath = netcfg.DefaultJournalPath
	}
	if m.bind == nil {
		m.bind = conn.NewDefaultBind
	}
	if m.isAdmin == nil {
		m.isAdmin = ipc.IsAdmin
	}
	return m
}

// load reads the stored tunnels.
func (m *Manager) load() error {
	ts, err := m.store.load()
	if err != nil {
		return err
	}
	pols := make(map[string]Policy, len(ts))
	for name := range ts {
		pols[name] = m.store.policyFor(name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, cfg := range ts {
		m.tunnels[name] = newTunnel(name, cfg, pols[name])
	}
	return nil
}

// Serve loads the stored tunnels, listens on the socket and serves until
// ctx ends. All tunnels are taken down before it returns ctx.Err().
func (m *Manager) Serve(ctx context.Context) error {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	// Undo what a crashed run left in the system before anything is
	// loaded, except an active kill switch: it keeps blocking (fail
	// closed) until its tunnels are taken down.
	j, err := netcfg.OpenJournal(m.jpath)
	if err != nil {
		return err
	}
	m.journal = j
	ksHeld := len(j.Entries()[killswitch.JournalOwner]) > 0
	keep := func(owner string) bool { return owner == killswitch.JournalOwner }
	if err := netcfg.Cleanup(ctx, m.runner, j, keep); err != nil {
		log.Printf("daemon: cleaning up after the previous run: %v", err)
	}
	if m.tun == nil {
		m.tun = DefaultTUN(m.runner, j)
	}
	if err := m.load(); err != nil {
		return err
	}
	m.startKillSwitch(ksHeld, j.RecoveredFromCorruption())
	l, err := ipc.Listen(m.socket)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	wctx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		m.watchNetwork(wctx)
	}()

	var wg sync.WaitGroup
	var acceptErr error
	for {
		c, err := ipc.Accept(l)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if errors.Is(err, net.ErrClosed) {
				acceptErr = err
				break
			}
			log.Printf("daemon: accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		m.handle(c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Serve(ctx)
			m.dropAgent(c)
		}()
	}
	l.Close()
	wg.Wait()
	stopWatch()
	<-watched
	m.shutdown()
	if acceptErr != nil {
		return acceptErr
	}
	return ctx.Err()
}

// watchNetwork refreshes the connected tunnels' network configuration (the
// endpoint routes that follow the gateway, the automatic MTU, the DNS that
// follows the primary service) after every network change, and every
// verifyEvery without one (P12: DHCP renewals rewrite the DNS silently),
// until ctx ends. Refresh changes nothing when nothing changed (P9).
// Notifications about the tunnels' own interfaces are not changes of the
// network. When the notifications fail, the periodic check goes on.
func (m *Manager) watchNetwork(ctx context.Context) {
	var changes <-chan netmon.Event
	if src, err := m.netSource(); err != nil {
		log.Printf("daemon: not watching network changes: %v", err)
	} else {
		changes = netmon.Watch(ctx, src, m.netDebounce, m.ownIface)
	}
	tick := time.NewTicker(m.verifyEvery)
	defer tick.Stop()
	for {
		select {
		case _, ok := <-changes:
			if !ok {
				changes = nil
				if ctx.Err() != nil {
					return
				}
				log.Printf("daemon: network change notifications stopped (the source failed); the network configuration is only checked every %v until restart", m.verifyEvery)
				continue
			}
			m.refreshAll(ctx)
		case <-tick.C:
			m.refreshAll(ctx)
			m.verifyKillSwitch(ctx)
		case <-ctx.Done():
			if changes != nil {
				for range changes { // the watcher ends with ctx
				}
			}
			return
		}
	}
}

// ownIface reports whether name is the interface of one of the tunnels.
func (m *Manager) ownIface(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tunnels {
		if t.iface != "" && t.iface == name {
			return true
		}
	}
	return false
}

// refreshAll calls Refresh for each connected tunnel in turn. Manager.mu is
// not held while Refresh runs its commands; a Configurer serializes Refresh
// with its own Remove, and a removed one refreshes nothing. A failed
// Refresh leaves the tunnel up: the next change retries it.
func (m *Manager) refreshAll(ctx context.Context) {
	type target struct {
		name string
		cfgr netcfg.Configurer
	}
	m.mu.Lock()
	var ts []target
	for _, t := range m.tunnels {
		if t.state == StateConnected && t.cfgr != nil {
			ts = append(ts, target{t.name, t.cfgr})
		}
	}
	m.mu.Unlock()
	slices.SortFunc(ts, func(a, b target) int { return cmp.Compare(a.name, b.name) })
	for _, t := range ts {
		if ctx.Err() != nil {
			return
		}
		if err := t.cfgr.Refresh(ctx); err != nil {
			debugf("daemon: tunnel %s: refreshing the network configuration: %v", t.name, err)
		}
	}
}

func (m *Manager) shutdown() {
	m.mu.Lock()
	ts := make([]*tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		ts = append(ts, t)
	}
	m.mu.Unlock()
	for _, t := range ts {
		m.teardown(t, StateDisconnected, nil)
	}
}

// ---- requests ----

var (
	errForbidden  = &ipc.Error{Code: ipc.CodeForbidden, Message: msg.DaemonForbidden}
	errAdminOnly  = &ipc.Error{Code: ipc.CodeForbidden, Message: msg.DaemonAdminOnly}
	errBadRequest = &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.DaemonBadRequest}
	errNotFound   = &ipc.Error{Code: ipc.CodeNotFound, Message: msg.DaemonTunnelNotFound}
	errNoCard     = &ipc.Error{Code: ipc.CodeUnavailable, Message: msg.DaemonNoCard}
	errAborted    = &ipc.Error{Code: ipc.CodeUnavailable, Message: msg.DaemonConnectAborted}
	errNotYours   = &ipc.Error{Code: ipc.CodeForbidden, Message: msg.DaemonNotYourTunnel}
)

func decode(params json.RawMessage, v any) error {
	if len(params) == 0 {
		return errBadRequest
	}
	if err := json.Unmarshal(params, v); err != nil {
		return errBadRequest
	}
	return nil
}

func (m *Manager) admin(uid uint32) bool {
	ok, err := m.isAdmin(uid)
	if err != nil {
		log.Printf("daemon: admin check for uid %d: %v", uid, err)
		return false
	}
	return ok
}

// user reports whether uid may see status: an administrator or the user of
// a registered agent.
func (m *Manager) user(uid uint32) bool {
	return m.agentUser(uid) || m.admin(uid)
}

// agentUser reports whether an agent of uid is registered.
func (m *Manager) agentUser(uid uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.agents {
		if a.seq != 0 && a.uid == uid {
			return true
		}
	}
	return false
}

// requestConnect is tunnel.connect from uid (R19, R21). A non-administrator
// only ever uses its own agent and may not take over a tunnel bound to
// another user; an administrator tries its own agents first, then other
// users'. Either way an agent is used only after it proved it holds the
// configured key.
func (m *Manager) requestConnect(ctx context.Context, uid uint32, name string) (ipc.TunnelStatus, error) {
	admin := m.admin(uid)
	if !admin && !m.agentUser(uid) {
		return ipc.TunnelStatus{}, errForbidden
	}
	return m.connect(ctx, name, uid, admin, "")
}

// requestDisconnect is tunnel.disconnect from uid. A non-administrator may
// only disconnect a tunnel bound to its own uid.
func (m *Manager) requestDisconnect(uid uint32, name string) (ipc.TunnelStatus, error) {
	if m.admin(uid) {
		return m.disconnect(name, nil)
	}
	if !m.agentUser(uid) {
		return ipc.TunnelStatus{}, errForbidden
	}
	return m.disconnect(name, func(t *tunnel) bool { return t.boundTo(uid) })
}

func (m *Manager) handle(c *ipc.Conn) {
	c.Handle(ipc.MethodAgentRegister, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		var p ipc.AgentRegister
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		m.agentRegister(c, uid, p.Serials)
		return nil, nil
	})
	c.Handle(ipc.MethodAgentEvent, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		var p ipc.AgentEvent
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		m.agentEvent(c, uid, p)
		return nil, nil
	})
	c.Handle(ipc.MethodTunnelAdd, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		if !m.admin(uid) {
			return nil, errAdminOnly
		}
		var p ipc.TunnelAdd
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return nil, m.add(p.Name, p.Config)
	})
	c.Handle(ipc.MethodTunnelRemove, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		if !m.admin(uid) {
			return nil, errAdminOnly
		}
		var p ipc.TunnelName
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return nil, m.remove(p.Name)
	})
	c.Handle(ipc.MethodTunnelConnect, func(ctx context.Context, uid uint32, params json.RawMessage) (any, error) {
		var p ipc.TunnelName
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return m.requestConnect(ctx, uid, p.Name)
	})
	c.Handle(ipc.MethodTunnelDisconnect, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		var p ipc.TunnelName
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return m.requestDisconnect(uid, p.Name)
	})
	c.Handle(ipc.MethodTunnelStatus, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		if !m.user(uid) {
			return nil, errForbidden
		}
		var p ipc.TunnelName
		if len(params) > 0 && string(params) != "null" {
			if err := decode(params, &p); err != nil {
				return nil, err
			}
		}
		return m.statuses(p.Name)
	})
}

func (m *Manager) add(name, text string) error {
	if !validName(name) {
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.DaemonInvalidName}
	}
	cfg, err := config.Parse(name, strings.NewReader(text))
	if err != nil {
		// config errors are msg texts and never echo key values
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: err.Error()}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnels[name] != nil {
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.DaemonTunnelExists}
	}
	if err := m.store.save(name, text); err != nil {
		log.Printf("daemon: store %s: %v", name, err)
		return &ipc.Error{Code: ipc.CodeInternal, Message: fmt.Sprintf(msg.DaemonStoreFailedFmt, err)}
	}
	m.tunnels[name] = newTunnel(name, cfg, m.store.policyFor(name))
	log.Printf("daemon: tunnel %s added", name)
	return nil
}

func (m *Manager) remove(name string) error {
	m.mu.Lock()
	t := m.tunnels[name]
	delete(m.tunnels, name) // no new connect can start from here
	m.mu.Unlock()
	if t == nil {
		return errNotFound
	}
	m.teardown(t, StateDisconnected, nil)
	if err := m.store.removeEndpoints(name); err != nil {
		log.Printf("daemon: store remove %s endpoint cache: %v", name, err)
	}
	if err := m.store.removePolicy(name); err != nil {
		log.Printf("daemon: store remove %s policy: %v", name, err)
	}
	if err := m.store.remove(name); err != nil {
		log.Printf("daemon: store remove %s: %v", name, err)
		return &ipc.Error{Code: ipc.CodeInternal, Message: fmt.Sprintf(msg.DaemonStoreFailedFmt, err)}
	}
	log.Printf("daemon: tunnel %s removed", name)
	return nil
}

// disconnect takes the tunnel down if cond (checked under Manager.mu, nil:
// always) holds, else fails with forbidden.
func (m *Manager) disconnect(name string, cond func(*tunnel) bool) (ipc.TunnelStatus, error) {
	m.mu.Lock()
	t := m.tunnels[name]
	m.mu.Unlock()
	if t == nil {
		return ipc.TunnelStatus{}, errNotFound
	}
	if !m.teardown(t, StateDisconnected, cond) {
		return ipc.TunnelStatus{}, errNotYours
	}
	return m.status(t), nil
}

func (m *Manager) statuses(name string) ([]ipc.TunnelStatus, error) {
	m.mu.Lock()
	var ts []*tunnel
	for n, t := range m.tunnels {
		if name == "" || n == name {
			ts = append(ts, t)
		}
	}
	m.mu.Unlock()
	if name != "" && len(ts) == 0 {
		return nil, errNotFound
	}
	out := make([]ipc.TunnelStatus, 0, len(ts))
	for _, t := range ts {
		out = append(out, m.status(t))
	}
	slices.SortFunc(out, func(a, b ipc.TunnelStatus) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// status reads the device (IpcGet takes device locks) outside Manager.mu.
func (m *Manager) status(t *tunnel) ipc.TunnelStatus {
	m.mu.Lock()
	st := ipc.TunnelStatus{Name: t.name, State: t.state, FullTunnel: routesAll(t.cfg), KillSwitch: killSwitchStatus(t)}
	if t.hasRef {
		st.Identity = t.ref.String()
	}
	var dev *device.Device
	if t.state == StateConnected && t.dev != nil {
		dev = t.dev
		st.Interface, st.MTU = t.iface, t.applied.MTU
		var warns []string
		var w string
		if st.DNS, w = dnsStatus(t.dnsRole, len(t.cfg.DNS) > 0, t.applied.DNS); w != "" {
			warns = append(warns, w)
		}
		// P3: a Linux full tunnel (it has a table) without nft.
		if t.applied.FullTunnel && t.applied.Table != 0 && !t.applied.RPFilter {
			warns = append(warns, msg.DaemonWarnNoRPFilter)
		}
		st.Warning = strings.Join(warns, "; ")
	}
	m.mu.Unlock()
	if dev != nil {
		st.LastHandshake = lastHandshake(dev)
	}
	return st
}

// lastHandshake returns the newest peer handshake time, RFC 3339, or "".
func lastHandshake(dev *device.Device) string {
	s, err := dev.IpcGet()
	if err != nil {
		return ""
	}
	var best time.Time
	var sec int64
	for _, line := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ := strconv.ParseInt(v, 10, 64)
			if sec != 0 {
				if t := time.Unix(sec, nsec); t.After(best) {
					best = t
				}
			}
		}
	}
	if best.IsZero() {
		return ""
	}
	return best.UTC().Format(time.RFC3339)
}

// ---- agents ----

func (m *Manager) agentRegister(c *ipc.Conn, uid uint32, serials []uint32) {
	m.mu.Lock()
	a := m.agents[c]
	if a == nil {
		a = &agentState{uid: uid}
		m.agents[c] = a
	}
	if a.seq == 0 {
		m.nextSeq++
		a.seq = m.nextSeq
	}
	old := a.serials
	a.serials = map[uint32]bool{}
	for _, s := range serials {
		a.serials[s] = true
	}
	var inserted []uint32
	for s := range a.serials {
		if !old[s] {
			inserted = append(inserted, s)
		}
	}
	m.mu.Unlock()
	log.Printf("daemon: agent of uid %d registered with %d card(s)", uid, len(serials))
	// A card pulled while this user's agent was away is noticed here: the
	// new connection has no earlier list to diff against (R20).
	m.reconcile(uid)
	for _, s := range inserted {
		m.cardInserted(s, uid)
	}
}

// agentEvent handles card changes. pin_ready may arrive out of order with
// key replies and card_removed, so it is only a hint.
func (m *Manager) agentEvent(c *ipc.Conn, uid uint32, ev ipc.AgentEvent) {
	m.mu.Lock()
	a := m.agents[c]
	if a == nil || a.seq == 0 {
		m.mu.Unlock()
		return
	}
	switch ev.Type {
	case ipc.EventCardInserted:
		a.serials[ev.Serial] = true
		m.mu.Unlock()
		m.cardInserted(ev.Serial, uid)
	case ipc.EventCardRemoved:
		delete(a.serials, ev.Serial)
		m.mu.Unlock()
		m.reconcile(uid)
	case ipc.EventPINReady:
		present := a.serials[ev.Serial]
		m.mu.Unlock()
		if present {
			m.pinReady(ev.Serial, uid)
		}
	default:
		m.mu.Unlock()
	}
}

// dropAgent forgets a closed agent connection. The user's tunnels stay up
// for agentGrace, so an agent restart does not cost a reconnect; meanwhile
// their handshakes fail, since no agent serves the key. After the grace,
// every tunnel of that user whose card no registered agent of the user
// reports is torn down to card_removed: without an agent nobody watches the
// card, so the session must not outlive it (spec §5.5). A later agent that
// reports the card reconnects the tunnel.
func (m *Manager) dropAgent(c *ipc.Conn) {
	m.mu.Lock()
	a := m.agents[c]
	delete(m.agents, c)
	m.mu.Unlock()
	if a == nil || a.seq == 0 {
		return
	}
	log.Printf("daemon: agent of uid %d disconnected", a.uid)
	time.AfterFunc(m.agentGrace, func() { m.reconcile(a.uid) })
}

// uses reports whether t runs (or is getting) its key from serial of uid.
func (t *tunnel) uses(serial, uid uint32) bool {
	return t.hasRef && t.ref.Serial == serial && t.uid == uid
}

// bound reports whether t is tied to the agent user t.uid: it is up, coming
// up, or waiting for that user's card to come back.
func (t *tunnel) bound() bool {
	return t.hasRef && (t.state == StateConnecting || t.state == StateConnected || t.state == StateCardRemoved)
}

func (t *tunnel) boundTo(uid uint32) bool { return t.bound() && t.uid == uid }

// reconcile takes down every tunnel of uid whose card no registered agent of
// uid reports any more.
func (m *Manager) reconcile(uid uint32) {
	cond := func(t *tunnel) bool { // under Manager.mu
		return t.hasRef && t.uid == uid && (t.state == StateConnected || t.state == StateConnecting) &&
			m.agentForLocked(t.ref.Serial, uid) == nil
	}
	for _, t := range m.matching(cond) {
		// t.ref may change once Manager.mu is released (a reconnect):
		// the serial is read with the check.
		var serial uint32
		check := func(t *tunnel) bool {
			if !cond(t) {
				return false
			}
			serial = t.ref.Serial
			return true
		}
		if m.teardown(t, StateCardRemoved, check) {
			log.Printf("daemon: tunnel %s: YubiKey %d removed, tunnel down", t.name, serial)
		}
	}
}

// cardInserted reconnects tunnels that went down because the card was removed.
func (m *Manager) cardInserted(serial, uid uint32) {
	for _, t := range m.matching(func(t *tunnel) bool { return t.state == StateCardRemoved && t.uses(serial, uid) }) {
		go func() {
			if _, err := m.connect(context.Background(), t.name, uid, false, StateCardRemoved); err != nil {
				log.Printf("daemon: tunnel %s: reconnect: %v", t.name, err)
			}
		}()
	}
}

// pinReady redoes the static-static precomputation of connected devices
// using the card, in case it failed while the user was typing the PIN.
func (m *Manager) pinReady(serial, uid uint32) {
	m.mu.Lock()
	var devs []*device.Device
	if m.agentForLocked(serial, uid) != nil {
		for _, t := range m.tunnels {
			if t.state == StateConnected && t.dev != nil && t.uses(serial, uid) {
				devs = append(devs, t.dev)
			}
		}
	}
	m.mu.Unlock()
	for _, d := range devs {
		go func() {
			if n := d.RecomputeStaticStatic(); n > 0 {
				log.Printf("daemon: static-static recompute failed for %d peer(s)", n)
			}
		}()
	}
}

func (m *Manager) matching(cond func(*tunnel) bool) []*tunnel {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*tunnel
	for _, t := range m.tunnels {
		if cond(t) {
			out = append(out, t)
		}
	}
	return out
}

// cardRegistered reports whether any agent reports serial.
func (m *Manager) cardRegistered(serial uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.agents {
		if a.seq != 0 && a.serials[serial] {
			return true
		}
	}
	return false
}

// agentFor returns the earliest registered agent of uid reporting serial.
func (m *Manager) agentFor(serial, uid uint32) *ipc.Conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.agentForLocked(serial, uid)
}

func (m *Manager) agentForLocked(serial, uid uint32) *ipc.Conn {
	var best *ipc.Conn
	var seq uint64
	for c, a := range m.agents {
		if a.seq != 0 && a.uid == uid && a.serials[serial] && (best == nil || a.seq < seq) {
			best, seq = c, a.seq
		}
	}
	return best
}

// uidsWithSerialLocked returns the users, other than except, whose agents
// report serial, earliest registration first.
func (m *Manager) uidsWithSerialLocked(serial, except uint32) []uint32 {
	first := map[uint32]uint64{}
	for _, a := range m.agents {
		if a.seq == 0 || a.uid == except || !a.serials[serial] {
			continue
		}
		if s, ok := first[a.uid]; !ok || a.seq < s {
			first[a.uid] = a.seq
		}
	}
	uids := make([]uint32, 0, len(first))
	for u := range first {
		uids = append(uids, u)
	}
	slices.SortFunc(uids, func(x, y uint32) int { return cmp.Compare(first[x], first[y]) })
	return uids
}

// candidate is one identity of a tunnel and a user whose agent may serve it.
type candidate struct {
	id  config.Identity
	uid uint32
}

// candidatesLocked lists who may serve cfg for a connect by uid, in order of
// preference. A non-administrator gets only its own agent for the first
// identity that agent reports. An administrator gets its own agents for every
// identity first, then other users' agents (identity order, earliest
// registration first). Every candidate still has to pass prove.
func (m *Manager) candidatesLocked(cfg *config.Tunnel, uid uint32, admin bool) []candidate {
	var out []candidate
	for _, id := range cfg.Identities {
		if m.agentForLocked(id.Ref.Serial, uid) != nil {
			out = append(out, candidate{id: id, uid: uid})
			if !admin {
				return out
			}
		}
	}
	if !admin {
		return out
	}
	for _, id := range cfg.Identities {
		for _, u := range m.uidsWithSerialLocked(id.Ref.Serial, uid) {
			out = append(out, candidate{id: id, uid: u})
		}
	}
	return out
}

// ---- connect and teardown ----

// connect brings tunnel name up. caller is the requester's context: the
// attempt is abandoned when it ends. A non-empty onlyFrom makes connect a
// no-op unless the tunnel is in that state (automatic reconnect).
//
// Nothing about the tunnel changes until an agent has proved it holds the
// configured key (R21), so a failed or stalled connect by another user can
// neither bind nor block the tunnel.
func (m *Manager) connect(caller context.Context, name string, uid uint32, admin bool, onlyFrom string) (ipc.TunnelStatus, error) {
	m.mu.Lock()
	t := m.tunnels[name]
	if t == nil {
		m.mu.Unlock()
		return ipc.TunnelStatus{}, errNotFound
	}
	if onlyFrom != "" && t.state != onlyFrom {
		m.mu.Unlock()
		return m.status(t), nil
	}
	if !admin && t.bound() && t.uid != uid {
		m.mu.Unlock()
		return ipc.TunnelStatus{}, errNotYours
	}
	if t.state == StateConnecting || t.state == StateConnected {
		m.mu.Unlock()
		return m.status(t), nil
	}
	// Refused before the agent is asked (no PIN for nothing); checked
	// again when the tunnel is reserved below.
	if err := m.conflictLocked(t); err != nil {
		m.mu.Unlock()
		log.Printf("daemon: tunnel %s: connect: %v", name, err)
		return ipc.TunnelStatus{}, err
	}
	cands := m.candidatesLocked(t.cfg, uid, admin)
	cfg, gen0, abort := t.cfg, t.gen, t.abort
	m.mu.Unlock()

	if len(cands) == 0 {
		m.failUnbound(t, uid, gen0)
		return ipc.TunnelStatus{}, errNoCard
	}
	// The policy is read again, so a changed file applies at this connect.
	pol := m.store.policyFor(name)
	proving, cancelProving := context.WithCancel(m.ctx)
	defer cancelProving()
	defer context.AfterFunc(caller, cancelProving)()
	defer context.AfterFunc(abort, cancelProving)()
	c, err := m.prove(proving, name, cands)
	if err != nil {
		m.failUnbound(t, uid, gen0)
		log.Printf("daemon: tunnel %s: connect: %v", name, err)
		return ipc.TunnelStatus{}, userErr(err)
	}

	// Bind the tunnel to the proven agent's user.
	m.mu.Lock()
	switch {
	case m.tunnels[name] != t:
		m.mu.Unlock()
		return ipc.TunnelStatus{}, errAborted // removed meanwhile
	case !admin && t.bound() && t.uid != uid:
		m.mu.Unlock()
		return ipc.TunnelStatus{}, errNotYours
	case t.state == StateConnecting || t.state == StateConnected:
		m.mu.Unlock()
		return m.status(t), nil // a concurrent connect won
	case t.gen != gen0:
		m.mu.Unlock()
		return ipc.TunnelStatus{}, errAborted // disconnected or card removed meanwhile
	}
	// The check and the reservation (state connecting) are one step under
	// Manager.mu, so of two conflicting connects only one gets past it; the
	// DNS role is chosen in the same step.
	if err := m.conflictLocked(t); err != nil {
		m.mu.Unlock()
		log.Printf("daemon: tunnel %s: connect: %v", name, err)
		return ipc.TunnelStatus{}, err
	}
	t.dnsRole = m.dnsRoleLocked(t)
	demote := m.demotionLocked(t)
	prev := reservation{state: t.state, ref: t.ref, hasRef: t.hasRef, uid: t.uid, policy: t.policy}
	t.gen++
	gen := t.gen
	t.state = StateConnecting
	t.ref, t.hasRef, t.uid = c.id.Ref, true, c.uid
	t.policy, t.mark, t.endpoints = pol, 0, nil
	life, cancelLife := context.WithCancel(m.ctx)
	attempt, cancelAttempt := context.WithCancel(life)
	t.cancel = cancelLife
	m.mu.Unlock()
	defer cancelAttempt()
	defer context.AfterFunc(caller, cancelAttempt)()

	// P18: a full tunnel takes the DNS from a split tunnel that answers
	// every name, before anything of its own is built. When that fails it
	// is refused and the reservation undone.
	if demote != nil {
		if err := m.demote(attempt, demote); err != nil {
			m.mu.Lock()
			if t.gen == gen {
				t.state, t.ref, t.hasRef, t.uid, t.policy = prev.state, prev.ref, prev.hasRef, prev.uid, prev.policy
				t.cancel = nil
			}
			m.mu.Unlock()
			cancelLife()
			m.syncKillSwitch() // a no-op unless a sync saw the reservation
			log.Printf("daemon: tunnel %s: connect: %v", name, err)
			return ipc.TunnelStatus{}, userErr(err)
		}
	}

	t.op.Lock()
	defer t.op.Unlock()
	m.reap(t)

	dev, cfgr, info, err := m.build(attempt, life, cfg, c, t, gen)
	m.mu.Lock()
	if t.gen != gen {
		err = errAborted // disconnected, removed or card removed meanwhile
	}
	if err == nil {
		t.dev, t.cfgr, t.iface, t.devGen = dev, cfgr, info.iface, gen
		t.endpoints, t.listenPort, t.applied = info.endpoints, info.listenPort, info.applied
		t.state = StateConnected
		m.mu.Unlock()
		log.Printf("daemon: tunnel %s connected with %s (uid %d)", name, c.id.Ref, c.uid)
		// Its interface and endpoint pass the kill switch from here.
		m.syncKillSwitch()
		return m.status(t), nil
	}
	if t.gen == gen {
		t.state, t.cancel, t.mark, t.endpoints = StateError, nil, 0, nil
	}
	m.mu.Unlock()
	cancelLife()
	if dev != nil {
		m.closeDevice(dev, cfgr)
	}
	m.syncKillSwitch()
	log.Printf("daemon: tunnel %s: connect: %v", name, err)
	return ipc.TunnelStatus{}, userErr(err)
}

// failUnbound records a connect that failed before binding. Only the owner's
// own reconnect (a tunnel bound to uid waiting for its card) changes the
// state; anybody else's failure leaves the tunnel as it was.
func (m *Manager) failUnbound(t *tunnel, uid uint32, gen0 uint64) {
	m.mu.Lock()
	changed := t.gen == gen0 && t.state == StateCardRemoved && t.uid == uid
	if changed {
		t.state = StateError
	}
	m.mu.Unlock()
	if changed {
		m.syncKillSwitch()
	}
}

// prove tries the candidates in order and returns the first whose agent
// proves it holds the configured key.
func (m *Manager) prove(ctx context.Context, name string, cands []candidate) (candidate, error) {
	var lastErr error = errNoCard
	for _, c := range cands {
		err := m.proveOne(ctx, c)
		if err == nil {
			return c, nil
		}
		log.Printf("daemon: tunnel %s: agent of uid %d for %s: %v", name, c.uid, c.id.Ref, err)
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return candidate{}, lastErr
}

// proveOne checks that c's agent serves the configured public key and can
// use the matching private key (R21). key.public must equal the configured
// key; then the agent computes X25519 with a fresh ephemeral public key,
// which must equal X25519(ephemeral private, configured key). This call is
// also where the card asks for its PIN, so it gets the warm-up timeout.
func (m *Manager) proveOne(ctx context.Context, c candidate) error {
	ref, want := c.id.Ref, c.id.PublicKey
	conn := m.agentFor(ref.Serial, c.uid)
	if conn == nil {
		return errNoCard
	}
	pub, err := fetchPublic(ctx, conn, ref)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(pub[:], want[:]) != 1 {
		return &ipc.Error{Code: ipc.CodeForbidden, Message: fmt.Sprintf(msg.DaemonKeyMismatchFmt, ref)}
	}

	var priv [32]byte
	defer clear(priv[:])
	if _, err := rand.Read(priv[:]); err != nil {
		return err
	}
	ephPub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	expect, err := curve25519.X25519(priv[:], want[:])
	if err != nil { // low-order configured key: nothing can prove it
		return &ipc.Error{Code: ipc.CodeForbidden, Message: fmt.Sprintf(msg.DaemonProofFailedFmt, ref)}
	}
	defer clear(expect)

	key := &remoteKey{ref: ref, pub: want, uid: c.uid, find: m.agentFor, life: ctx}
	wctx, cancel := context.WithTimeout(ctx, warmUpTimeout)
	defer cancel()
	got, err := key.X25519(wctx, [32]byte(ephPub))
	defer clear(got[:])
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got[:], expect) != 1 {
		return &ipc.Error{Code: ipc.CodeForbidden, Message: fmt.Sprintf(msg.DaemonProofFailedFmt, ref)}
	}
	return nil
}

// devInfo is what build reports about the device for the kill switch and
// the status.
type devInfo struct {
	iface      string
	endpoints  []netip.AddrPort
	listenPort uint16
	applied    netcfg.Applied
}

// build makes the device for one connect attempt (generation gen of t)
// after the agent proved its key: resolve endpoints, put the kill switch in
// place, then NewDevice, SetStaticKey (once, before Up), IpcSet, addresses
// and routes, Up. life bounds the key's calls for the device's whole
// lifetime; attempt only this connect. The DNS role is read from t just
// before Apply: a full tunnel's demotion (P18) may change it while t waits
// for t.op.
//
// The kill switch follows the connecting state only once the endpoints are
// resolved, so a first connect can still look up a name; a tunnel that was
// blocking already (card_removed, error) resolves behind it, with the mark
// (Linux full tunnel) or from the endpoint cache. From then on the
// connecting tunnel's endpoints pass outbound (replies only come back), so
// the first handshake is not rejected. A tunnel whose kill switch is on is
// refused when the kill switch cannot block.
//
// A full tunnel (a default route in some peer's AllowedIPs) on Linux gets a
// routing table T first: its endpoint lookups and its WireGuard socket carry the
// mark T (fwmark=T leads the UAPI text, a device key that must precede the
// first peer), and its routes go through table T.
func (m *Manager) build(attempt, life context.Context, cfg *config.Tunnel, c candidate, t *tunnel, gen uint64) (*device.Device, netcfg.Configurer, devInfo, error) {
	id := c.id
	var routes []netip.Prefix
	for _, peer := range cfg.Peers {
		routes = append(routes, peer.AllowedIPs...)
	}
	var mark uint32
	if slices.ContainsFunc(routes, func(r netip.Prefix) bool { return r.Bits() == 0 }) {
		if !m.fullTunnel {
			return nil, nil, devInfo{}, netcfg.ErrFullTunnelUnsupported
		}
		if m.pickTable != nil {
			table, err := m.pickTable(attempt)
			if err != nil {
				return nil, nil, devInfo{}, err
			}
			mark = table
		}
	}
	m.mu.Lock()
	if t.gen == gen {
		t.mark = mark
	}
	m.mu.Unlock()
	rt, err := m.resolveTunnel(attempt, cfg, mark, m.ksBlocking.Load())
	if err != nil {
		return nil, nil, devInfo{}, err
	}
	if err := attempt.Err(); err != nil {
		return nil, nil, devInfo{}, err
	}
	// From here the endpoints pass the kill switch outbound (P17): the
	// first handshake leaves as soon as the device is up.
	m.mu.Lock()
	if t.gen == gen {
		t.endpoints = resolvedEndpoints(rt)
	}
	m.mu.Unlock()
	if err := m.armKillSwitch(t); err != nil {
		return nil, nil, devInfo{}, err
	}
	key := &remoteKey{ref: id.Ref, pub: id.PublicKey, uid: c.uid, find: m.agentFor, life: life}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = netcfg.AutoMTU(attempt, m.runner, resolvedEndpoints(rt))
	}
	tdev, cfgr, err := m.tun(cfg.Name, mtu)
	if err != nil {
		return nil, nil, devInfo{}, err
	}
	iface, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return nil, nil, devInfo{}, err
	}
	dev := device.NewDevice(tdev, m.bind(), device.NewLogger(device.LogLevelError, fmt.Sprintf("latchwire(%s): ", cfg.Name)))
	fail := func(err error) (*device.Device, netcfg.Configurer, devInfo, error) {
		m.closeDevice(dev, cfgr)
		return nil, nil, devInfo{}, err
	}
	if err := m.ops.setStaticKey(dev, wgadapter.New(key, wgadapter.DefaultLimits)); err != nil {
		return fail(err)
	}
	uapi := rt.UAPI()
	if mark != 0 {
		uapi = fmt.Sprintf("fwmark=%d\n", mark) + uapi
	}
	if err := m.ops.ipcSet(dev, uapi); err != nil {
		return fail(err)
	}
	m.mu.Lock()
	role := t.dnsRole
	m.mu.Unlock()
	plan := netcfg.Plan{Iface: iface, Addresses: id.Addresses, Routes: routes, MTU: mtu,
		MTUAuto: cfg.MTU == 0, Endpoints: resolvedEndpoints(rt), FwMark: mark,
		DNS: cfg.DNS, DNSSearch: cfg.DNSSearch, DNSRole: role}
	applied, err := cfgr.Apply(attempt, plan)
	if err != nil {
		return fail(err)
	}
	if err := m.ops.up(dev); err != nil {
		return fail(err)
	}
	// The kill switch lets the endpoints in only to the port the device
	// is bound to: the configured ListenPort, or the one the system chose.
	port := listenPort(dev)
	if port == 0 {
		return fail(errors.New("the device reports no listen port"))
	}
	return dev, cfgr, devInfo{iface: iface, endpoints: resolvedEndpoints(rt), listenPort: port, applied: applied}, nil
}

// listenPort reads the UDP port dev is bound to (0: unknown).
func listenPort(dev *device.Device) uint16 {
	s, err := dev.IpcGet()
	if err != nil {
		return 0
	}
	for line := range strings.Lines(s) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "listen_port="); ok {
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return 0
			}
			return uint16(n)
		}
	}
	return 0
}

// ---- several tunnels ----

// routesAll reports whether cfg is a full tunnel: some peer's AllowedIPs
// hold 0.0.0.0/0 or ::/0.
func routesAll(cfg *config.Tunnel) bool {
	for _, p := range cfg.Peers {
		if slices.ContainsFunc(p.AllowedIPs, func(r netip.Prefix) bool { return r.Bits() == 0 }) {
			return true
		}
	}
	return false
}

// active reports whether t holds, or is getting, what it needs from the
// system: it is connecting or connected, or its device is not closed yet
// (a teardown in progress). Manager.mu is held.
func (t *tunnel) active() bool {
	return t.state == StateConnecting || t.state == StateConnected || t.dev != nil
}

// reservation is what a connect changed when it reserved the tunnel, so
// that a refused demotion can put it back.
type reservation struct {
	state  string
	ref    keyref.Ref
	hasRef bool
	uid    uint32
	policy Policy
}

// demotionLocked returns the split tunnel whose DNS servers answer every
// name when t, a full tunnel with DNS servers, is to take them over (P18),
// or nil. Manager.mu is held.
func (m *Manager) demotionLocked(t *tunnel) *tunnel {
	if t.dnsRole != netcfg.DNSPrimary || !routesAll(t.cfg) {
		return nil
	}
	for _, o := range m.othersLocked(t) {
		if o.dnsRole == netcfg.DNSPrimary && !routesAll(o.cfg) {
			return o
		}
	}
	return nil
}

// demote limits o's DNS servers to its search domains (DNSScoped), or takes
// them out (DNSNone, status "ignored") without search domains, so that a
// full tunnel can answer every name (P18). It holds o.op, so o is not
// between building its device and recording it: o is either still waiting
// to build (its Apply then reads the new role), connected (its Configurer
// changes the role in place), or gone (nothing to do). A failure keeps o's
// role as far as it is still in effect and is returned.
func (m *Manager) demote(ctx context.Context, o *tunnel) error {
	o.op.Lock()
	defer o.op.Unlock()
	m.mu.Lock()
	if o.dnsRole != netcfg.DNSPrimary {
		m.mu.Unlock()
		return nil
	}
	role := netcfg.DNSNone
	if len(o.cfg.DNSSearch) > 0 {
		role = netcfg.DNSScoped
	}
	cfgr := o.cfgr
	switch {
	case o.dev != nil && o.devGen == o.gen && cfgr != nil:
		// Connected: changed in place below.
	case o.state == StateConnecting:
		o.dnsRole = role // its build has not read it yet
		m.mu.Unlock()
		log.Printf("daemon: tunnel %s: its DNS servers no longer answer every name: a full tunnel connects", o.name)
		return nil
	default:
		m.mu.Unlock()
		return nil // down or failed: no DNS of its own
	}
	m.mu.Unlock()
	how, err := cfgr.SetDNSRole(ctx, role)
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case o.cfgr != cfgr:
		// Torn down meanwhile: its DNS went with its Configurer.
	case err == nil:
		o.dnsRole, o.applied.DNS = role, how
	case how != o.applied.DNS:
		// The old DNS is undone, the new one not applied.
		o.dnsRole, o.applied.DNS = netcfg.DNSNone, how
	}
	if err != nil {
		return &ipc.Error{Code: ipc.CodeInternal, Message: fmt.Sprintf(msg.DaemonDemoteFailedFmt, o.name, err)}
	}
	log.Printf("daemon: tunnel %s: its DNS servers no longer answer every name (%s): a full tunnel connects", o.name, how)
	return nil
}

// othersLocked returns the active tunnels other than t, in name order.
// Manager.mu is held.
func (m *Manager) othersLocked(t *tunnel) []*tunnel {
	var out []*tunnel
	for _, o := range m.tunnels {
		if o != t && o.active() {
			out = append(out, o)
		}
	}
	slices.SortFunc(out, func(a, b *tunnel) int { return cmp.Compare(a.name, b.name) })
	return out
}

// conflictLocked returns why t may not connect next to the tunnels that
// are connecting or connected (nil: it may): a second full tunnel; an
// AllowedIPs prefix that overlaps one of another tunnel's (the default
// routes left out: a split tunnel's more specific routes beside a full
// tunnel are meant to win); the ListenPort another tunnel has configured
// or is bound to. Manager.mu is held.
func (m *Manager) conflictLocked(t *tunnel) error {
	refuse := func(format string, args ...any) error {
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: fmt.Sprintf(format, args...)}
	}
	others := m.othersLocked(t)
	if routesAll(t.cfg) {
		for _, o := range others {
			if routesAll(o.cfg) {
				return refuse(msg.DaemonConflictFullFmt, o.name)
			}
		}
	}
	for _, p := range t.cfg.Peers {
		for _, a := range p.AllowedIPs {
			if a.Bits() == 0 {
				continue
			}
			for _, o := range others {
				for _, op := range o.cfg.Peers {
					for _, b := range op.AllowedIPs {
						if b.Bits() != 0 && a.Overlaps(b) {
							return refuse(msg.DaemonConflictAllowedIPsFmt, a, b, o.name)
						}
					}
				}
			}
		}
	}
	if port := t.cfg.ListenPort; port != 0 {
		for _, o := range others {
			if o.cfg.ListenPort == port || int(o.listenPort) == port {
				return refuse(msg.DaemonConflictListenPortFmt, port, o.name)
			}
		}
	}
	return nil
}

// dnsRoleLocked chooses the part t's DNS servers take as it starts
// connecting. A full tunnel's answer every name (DNSPrimary); so do a split
// tunnel's when no other active tunnel's do. Otherwise they answer t's
// search domains only (DNSScoped), or, without search domains, are not
// applied (DNSNone; status "ignored").
//
// The owner leaving promotes nobody: the tunnels already up keep what they
// have until they reconnect, and the next tunnel to connect may take it.
// A full tunnel takes DNSPrimary from a split tunnel that holds it: the
// connect demotes that one first (demotionLocked, demote; P18). Manager.mu
// is held.
func (m *Manager) dnsRoleLocked(t *tunnel) netcfg.DNSRole {
	switch {
	case len(t.cfg.DNS) == 0:
		return netcfg.DNSNone
	case routesAll(t.cfg):
		return netcfg.DNSPrimary
	}
	for _, o := range m.othersLocked(t) {
		if o.dnsRole == netcfg.DNSPrimary {
			if len(t.cfg.DNSSearch) > 0 {
				return netcfg.DNSScoped
			}
			return netcfg.DNSNone
		}
	}
	return netcfg.DNSPrimary
}

// dnsStatus maps the DNS role a tunnel was given, whether it has DNS
// servers, and the netcfg outcome of its Apply to TunnelStatus.DNS and a
// warning ("": none):
//
//	role     servers  outcome                    DNS         warning
//	any      no       any                        none
//	none     yes      any                        ignored     DaemonWarnDNSIgnored
//	any      yes      "" (not applied)           ignored     DaemonWarnDNSNotApplied
//	primary  yes      primary-busy               busy        DaemonWarnDNSBusy
//	primary  yes      resolvconf-shared          shared      DaemonWarnDNSShared
//	primary  yes      scutil-primary-overridden  overridden  DaemonWarnDNSOverridden
//	primary  yes      any other                  primary
//	scoped   yes      scoped-unsupported         ignored     DaemonWarnDNSScopedUnsupported
//	scoped   yes      any other                  scoped
func dnsStatus(role netcfg.DNSRole, servers bool, outcome string) (string, string) {
	switch {
	case !servers:
		return ipc.DNSStatusNone, ""
	case role == netcfg.DNSNone:
		return ipc.DNSStatusIgnored, msg.DaemonWarnDNSIgnored
	case outcome == "":
		return ipc.DNSStatusIgnored, msg.DaemonWarnDNSNotApplied
	case role == netcfg.DNSPrimary:
		switch outcome {
		case netcfg.DNSOutcomePrimaryBusy:
			return ipc.DNSStatusBusy, msg.DaemonWarnDNSBusy
		case netcfg.DNSOutcomeResolvconfShared:
			return ipc.DNSStatusShared, msg.DaemonWarnDNSShared
		case netcfg.DNSOutcomeScutilPrimaryOverridden:
			return ipc.DNSStatusOverridden, msg.DaemonWarnDNSOverridden
		}
		return ipc.DNSStatusPrimary, ""
	case outcome == netcfg.DNSOutcomeScopedUnsupported:
		return ipc.DNSStatusIgnored, msg.DaemonWarnDNSScopedUnsupported
	}
	return ipc.DNSStatusScoped, ""
}

// killSwitchStatus is TunnelStatus.KillSwitch for t: off when t's kill
// switch is not on or t is disconnected, armed while t is connected, and
// blocking while it is connecting, waiting for its card or failed (the kill
// switch is fail-closed, see killSwitchState). Manager.mu is held.
func killSwitchStatus(t *tunnel) string {
	if !t.policy.armed(t.cfg) {
		return ipc.KillSwitchStatusOff
	}
	switch t.state {
	case StateConnected:
		return ipc.KillSwitchStatusArmed
	case StateConnecting, StateCardRemoved, StateError:
		return ipc.KillSwitchStatusBlocking
	}
	return ipc.KillSwitchStatusOff
}

// resolvedEndpoints returns the endpoints of a tunnel from resolveTunnel.
func resolvedEndpoints(rt *config.Tunnel) []netip.AddrPort {
	var eps []netip.AddrPort
	for _, p := range rt.Peers {
		if ap, err := netip.ParseAddrPort(p.Endpoint); err == nil {
			eps = append(eps, ap)
		}
	}
	return eps
}

// resolveTunnel returns a copy of cfg whose endpoints are literal IP:port.
// Names are resolved at every connect, with mark (see Manager.resolve); IPv4
// is preferred. The addresses found are written to the tunnel's endpoint
// cache; when a lookup fails for a transient reason (and ctx has not
// ended), the cached address of that peer is used if its configured
// endpoint is unchanged. A name that does not exist (NXDOMAIN) never falls
// back to the cache, unless blocked: behind the kill switch the resolver
// reaches no DNS server, and the system resolver may then report any
// error (macOS: "no such host"), so any failure uses the cache (P17).
func (m *Manager) resolveTunnel(ctx context.Context, cfg *config.Tunnel, mark uint32, blocked bool) (*config.Tunnel, error) {
	rt := *cfg
	rt.Peers = slices.Clone(cfg.Peers)
	var (
		found  = map[string]cachedEndpoint{} // what this connect resolved
		cache  map[string]cachedEndpoint     // read on the first failure
		loaded bool
	)
	for i := range rt.Peers {
		ep := rt.Peers[i].Endpoint
		if ep == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(ep)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(host)
		if err == nil {
			rt.Peers[i].Endpoint = netip.AddrPortFrom(addr.Unmap(), uint16(port)).String()
			continue
		}
		key := hex.EncodeToString(rt.Peers[i].PublicKey[:])
		rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		addrs, lerr := m.resolve(rctx, host, mark)
		cancel()
		if lerr != nil || len(addrs) == 0 {
			cacheOK := transientLookupErr(lerr) || blocked
			if !loaded && ctx.Err() == nil && cacheOK {
				loaded = true
				if cache, err = m.store.loadEndpoints(cfg.Name); err != nil {
					log.Printf("daemon: %s: ignoring the endpoint cache: %v", cfg.Name, err)
				}
			}
			c, ok := cache[key]
			ap, perr := netip.ParseAddrPort(c.Addr)
			if ctx.Err() != nil || !cacheOK || !ok || c.Endpoint != ep || perr != nil || ap.Port() != uint16(port) {
				return nil, &ipc.Error{Code: ipc.CodeUnavailable, Message: fmt.Sprintf(msg.DaemonResolveFmt, host)}
			}
			log.Printf("daemon: %s: cannot resolve %s (%v, kill switch blocking: %v); using the address %s cached %v ago", cfg.Name, host, lerr, blocked, ap, time.Since(c.Resolved).Round(time.Second))
			found[key] = c
			rt.Peers[i].Endpoint = ap.String()
			continue
		}
		addr = addrs[0]
		for _, a := range addrs {
			if a.Unmap().Is4() {
				addr = a
				break
			}
		}
		ap := netip.AddrPortFrom(addr.Unmap(), uint16(port))
		rt.Peers[i].Endpoint = ap.String()
		found[key] = cachedEndpoint{Endpoint: ep, Addr: ap.String(), Resolved: time.Now().UTC().Round(0)}
	}
	// An attempt that ended (a teardown, a remove) writes nothing: remove
	// deletes the cache once the attempt has let go of the tunnel.
	if len(found) > 0 && ctx.Err() == nil {
		if err := m.store.saveEndpoints(cfg.Name, found); err != nil {
			log.Printf("daemon: %s: writing the endpoint cache: %v", cfg.Name, err)
		}
	}
	return &rt, nil
}

// transientLookupErr reports whether a failed endpoint lookup may succeed
// later, so that the cached address may stand in: a timeout, a temporary
// failure (SERVFAIL, a socket error such as no route or a kill switch's
// reject) or an error from outside the resolver. A name that does not exist
// (IsNotFound), any other DNS answer, or an empty answer is not.
func transientLookupErr(err error) bool {
	if err == nil {
		return false // no error, no addresses
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return !de.IsNotFound && (de.IsTemporary || de.IsTimeout)
	}
	return true
}

// teardown moves t to state and closes its device. cond, if set, is checked
// under Manager.mu; teardown does nothing and returns false if it fails.
func (m *Manager) teardown(t *tunnel, state string, cond func(*tunnel) bool) bool {
	m.mu.Lock()
	if cond != nil && !cond(t) {
		m.mu.Unlock()
		return false
	}
	t.gen++
	t.state = state
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.abortCancel()
	t.abort, t.abortCancel = context.WithCancel(context.Background())
	m.mu.Unlock()
	t.op.Lock()
	m.reap(t)
	t.op.Unlock()
	m.syncKillSwitch()
	return true
}

// reap closes t's device if it belongs to an older attempt. t.op is held.
func (m *Manager) reap(t *tunnel) {
	m.mu.Lock()
	if t.dev == nil || t.devGen == t.gen {
		m.mu.Unlock()
		return
	}
	dev, cfgr := t.dev, t.cfgr
	t.dev, t.cfgr, t.iface, t.applied = nil, nil, "", netcfg.Applied{}
	t.endpoints, t.listenPort, t.mark = nil, 0, 0
	m.mu.Unlock()
	m.closeDevice(dev, cfgr)
}

// closeDevice stops the tunnel first, so no packet uses it once this starts
// (R20), then removes addresses and routes. Removal is best effort: closing
// the TUN usually takes them with the interface, so its errors are expected
// and only logged in debug mode.
func (m *Manager) closeDevice(dev *device.Device, cfgr netcfg.Configurer) {
	m.ops.close(dev)
	if err := cfgr.Remove(context.Background()); err != nil {
		debugf("daemon: removing routes after close: %v", err)
	}
}

// debug enables debug logging; set LATCHWIRE_DEBUG=1.
var debug = os.Getenv("LATCHWIRE_DEBUG") != ""

func debugf(format string, args ...any) {
	if debug {
		log.Printf(format, args...)
	}
}

// userErr turns a connect failure into the error the requester sees.
func userErr(err error) error {
	var ie *ipc.Error
	switch {
	case errors.As(err, &ie):
		return ie
	case errors.Is(err, netcfg.ErrFullTunnelUnsupported), errors.Is(err, netcfg.ErrDNSUnsupported):
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: err.Error()}
	case errors.Is(err, context.Canceled):
		return errAborted
	case errors.Is(err, context.DeadlineExceeded):
		return &ipc.Error{Code: ipc.CodeUnavailable, Message: msg.AgentRequestExpired}
	case errors.Is(err, keyprovider.ErrUnavailable):
		return &ipc.Error{Code: ipc.CodeUnavailable, Message: err.Error()}
	}
	return &ipc.Error{Code: ipc.CodeInternal, Message: fmt.Sprintf(msg.DaemonConnectFailedFmt, err)}
}

// ---- kill switch ----

// killSwitchState is the kill switch the tunnels' states call for. It
// blocks while any tunnel whose kill switch is on (Policy.armed) is
// connecting, connected, waiting for its card (card_removed) or failed
// (error): it is fail-closed, and only down, remove and a graceful shutdown
// (all to disconnected) end it. While blocking, every connected tunnel's
// interface, resolved endpoints and listen port pass; a connecting tunnel's
// resolved endpoints pass outbound only (P17); and so do the packets with a
// full tunnel's mark (Linux), connected or connecting.
func (m *Manager) killSwitchState() killswitch.State {
	s, _ := m.killSwitchStateAndOwners()
	return s
}

// ksTunnel is one tunnel the kill switch blocks for, as recorded in the
// store so that a restarted daemon restores it (P17): its name and, when
// bound, the key and the user whose agent serves it.
type ksTunnel struct {
	Name string `json:"name"`
	Ref  string `json:"ref,omitempty"`
	UID  uint32 `json:"uid"`
}

// killSwitchStateAndOwners returns killSwitchState and the armed tunnels
// that make it block, in name order.
func (m *Manager) killSwitchStateAndOwners() (killswitch.State, []ksTunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.tunnels))
	for n := range m.tunnels {
		names = append(names, n)
	}
	slices.Sort(names)
	var (
		s      killswitch.State
		owners []ksTunnel
	)
	for _, n := range names {
		t := m.tunnels[n]
		switch t.state {
		case StateConnecting, StateConnected, StateCardRemoved, StateError:
			if t.policy.armed(t.cfg) {
				s.Block = true
				o := ksTunnel{Name: n}
				if t.hasRef {
					o.Ref, o.UID = t.ref.String(), t.uid
				}
				owners = append(owners, o)
			}
		}
	}
	if !s.Block {
		return killswitch.State{}, nil
	}
	for _, n := range names {
		t := m.tunnels[n]
		switch t.state {
		case StateConnected:
			if t.iface != "" {
				s.Tunnels = append(s.Tunnels, killswitch.TunnelRule{Iface: t.iface, Endpoints: slices.Clone(t.endpoints), ListenPort: t.listenPort})
			}
			if t.mark != 0 {
				s.FwMark = t.mark
			}
		case StateConnecting:
			if len(t.endpoints) > 0 {
				s.Tunnels = append(s.Tunnels, killswitch.TunnelRule{Endpoints: slices.Clone(t.endpoints)})
			}
			if t.mark != 0 && s.FwMark == 0 {
				s.FwMark = t.mark
			}
		}
	}
	return s, owners
}

// statesEqual reports whether two kill switch states are the same.
func statesEqual(a, b killswitch.State) bool {
	return a.Block == b.Block && a.FwMark == b.FwMark && slices.EqualFunc(a.Tunnels, b.Tunnels, func(x, y killswitch.TunnelRule) bool {
		return x.Iface == y.Iface && x.ListenPort == y.ListenPort && slices.Equal(x.Endpoints, y.Endpoints)
	})
}

// syncKillSwitch puts killSwitchState in place unless it is in place
// already. It runs outside Manager.mu (Set runs commands) and logs and
// returns Set's error; the next sync tries again.
func (m *Manager) syncKillSwitch() error {
	return m.setKillSwitch(false)
}

// setKillSwitch is syncKillSwitch; force sets the state even when it is
// believed in place. Before a blocking Set, the tunnels it blocks for are
// recorded in the store (saveKillSwitchTunnels); the record goes once a
// release succeeded.
func (m *Manager) setKillSwitch(force bool) error {
	m.ksMu.Lock()
	defer m.ksMu.Unlock()
	return m.setKillSwitchLocked(force)
}

func (m *Manager) setKillSwitchLocked(force bool) error {
	s, owners := m.killSwitchStateAndOwners()
	if s.Block && !slices.Equal(owners, m.ksSaved) {
		if err := m.store.saveKillSwitchTunnels(owners); err != nil {
			log.Printf("daemon: kill switch: recording its tunnels: %v", err)
		} else {
			m.ksSaved = owners
		}
	}
	if !force && m.ksLast != nil && statesEqual(*m.ksLast, s) {
		return nil
	}
	fw, err := m.firewallLocked()
	if err != nil {
		if !s.Block && errors.Is(err, killswitch.ErrUnsupported) {
			// No firewall here: nothing can be blocking.
			m.ksLast = &s
			m.released()
			return nil
		}
		m.ksLast = nil
		log.Printf("daemon: kill switch: %v", err)
		return err
	}
	if s.Block {
		m.ksBlocking.Store(true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), killSwitchTimeout)
	defer cancel()
	if err := fw.Set(ctx, s); err != nil {
		m.ksLast = nil
		log.Printf("daemon: kill switch (block %v): %v", s.Block, err)
		return err
	}
	m.ksLast = &s
	if !s.Block {
		m.released()
	}
	return nil
}

// released notes that no kill switch is in place; m.ksMu is held.
func (m *Manager) released() {
	m.ksBlocking.Store(false)
	if err := m.store.removeKillSwitchTunnels(); err != nil {
		log.Printf("daemon: kill switch: removing the record of its tunnels: %v", err)
		return
	}
	m.ksSaved = nil
}

// verifyKillSwitch runs at the verification tick (P17). While the kill
// switch should block, it asks the firewall whether the blocking is still
// in effect (pf enabled with the anchor's rules, the nft table there) and
// sets it again when not. A state whose Set failed is retried.
func (m *Manager) verifyKillSwitch(ctx context.Context) {
	m.ksMu.Lock()
	defer m.ksMu.Unlock()
	if m.ksLast == nil {
		if m.fwErr == nil {
			m.setKillSwitchLocked(true)
		}
		return
	}
	if !m.ksLast.Block || m.fw == nil {
		return
	}
	v, ok := m.fw.(killswitch.Verifier)
	if !ok {
		return
	}
	vctx, cancel := context.WithTimeout(ctx, killSwitchTimeout)
	defer cancel()
	in, err := v.Verify(vctx)
	if in || ctx.Err() != nil {
		return
	}
	if err != nil {
		log.Printf("daemon: kill switch: checking it: %v; setting it again", err)
	} else {
		log.Printf("daemon: WARNING: the kill switch was no longer in effect (pf disabled or its rules removed); setting it again")
	}
	m.setKillSwitchLocked(true)
}

// firewallLocked returns the kill switch's firewall, made on first use.
// That the platform has none (ErrUnsupported) is remembered; other errors
// are retried at the next use. m.ksMu is held.
func (m *Manager) firewallLocked() (killswitch.Firewall, error) {
	if m.fw != nil || m.fwErr != nil {
		return m.fw, m.fwErr
	}
	fw, err := killswitch.New(m.runner, m.journal)
	if errors.Is(err, killswitch.ErrUnsupported) {
		m.fwErr = err
	}
	if err != nil {
		return nil, err
	}
	m.fw = fw
	return fw, nil
}

// armKillSwitch puts the kill switch in place for t, which is connecting.
// When t's kill switch is on and that fails, the connect is refused (P3: no
// tunnel runs without the kill switch it asks for).
func (m *Manager) armKillSwitch(t *tunnel) error {
	err := m.syncKillSwitch()
	m.mu.Lock()
	armed := t.policy.armed(t.cfg)
	m.mu.Unlock()
	if err == nil || !armed {
		return nil
	}
	code := ipc.CodeInternal
	if errors.Is(err, killswitch.ErrUnsupported) {
		code = ipc.CodeBadRequest
	}
	return &ipc.Error{Code: code, Message: fmt.Sprintf(msg.DaemonKillSwitchRefusedFmt, err)}
}

// startKillSwitch settles the kill switch at startup, after the cleanup
// and the load.
//
// held says that the journal holds an active kill switch (a crash, or a
// stop that could not remove it). The tunnels it blocked for, as recorded
// in the store, are restored to card_removed with their key and user, so
// the card's return reconnects them and their user can take them down;
// the other tunnels load disconnected. It keeps blocking while a restored
// tunnel's kill switch is still on; otherwise it is removed. A record that
// cannot be read restores nothing (logged).
//
// recovered says that the journal was unreadable (P6): what it held is
// unknown, so the kill switch's well-known objects (the pf anchor, the nft
// table) are removed: on a corrupt journal the kill switch fails open,
// which is logged.
func (m *Manager) startKillSwitch(held, recovered bool) {
	switch {
	case recovered:
		log.Printf("daemon: WARNING: the journal was unreadable; removing any kill switch a previous run left in place: traffic is NOT blocked until a tunnel with the kill switch connects")
		m.ksMu.Lock()
		m.ksLast = nil
		m.ksMu.Unlock()
		if err := m.setKillSwitch(true); err != nil {
			log.Printf("daemon: removing the kill switch after an unreadable journal: %v", err)
		}
	case held:
		recs, err := m.store.loadKillSwitchTunnels()
		if err != nil {
			log.Printf("daemon: WARNING: the record of the kill switch's tunnels is unusable (%v): the kill switch of the previous run is removed", err)
		}
		restored := m.restoreKillSwitchTunnels(recs)
		if len(restored) > 0 {
			log.Printf("daemon: the kill switch of the previous run is still on: blocking for %v until they are taken down or reconnected", restored)
		} else {
			log.Printf("daemon: removing the kill switch of the previous run: none of its tunnels has its kill switch on now")
		}
		m.ksMu.Lock()
		m.ksLast = nil
		m.ksMu.Unlock()
		if err := m.syncKillSwitch(); err != nil {
			log.Printf("daemon: restoring the kill switch: %v", err)
		}
	default:
		// A record left behind by a run whose kill switch is gone
		// (a reboot clears the journal).
		if err := m.store.removeKillSwitchTunnels(); err != nil {
			log.Printf("daemon: kill switch: removing a stale record of its tunnels: %v", err)
		}
	}
}

// restoreKillSwitchTunnels puts the recorded tunnels that still exist and
// still have their kill switch on into card_removed, bound to the recorded
// key (one of the tunnel's identities) and user, and returns their names.
func (m *Manager) restoreKillSwitchTunnels(recs []ksTunnel) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for _, r := range recs {
		t := m.tunnels[r.Name]
		if t == nil || !t.policy.armed(t.cfg) {
			continue
		}
		t.state = StateCardRemoved
		if ref, err := keyref.Parse(r.Ref); err == nil && slices.ContainsFunc(t.cfg.Identities, func(id config.Identity) bool { return id.Ref == ref }) {
			t.ref, t.hasRef, t.uid = ref, true, r.UID
		} else if r.Ref != "" {
			log.Printf("daemon: tunnel %s: the recorded key %q is not one of its identities; it waits unbound", r.Name, r.Ref)
		}
		names = append(names, r.Name)
	}
	return names
}
