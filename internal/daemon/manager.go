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
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
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
	defaultMTU     = 1420
	resolveTimeout = 10 * time.Second

	// agentGrace is how long a user's tunnels stay up after that user's
	// agent connection closes. An agent restarted within it keeps them; after
	// it, every tunnel of that user whose card no agent reports is torn down
	// to card_removed (spec §5.5).
	agentGrace = 10 * time.Second
)

// TUNFactory creates the TUN device for a tunnel and the Configurer for its
// addresses and routes.
type TUNFactory func(name string, mtu int) (tun.Device, netcfg.Configurer, error)

// Options configures a Manager. Zero fields get production defaults.
type Options struct {
	Socket   string     // DefaultSocket
	StoreDir string     // DefaultStoreDir()
	TUN      TUNFactory // DefaultTUN
	Bind     func() conn.Bind
	IsAdmin  func(uid uint32) (bool, error) // nil = ipc.IsAdmin
}

// DefaultTUN creates a kernel TUN device (utunN on macOS, the tunnel's name
// on Linux) configured with the platform's network commands.
func DefaultTUN(name string, mtu int) (tun.Device, netcfg.Configurer, error) {
	ifname := name
	if runtime.GOOS == "darwin" {
		ifname = "utun"
	}
	d, err := tun.CreateTUN(ifname, mtu)
	if err != nil {
		return nil, nil, err
	}
	return d, netcfg.New(netcfg.Exec), nil
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
	tun     TUNFactory
	bind    func() conn.Bind
	isAdmin func(uint32) (bool, error)
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	ops     devOps
	// agentGrace is the agentGrace constant; tests shorten it.
	agentGrace time.Duration

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
	devGen uint64
	// abort is cancelled by every teardown: a connect still proving an
	// agent (and maybe waiting for a PIN) then gives up.
	abort       context.Context
	abortCancel context.CancelFunc
}

func newTunnel(name string, cfg *config.Tunnel) *tunnel {
	t := &tunnel{name: name, cfg: cfg, state: StateDisconnected}
	t.abort, t.abortCancel = context.WithCancel(context.Background())
	return t
}

// NewManager returns a manager; it does nothing until Serve.
func NewManager(o Options) *Manager {
	m := &Manager{
		socket:     o.Socket,
		store:      &store{dir: o.StoreDir},
		tun:        o.TUN,
		bind:       o.Bind,
		isAdmin:    o.IsAdmin,
		ops:        defaultOps,
		agentGrace: agentGrace,
		ctx:        context.Background(),
		tunnels:    map[string]*tunnel{},
		agents:     map[*ipc.Conn]*agentState{},
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
	if m.socket == "" {
		m.socket = DefaultSocket
	}
	if m.store.dir == "" {
		m.store.dir = DefaultStoreDir()
	}
	if m.tun == nil {
		m.tun = DefaultTUN
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
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, cfg := range ts {
		m.tunnels[name] = newTunnel(name, cfg)
	}
	return nil
}

// Serve loads the stored tunnels, listens on the socket and serves until
// ctx ends. All tunnels are taken down before it returns ctx.Err().
func (m *Manager) Serve(ctx context.Context) error {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	if err := m.load(); err != nil {
		return err
	}
	l, err := ipc.Listen(m.socket)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()

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
	m.shutdown()
	if acceptErr != nil {
		return acceptErr
	}
	return ctx.Err()
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
	m.tunnels[name] = newTunnel(name, cfg)
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
	st := ipc.TunnelStatus{Name: t.name, State: t.state}
	if t.hasRef {
		st.Identity = t.ref.String()
	}
	var dev *device.Device
	if t.state == StateConnected {
		dev = t.dev
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
		if m.teardown(t, StateCardRemoved, cond) {
			log.Printf("daemon: tunnel %s: YubiKey %d removed, tunnel down", t.name, t.ref.Serial)
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
	cands := m.candidatesLocked(t.cfg, uid, admin)
	cfg, gen0, abort := t.cfg, t.gen, t.abort
	m.mu.Unlock()

	if len(cands) == 0 {
		m.failUnbound(t, uid, gen0)
		return ipc.TunnelStatus{}, errNoCard
	}
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
	t.gen++
	gen := t.gen
	t.state = StateConnecting
	t.ref, t.hasRef, t.uid = c.id.Ref, true, c.uid
	life, cancelLife := context.WithCancel(m.ctx)
	attempt, cancelAttempt := context.WithCancel(life)
	t.cancel = cancelLife
	m.mu.Unlock()
	defer cancelAttempt()
	defer context.AfterFunc(caller, cancelAttempt)()

	t.op.Lock()
	defer t.op.Unlock()
	m.reap(t)

	dev, cfgr, err := m.build(attempt, life, cfg, c)
	m.mu.Lock()
	if t.gen != gen {
		err = errAborted // disconnected, removed or card removed meanwhile
	}
	if err == nil {
		t.dev, t.cfgr, t.devGen = dev, cfgr, gen
		t.state = StateConnected
		m.mu.Unlock()
		log.Printf("daemon: tunnel %s connected with %s (uid %d)", name, c.id.Ref, c.uid)
		return m.status(t), nil
	}
	if t.gen == gen {
		t.state, t.cancel = StateError, nil
	}
	m.mu.Unlock()
	cancelLife()
	if dev != nil {
		m.closeDevice(dev, cfgr)
	}
	log.Printf("daemon: tunnel %s: connect: %v", name, err)
	return ipc.TunnelStatus{}, userErr(err)
}

// failUnbound records a connect that failed before binding. Only the owner's
// own reconnect (a tunnel bound to uid waiting for its card) changes the
// state; anybody else's failure leaves the tunnel as it was.
func (m *Manager) failUnbound(t *tunnel, uid uint32, gen0 uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.gen == gen0 && t.state == StateCardRemoved && t.uid == uid {
		t.state = StateError
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

// build makes the device for one connect attempt after the agent proved its
// key: resolve endpoints, then NewDevice, SetStaticKey (once, before Up),
// IpcSet, addresses and routes, Up. life bounds the key's calls for the
// device's whole lifetime; attempt only this connect.
func (m *Manager) build(attempt, life context.Context, cfg *config.Tunnel, c candidate) (*device.Device, netcfg.Configurer, error) {
	id := c.id
	var routes []netip.Prefix
	for _, peer := range cfg.Peers {
		routes = append(routes, peer.AllowedIPs...)
	}
	for _, r := range routes {
		if r.Bits() == 0 {
			return nil, nil, netcfg.ErrFullTunnelUnsupported
		}
	}
	rt, err := m.resolveTunnel(attempt, cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := attempt.Err(); err != nil {
		return nil, nil, err
	}
	key := &remoteKey{ref: id.Ref, pub: id.PublicKey, uid: c.uid, find: m.agentFor, life: life}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	tdev, cfgr, err := m.tun(cfg.Name, mtu)
	if err != nil {
		return nil, nil, err
	}
	iface, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return nil, nil, err
	}
	dev := device.NewDevice(tdev, m.bind(), device.NewLogger(device.LogLevelError, fmt.Sprintf("latchwire(%s): ", cfg.Name)))
	fail := func(err error) (*device.Device, netcfg.Configurer, error) {
		m.closeDevice(dev, cfgr)
		return nil, nil, err
	}
	if err := m.ops.setStaticKey(dev, wgadapter.New(key, wgadapter.DefaultLimits)); err != nil {
		return fail(err)
	}
	if err := m.ops.ipcSet(dev, rt.UAPI()); err != nil {
		return fail(err)
	}
	if err := cfgr.Apply(iface, id.Addresses, routes); err != nil {
		return fail(err)
	}
	if err := m.ops.up(dev); err != nil {
		return fail(err)
	}
	return dev, cfgr, nil
}

// resolveTunnel returns a copy of cfg whose endpoints are literal IP:port.
// Names are resolved at every connect; IPv4 is preferred.
func (m *Manager) resolveTunnel(ctx context.Context, cfg *config.Tunnel) (*config.Tunnel, error) {
	rt := *cfg
	rt.Peers = slices.Clone(cfg.Peers)
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
		if err != nil {
			rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
			addrs, lerr := m.resolve(rctx, host)
			cancel()
			if lerr != nil || len(addrs) == 0 {
				return nil, &ipc.Error{Code: ipc.CodeUnavailable, Message: fmt.Sprintf(msg.DaemonResolveFmt, host)}
			}
			addr = addrs[0]
			for _, a := range addrs {
				if a.Unmap().Is4() {
					addr = a
					break
				}
			}
		}
		rt.Peers[i].Endpoint = netip.AddrPortFrom(addr.Unmap(), uint16(port)).String()
	}
	return &rt, nil
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
	t.dev, t.cfgr = nil, nil
	m.mu.Unlock()
	m.closeDevice(dev, cfgr)
}

// closeDevice stops the tunnel first, so no packet uses it once this starts
// (R20), then removes addresses and routes. Removal is best effort: closing
// the TUN usually takes them with the interface, so its errors are expected
// and only logged in debug mode.
func (m *Manager) closeDevice(dev *device.Device, cfgr netcfg.Configurer) {
	m.ops.close(dev)
	if err := cfgr.Remove(); err != nil {
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
	case errors.Is(err, netcfg.ErrFullTunnelUnsupported):
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
