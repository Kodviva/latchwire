package daemon

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netmon"
)

// On-demand: a tunnel whose policy has OnDemand on is connected while the
// machine is on a network that is not one of its TrustedNetworks, and
// taken down again when the machine is on a trusted one.
//
// The network is identified by netmon.NetworkID (the default gateway's IP
// and MAC address on the physical network; neither the Linux full tunnel,
// which routes through its own table, nor the macOS one, whose 0/1 and
// 128/1 routes leave the default route alone, changes what it reads). It
// is evaluated by one goroutine (onDemandLoop) after every debounced
// network change, every verification tick, every agent registration and
// every card reported anew; requests made while an evaluation runs
// coalesce into one more. An evaluation:
//
//   - does nothing on "none" (no network): there is nothing to protect and
//     nothing to connect through; a tunnel that is up stays up;
//   - looks an "unknown" network (gateway MAC not known yet) up once more
//     after odRecheck (P9) and, still unknown, treats it as untrusted (P10);
//   - on a trusted network, takes down to disconnected the tunnels that an
//     on-demand connect brought up (or is bringing up), exactly as down
//     does: their kill switch stops blocking. Not so a tunnel whose kill
//     switch an administrator set to "on" (P22): the network ID is not
//     authenticated (anyone on the local segment can copy the gateway's IP
//     and MAC address), and such a spoofable signal must not lift a kill
//     switch chosen explicitly; on-demand only does not connect it there.
//     A tunnel connected by hand or by AutoConnect is never taken down,
//     and neither is one waiting for
//     its card (card_removed) or failed (error): as everywhere, only down,
//     remove or a shutdown lifts that kill switch (fail-closed). Should its
//     card bring it back on the trusted network, the next evaluation (at
//     the latest the next verification tick) takes it down;
//   - on any other network, connects each disconnected on-demand tunnel
//     whose card the agent of an allowed user (or an administrator)
//     reports, as that user, through connect (the one gate, P20).
//
// It is idempotent: what it does (a connect's routes, a teardown) causes
// network notifications, and the next evaluation then finds nothing to do.
// An attempt is made once per "epoch": a failed attempt (a cancelled PIN)
// is retried only when the machine is on another identified network (a
// network ID other than the last identified one; "unknown" and "none" in
// between do not count) or an agent registers or reports a card anew
// (Manager.odEpoch), not at every notification or tick. An AutoConnect
// attempt counts as the epoch's attempt too: one PIN prompt per report.
//
// A down by hand (tunnel.disconnect) suppresses on-demand for that tunnel
// until the machine is on another identified network (tunnel.odSuppress);
// "unknown" and "none" in between do not count as another network, so a
// sleep or a brief loss of the gateway does not undo the down. When the
// network cannot be identified at the down (and no evaluation identified
// one before), the next identified network is taken as the down's, so
// only a change between two identified networks lifts it. A down also
// abandons an on-demand or AutoConnect attempt still waiting for its PIN
// (requestDisconnect lets the tunnel's allowed users do that). This is
// independent of AutoConnect's suppression (agentState.noAuto), which lasts
// for the agent sessions registered at the down: each feature stays quiet
// by its own rule, and a down sets both.

// onDemandRecheck is how long an unidentified network is given before it
// is looked up again (P9): the gateway's MAC address is usually in the
// neighbour cache within a moment of joining a network.
const onDemandRecheck = 2 * time.Second

// onDemandLookupTimeout bounds one network lookup outside the loop (down).
const onDemandLookupTimeout = 10 * time.Second

// kickOnDemand asks onDemandLoop for an evaluation. It never blocks;
// requests made before the loop takes one coalesce.
func (m *Manager) kickOnDemand() {
	select {
	case m.odKick <- struct{}{}:
	default:
	}
}

// onDemandLoop evaluates on-demand when kicked, one evaluation at a time,
// until ctx ends.
func (m *Manager) onDemandLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.odKick:
			m.evaluateOnDemand(ctx)
		}
	}
}

// currentNetwork returns the network ID; an "unknown" network is looked up
// once more after odRecheck (P9).
func (m *Manager) currentNetwork(ctx context.Context) (string, error) {
	id, err := m.networkID(ctx)
	if err != nil || id != netmon.UnknownNetwork {
		return id, err
	}
	t := time.NewTimer(m.odRecheck)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-t.C:
	}
	return m.networkID(ctx)
}

// identified reports whether id names a particular network.
func identified(id string) bool {
	return id != netmon.UnknownNetwork && id != netmon.NoNetwork
}

// onDemandHeldLocked reports whether t is up, or coming up, because of
// on-demand. Manager.mu is held.
func (t *tunnel) onDemandHeldLocked() bool {
	switch t.state {
	case StateConnecting, StateConnected:
		return t.odConnected
	case StateDisconnected:
		return t.odPending
	}
	return false
}

// evaluateOnDemand connects and disconnects the on-demand tunnels for the
// current network (see above). Only onDemandLoop calls it.
func (m *Manager) evaluateOnDemand(ctx context.Context) {
	m.mu.Lock()
	ts := make([]*tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		ts = append(ts, t)
	}
	m.mu.Unlock()
	slices.SortFunc(ts, func(a, b *tunnel) int { return cmp.Compare(a.name, b.name) })
	pols := map[*tunnel]Policy{}
	for _, t := range ts {
		if p := m.store.policyFor(t.name); p.OnDemand {
			pols[t] = p
		}
	}
	if len(pols) == 0 {
		return // nothing to decide: the network is not even looked up
	}
	id, err := m.currentNetwork(ctx)
	if err != nil {
		if ctx.Err() == nil && err.Error() != m.odErr {
			log.Printf("daemon: on-demand: identifying the network: %v", err)
		}
		m.odErr = err.Error()
		return
	}
	m.odErr = ""

	type want struct {
		t    *tunnel
		pol  Policy
		uids []uint32
	}
	var (
		drop  []*tunnel
		conns []want
	)
	m.mu.Lock()
	if identified(id) && id != m.netID {
		log.Printf("daemon: on-demand: network %s", id)
		m.netID = id
		m.odEpoch++
	}
	epoch := m.odEpoch
	for _, t := range ts {
		pol, ok := pols[t]
		if !ok || m.tunnels[t.name] != t {
			continue
		}
		if t.odSuppressed && identified(id) {
			switch t.odSuppress {
			case "":
				t.odSuppress = id // the network of the down, identified now
			case id:
			default:
				t.odSuppressed = false
				log.Printf("daemon: tunnel %s: on another network (%s) than at its down: on-demand applies again", t.name, id)
			}
		}
		switch {
		case id == netmon.NoNetwork:
			// No network: nothing to protect, nothing to connect through.
		case slices.Contains(pol.TrustedNetworks, id):
			// P22: never lifts a kill switch set to "on", as read now or
			// as the tunnel runs with it.
			if t.onDemandHeldLocked() && pol.KillSwitch != KillSwitchOn && t.policy.KillSwitch != KillSwitchOn {
				drop = append(drop, t)
			}
		case t.state == StateDisconnected && !t.autoPending && !t.odPending && !t.odSuppressed && t.odTried != epoch:
			if uids := m.cardUsersLocked(t.cfg); len(uids) > 0 {
				conns = append(conns, want{t, pol, uids})
			}
		}
	}
	m.mu.Unlock()

	for _, t := range drop {
		// As down does: to disconnected, so its kill switch stops blocking.
		if m.teardown(t, StateDisconnected, (*tunnel).onDemandHeldLocked) {
			log.Printf("daemon: tunnel %s: network %s is trusted: on-demand tunnel down", t.name, id)
		}
	}
	for _, w := range conns {
		m.connectOnDemand(w.t, w.pol, w.uids, id)
	}
}

// connectOnDemand starts an on-demand connect of t as the first of uids
// (users whose agents report one of t's cards) that pol allows or that is
// an administrator. connect checks it again, with the policy as it is then
// (P20), and binds the tunnel to that user's own agent, asking for the PIN.
func (m *Manager) connectOnDemand(t *tunnel, pol Policy, uids []uint32, id string) {
	var uid uint32
	found := false
	for _, u := range uids {
		if pol.allows(u) || m.admin(u) {
			uid, found = u, true
			break
		}
	}
	if !found {
		return
	}
	m.mu.Lock()
	if m.tunnels[t.name] != t || t.state != StateDisconnected || t.autoPending || t.odPending || t.odSuppressed || t.odTried == m.odEpoch {
		m.mu.Unlock()
		return
	}
	t.odPending, t.odTried = true, m.odEpoch
	m.mu.Unlock()
	log.Printf("daemon: tunnel %s: network %s is not trusted: connecting on demand with the YubiKey of uid %d", t.name, id, uid)
	go func() {
		defer func() {
			m.mu.Lock()
			t.odPending = false
			m.mu.Unlock()
		}()
		if _, err := m.connect(context.Background(), t.name, uid, false, connectOpts{onlyFrom: StateDisconnected, want: t, onDemand: true}); err != nil {
			log.Printf("daemon: tunnel %s: on-demand connect: %v", t.name, err)
		}
	}()
}

// cardUsersLocked returns the users whose registered agents report one of
// cfg's cards, earliest registration first. Manager.mu is held.
func (m *Manager) cardUsersLocked(cfg *config.Tunnel) []uint32 {
	first := map[uint32]uint64{}
	for _, a := range m.agents {
		if a.seq == 0 || !slices.ContainsFunc(cfg.Identities, func(id config.Identity) bool { return a.serials[id.Ref.Serial] }) {
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

// downNetwork returns the network a down suppresses on-demand on. It is
// looked up now; when it cannot be identified at this moment, the last
// identified one an evaluation saw stands in, or else "" (the next
// identified network is taken as the down's).
func (m *Manager) downNetwork() string {
	ctx, cancel := context.WithTimeout(context.Background(), onDemandLookupTimeout)
	defer cancel()
	if id, err := m.networkID(ctx); err == nil && identified(id) {
		return id
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.netID
}

// handleNetwork registers network.current: the ID of the network the
// machine is on, for users who may see the status.
func (m *Manager) handleNetwork(c *ipc.Conn) {
	c.Handle(ipc.MethodNetworkCurrent, func(ctx context.Context, uid uint32, _ json.RawMessage) (any, error) {
		if !m.user(uid) {
			return nil, errForbidden
		}
		id, err := m.currentNetwork(ctx)
		if err != nil {
			return nil, &ipc.Error{Code: ipc.CodeInternal, Message: fmt.Sprintf(msg.DaemonNetworkFailedFmt, err)}
		}
		return ipc.NetworkCurrent{ID: id}, nil
	})
}
