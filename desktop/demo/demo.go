// Package demo is a stand-in backend for the demo build (-tags demo) and the
// shell's tests. It holds no cryptography: its keys are made-up bytes and
// the production binary does not link it.
package demo

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Serials of the two demo cards.
const (
	CardA = 40727512
	CardB = 40727513
)

// Backend implements ui.Backend in memory.
type Backend struct {
	mu      sync.Mutex
	present map[uint32]bool
	keys    map[uint32][]desktop.Key
	tunnels []ipc.TunnelStatus
	// Added holds the configurations given to Add.
	Added map[string]string
	// DaemonDown makes every daemon call fail.
	DaemonDown bool

	fresh    map[uint32]bool
	grants   []ipc.AssistGrant
	held     bool
	revokes  int
	activity []ipc.ActivityEntry
}

// New returns a backend with two cards and two tunnels.
func New() *Backend {
	b := &Backend{present: map[uint32]bool{CardA: true, CardB: true}, keys: map[uint32][]desktop.Key{},
		Added: map[string]string{}, fresh: map[uint32]bool{}}
	b.tunnels = []ipc.TunnelStatus{
		{Name: "office", State: daemon.StateConnected, Identity: "piv://40727512/82",
			LastHandshake: time.Now().Add(-48 * time.Second).Format(time.RFC3339)},
		{Name: "servers", State: daemon.StateDisconnected},
	}
	return b
}

// NewEmpty returns New's backend without any tunnel, as a new user has it.
func NewEmpty() *Backend {
	b := New()
	b.tunnels = nil
	return b
}

// SetCard plugs a card in or removes it, the way the daemon reacts: a tunnel
// on a removed card goes to card_removed at once.
func (b *Backend) SetCard(serial uint32, in bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.present[serial] = in
	for i := range b.tunnels {
		t := &b.tunnels[i]
		ref, err := keyref.Parse(t.Identity)
		if err != nil || ref.Serial != serial {
			continue
		}
		switch {
		case !in && t.State == daemon.StateConnected:
			t.State, t.LastHandshake = daemon.StateCardRemoved, ""
		case in && t.State == daemon.StateCardRemoved:
			t.State, t.LastHandshake = daemon.StateConnected, time.Now().Format(time.RFC3339)
		}
	}
}

// Devices implements ui.Backend.
func (b *Backend) Devices() ([]desktop.Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []desktop.Device
	for _, s := range []uint32{CardA, CardB} {
		if b.present[s] {
			out = append(out, desktop.Device{Serial: s, Firmware: "5.8.0", Supported: true})
		}
	}
	return out, nil
}

// Inspect implements ui.Backend.
func (b *Backend) Inspect(serial uint32) (desktop.CardInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	info := desktop.CardInfo{Keys: b.keys[serial], Fresh: b.fresh[serial]}
	used := map[uint8]bool{}
	for _, k := range info.Keys {
		used[k.Ref.Slot] = true
	}
	for s := uint8(keyref.MinSlot); s <= keyref.MaxSlot; s++ {
		if !used[s] {
			info.FreeSlots = append(info.FreeSlots, s)
		}
	}
	return info, nil
}

// Keygen implements ui.Backend: it goes through the real Asker steps.
func (b *Backend) Keygen(serial uint32, slot uint8, a desktop.Asker) (desktop.Key, error) {
	pin, err := a.PIN(serial, 3)
	if err != nil {
		return desktop.Key{}, err
	}
	defer clear(pin)
	if len(pin) == 0 {
		return desktop.Key{}, errors.New(msg.PIVEmptyPIN)
	}
	k := desktop.Key{Ref: keyref.Ref{Serial: serial, Slot: slot}}
	if _, err := rand.Read(k.Public[:]); err != nil {
		return k, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys[serial] = append(b.keys[serial], k)
	return k, nil
}

func (b *Backend) find(name string) (*ipc.TunnelStatus, error) {
	if b.DaemonDown {
		return nil, desktop.ErrDaemonDown
	}
	for i := range b.tunnels {
		if b.tunnels[i].Name == name {
			return &b.tunnels[i], nil
		}
	}
	return nil, errors.New(msg.DaemonTunnelNotFound)
}

// Status implements ui.Backend.
func (b *Backend) Status(context.Context) ([]ipc.TunnelStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.DaemonDown {
		return nil, desktop.ErrDaemonDown
	}
	return append([]ipc.TunnelStatus(nil), b.tunnels...), nil
}

// Connect implements ui.Backend.
func (b *Backend) Connect(_ context.Context, name string) (ipc.TunnelStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, err := b.find(name)
	if err != nil {
		return ipc.TunnelStatus{}, err
	}
	if !b.present[CardA] {
		return ipc.TunnelStatus{}, errors.New(msg.DaemonNoCard)
	}
	t.State, t.Identity, t.LastHandshake = daemon.StateConnected, "piv://40727512/82", time.Now().Format(time.RFC3339)
	return *t, nil
}

// Disconnect implements ui.Backend.
func (b *Backend) Disconnect(_ context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, err := b.find(name)
	if err != nil {
		return err
	}
	t.State, t.Identity, t.LastHandshake = daemon.StateDisconnected, "", ""
	return nil
}

// Add implements ui.Backend.
func (b *Backend) Add(_ context.Context, name, config string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.DaemonDown {
		return desktop.ErrDaemonDown
	}
	b.Added[name] = config
	b.tunnels = append(b.tunnels, ipc.TunnelStatus{Name: name, State: daemon.StateDisconnected})
	return nil
}

// SetFresh makes a card look factory-fresh to Inspect.
func (b *Backend) SetFresh(serial uint32, fresh bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fresh[serial] = fresh
}

// Grant implements ui.Backend: it records g and holds it until Revoke or
// DropGrant.
func (b *Backend) Grant(_ context.Context, g ipc.AssistGrant) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.DaemonDown {
		return desktop.ErrDaemonDown
	}
	g.Groups = append([]string(nil), g.Groups...)
	b.grants = append(b.grants, g)
	b.held = true
	return nil
}

// Revoke implements ui.Backend.
func (b *Backend) Revoke(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held = false
	b.revokes++
	return nil
}

// GrantHeld implements ui.Backend.
func (b *Backend) GrantHeld() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.held
}

// DropGrant ends the access the way a lost agent connection does.
func (b *Backend) DropGrant() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held = false
}

// Grants returns what Grant was given, oldest first.
func (b *Backend) Grants() []ipc.AssistGrant {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]ipc.AssistGrant(nil), b.grants...)
}

// Revokes counts the Revoke calls.
func (b *Backend) Revokes() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.revokes
}

// SetActivity sets what Activity returns (newest first).
func (b *Backend) SetActivity(e []ipc.ActivityEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.activity = append([]ipc.ActivityEntry(nil), e...)
}

// Activity implements ui.Backend.
func (b *Backend) Activity(context.Context) ([]ipc.ActivityEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.DaemonDown {
		return nil, desktop.ErrDaemonDown
	}
	return append([]ipc.ActivityEntry(nil), b.activity...), nil
}
