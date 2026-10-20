package piv

import (
	"errors"
	"fmt"
	"sync"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

var (
	// ErrNotFound means no YubiKey with the requested serial could be opened.
	ErrNotFound = errors.New(msg.PIVCardNotFound)
	// ErrFirmwareTooOld means the firmware is older than 5.7.0 (no X25519).
	ErrFirmwareTooOld = errors.New(msg.PIVFirmwareTooOld)
	// ErrSlotOccupied means the requested slot holds a key and Force was not set.
	ErrSlotOccupied = errors.New(msg.PIVSlotOccupied)
	// ErrNoFreeSlot means every retired slot 82-95 holds a key.
	ErrNoFreeSlot = errors.New(msg.PIVNoFreeSlot)
	// ErrSlotEmpty means the referenced slot holds no key.
	ErrSlotEmpty = errors.New(msg.PIVSlotEmpty)
	// ErrFreshCard means the card still uses the factory management key and
	// the options needed to secure it (current PIN and PUK, new PIN and PUK)
	// were not all given.
	ErrFreshCard = errors.New(msg.PIVFreshCard)
	// ErrManagementKeyRequired means no usable management key was found.
	ErrManagementKeyRequired = errors.New(msg.PIVManagementKeyRequired)
	// ErrImportedKey means the slot's key was imported rather than generated
	// on the card.
	ErrImportedKey = errors.New(msg.PIVImportedKey)
	// ErrNotX25519 means the slot's key is not an X25519 key.
	ErrNotX25519 = errors.New(msg.PIVNotX25519)
)

// minFirmware is the first YubiKey firmware with X25519 in PIV.
var minFirmware = piv.Version{Major: 5, Minor: 7, Patch: 0}

func supported(v piv.Version) bool {
	if v.Major != minFirmware.Major {
		return v.Major > minFirmware.Major
	}
	if v.Minor != minFirmware.Minor {
		return v.Minor > minFirmware.Minor
	}
	return v.Patch >= minFirmware.Patch
}

func firmwareString(v piv.Version) string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Device describes a connected YubiKey.
type Device struct {
	Serial   uint32
	Firmware string
	Reader   string
	// Supported is true when the firmware is 5.7.0 or later.
	Supported bool
}

// Card is an open, exclusive connection to one YubiKey. All card operations
// through a Card and its providers are serialised.
type Card struct {
	c       card
	reader  string
	serial  uint32
	version piv.Version

	// sem serialises card access; it is a channel so that waiting can be
	// abandoned when a context ends. closed is guarded by sem.
	sem    chan struct{}
	closed bool
}

func newCard(c card, reader string) (*Card, error) {
	serial, err := c.Serial()
	if err != nil {
		return nil, err
	}
	return &Card{c: c, reader: reader, serial: serial, version: c.Version(), sem: make(chan struct{}, 1)}, nil
}

// Serial is the card's serial number.
func (c *Card) Serial() uint32 { return c.serial }

// Reader is the PC/SC reader name the card was opened through.
func (c *Card) Reader() string { return c.reader }

// Firmware is the card's firmware version, for example "5.7.1".
func (c *Card) Firmware() string { return firmwareString(c.version) }

// Close releases the connection. Providers made from the card stop working.
func (c *Card) Close() error {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.c.Close()
}

// List returns every connected YubiKey that could be opened. Cards already
// held open by a Backend provider in this process are reported without being
// reopened.
func List() ([]Device, error) {
	regMu.Lock()
	defer regMu.Unlock()
	return listLocked()
}

// Open connects to the YubiKey with the given serial. Only readers whose
// name identifies a YubiKey are opened; every other card opened while
// searching is closed again.
func Open(serial uint32) (*Card, error) { return openSerial(serial, nil) }

// openSerial is Open, skipping readers in skip (cards this process already
// holds open).
func openSerial(serial uint32, skip map[string]*shared) (*Card, error) {
	readers, err := sys.Cards()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", keyprovider.ErrUnavailable, err)
	}
	var lastErr error
	for _, r := range readers {
		if !isYubiKeyReader(r) || skip[r] != nil {
			continue
		}
		cc, err := sys.Open(r)
		if err != nil {
			lastErr = err
			continue
		}
		c, err := newCard(cc, r)
		if err != nil {
			cc.Close()
			lastErr = err
			continue
		}
		if c.serial == serial {
			return c, nil
		}
		cc.Close()
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w (%v)", ErrNotFound, lastErr)
	}
	return nil, ErrNotFound
}

// Backend gives the agent access to cards. Providers it returns implement
// io.Closer; providers for the same card share one connection, which is
// closed when the last of them is closed.
type Backend struct{}

// Serials lists the serial numbers of connected YubiKeys.
func (Backend) Serials() ([]uint32, error) {
	devs, err := List()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(devs))
	for _, d := range devs {
		out = append(out, d.Serial)
	}
	return out, nil
}

// Provider opens (or reuses) the card named by ref and returns a provider
// for its slot.
func (Backend) Provider(ref keyref.Ref, prompt func(retriesLeft int) (string, error)) (keyprovider.Provider, error) {
	regMu.Lock()
	defer regMu.Unlock()

	var sh *shared
	for _, s := range registry {
		if s.card.serial == ref.Serial && s.aliveLocked() {
			sh = s
			break
		}
	}
	if sh == nil {
		c, err := openSerial(ref.Serial, registry)
		if err != nil {
			return nil, err
		}
		sh = &shared{card: c}
		registry[c.reader] = sh
	}

	kp, err := sh.card.Provider(ref, prompt)
	if err != nil {
		if sh.refs == 0 {
			delete(registry, sh.card.reader)
			sh.card.Close()
		}
		return nil, err
	}
	p := kp.(*provider)
	sh.refs++
	p.closer = func() error {
		regMu.Lock()
		defer regMu.Unlock()
		sh.refs--
		if sh.refs > 0 || sh.dead {
			return nil
		}
		if registry[sh.card.reader] == sh {
			delete(registry, sh.card.reader)
		}
		return sh.card.Close()
	}
	return p, nil
}

// shared is a card held open by Backend providers. PC/SC connections are
// exclusive, so such a card cannot be opened again (not even by List) until
// it is closed.
type shared struct {
	card *Card
	refs int
	dead bool // removed; already closed and dropped from the registry
}

var (
	regMu    sync.Mutex
	registry = map[string]*shared{} // by reader name
)

func resetRegistry() {
	regMu.Lock()
	defer regMu.Unlock()
	registry = map[string]*shared{}
}

// alive reports whether a shared card still answers. A card that is busy
// with another operation is assumed present. A dead card is closed and
// dropped from the registry so that a reinserted card can be opened again.
func (sh *shared) aliveLocked() bool {
	c := sh.card
	select {
	case c.sem <- struct{}{}:
	default:
		return true
	}
	ok := !c.closed
	if ok {
		_, err := c.c.Serial()
		ok = err == nil
	}
	<-c.sem
	if !ok {
		sh.dropLocked()
	}
	return ok
}

// dropLocked closes a removed card and forgets it. Its providers report
// keyprovider.ErrUnavailable from then on.
func (sh *shared) dropLocked() {
	c := sh.card
	select {
	case c.sem <- struct{}{}:
		<-c.sem
		c.Close()
	default:
		// Busy: close once the operation in flight returns (it fails fast on
		// a removed card) instead of blocking the caller.
		go c.Close()
	}
	sh.dead = true
	if registry[sh.card.reader] == sh {
		delete(registry, sh.card.reader)
	}
}

func listLocked() ([]Device, error) {
	readers, err := sys.Cards()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", keyprovider.ErrUnavailable, err)
	}
	present := map[string]bool{}
	for _, r := range readers {
		present[r] = true
	}
	for r, sh := range registry {
		if !present[r] {
			sh.dropLocked()
		}
	}
	var devs []Device
	for _, r := range readers {
		if !isYubiKeyReader(r) {
			continue
		}
		if sh := registry[r]; sh != nil && sh.aliveLocked() {
			c := sh.card
			devs = append(devs, Device{Serial: c.serial, Firmware: firmwareString(c.version), Reader: r, Supported: supported(c.version)})
			continue
		}
		cc, err := sys.Open(r)
		if err != nil {
			continue // in use by another program, or not a PIV card
		}
		serial, err := cc.Serial()
		v := cc.Version()
		cc.Close()
		if err != nil {
			continue
		}
		devs = append(devs, Device{Serial: serial, Firmware: firmwareString(v), Reader: r, Supported: supported(v)})
	}
	return devs, nil
}
