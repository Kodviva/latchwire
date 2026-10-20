package piv

import (
	"errors"
	"fmt"
	"sync"
	"time"

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
	// ErrUnsupportedPolicy means the slot's key does not use PIN policy once
	// and touch policy never.
	ErrUnsupportedPolicy = errors.New(msg.PIVUnsupportedPolicy)
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

// List returns every connected YubiKey. Presence comes from the PC/SC reader
// list only: a reader is opened (briefly, in shared mode) only the first
// time it appears, and its serial and firmware are cached until the reader
// disappears. Cards are never queried on later calls. A reader that opens
// but whose serial cannot be read is retried at most every 10 seconds.
func List() ([]Device, error) {
	regMu.Lock()
	defer regMu.Unlock()
	return listLocked()
}

// Open connects to the YubiKey with the given serial. Only readers whose
// name identifies a YubiKey are opened; every other card opened while
// searching is closed again. The connection is shared: other programs can
// use the card between operations.
func Open(serial uint32) (*Card, error) {
	regMu.Lock()
	defer regMu.Unlock()
	return openSerialLocked(serial)
}

// openSerialLocked tries the reader cached for serial first, then readers
// not seen yet, then readers cached for other serials (in case the cache is
// stale). The serial is always checked on the opened card.
func openSerialLocked(serial uint32) (*Card, error) {
	readers, err := sys.Cards()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", keyprovider.ErrUnavailable, err)
	}
	sweepLocked(readers)
	var match, unseen, other []string
	for _, r := range readers {
		if !isYubiKeyReader(r) {
			continue
		}
		d, ok := seen[r]
		switch {
		case ok && d.Serial == serial:
			match = append(match, r)
		case !ok:
			unseen = append(unseen, r)
		default:
			other = append(other, r)
		}
	}
	var lastErr error
	for _, r := range append(append(match, unseen...), other...) {
		cc, err := sys.Open(r)
		if err != nil {
			lastErr = err
			continue
		}
		c, err := newCard(cc, r)
		if err != nil {
			cc.Close()
			failed[r] = now().Add(serialRetryInterval)
			lastErr = err
			continue
		}
		delete(failed, r)
		seen[r] = c.device()
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

func (c *Card) device() Device {
	return Device{Serial: c.serial, Firmware: firmwareString(c.version), Reader: c.reader, Supported: supported(c.version)}
}

// Backend gives the agent access to cards. Providers it returns implement
// io.Closer. Providers for the same card share one connection, which is
// closed when the last of them is closed. The connection is in shared mode
// with a PC/SC transaction only per operation, so holding it does not keep
// other programs (macOS smart-card login, ykman, ...) from using the card.
// When an operation fails with keyprovider.ErrUnavailable (transport error,
// or another card in the reader after a reset) the connection and the
// reader's cached serial are dropped: providers made from it keep failing,
// and the next Serials or Provider call opens the reader again.
type Backend struct{}

// Serials lists the serial numbers of connected YubiKeys (see List: no card
// command is sent for readers already seen).
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

	readers, err := sys.Cards()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", keyprovider.ErrUnavailable, err)
	}
	sweepLocked(readers)

	var sh *shared
	for _, s := range registry {
		if s.card.serial == ref.Serial {
			sh = s
			break
		}
	}
	if sh == nil {
		c, err := openSerialLocked(ref.Serial)
		if err != nil {
			return nil, err
		}
		sh = &shared{card: c}
		registry[c.reader] = sh
	}

	kp, err := sh.card.Provider(ref, prompt)
	if err != nil {
		switch {
		case errors.Is(err, keyprovider.ErrUnavailable):
			// The connection is dead (for example the card was re-seated
			// between two polls): forget it so the next call reopens.
			sh.forgetLocked()
		case sh.refs == 0:
			delete(registry, sh.card.reader)
			sh.card.Close()
		}
		return nil, err
	}
	p := kp.(*provider)
	sh.refs++
	p.onUnavailable = func() {
		regMu.Lock()
		defer regMu.Unlock()
		sh.forgetLocked()
	}
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

// shared is a card connection held by Backend providers.
type shared struct {
	card *Card
	refs int
	dead bool // reader gone; already closed and dropped from the registry
}

// serialRetryInterval is how long a reader that opened but whose serial
// could not be read is left alone by presence polling.
const serialRetryInterval = 10 * time.Second

// now is the clock; tests replace it.
var now = time.Now

var (
	regMu    sync.Mutex
	registry = map[string]*shared{}   // held connections, by reader name
	seen     = map[string]Device{}    // reader -> card read when the reader appeared
	failed   = map[string]time.Time{} // reader -> no serial read retry before this time
)

func resetRegistry() {
	regMu.Lock()
	defer regMu.Unlock()
	registry = map[string]*shared{}
	seen = map[string]Device{}
	failed = map[string]time.Time{}
}

// forgetLocked drops a connection that failed with a transport error, and
// the serial cached for its reader, so that the next Serials or Provider
// call opens the reader again. It does nothing if the connection was
// already dropped or replaced.
func (sh *shared) forgetLocked() {
	if sh.dead || registry[sh.card.reader] != sh {
		return
	}
	sh.dropLocked()
	delete(seen, sh.card.reader)
}

// sweepLocked forgets readers that are no longer listed: their cached
// device is dropped and a held connection is closed, so its providers report
// keyprovider.ErrUnavailable and a reinserted card is opened afresh.
func sweepLocked(readers []string) {
	present := make(map[string]bool, len(readers))
	for _, r := range readers {
		present[r] = true
	}
	for r := range seen {
		if !present[r] {
			delete(seen, r)
		}
	}
	for r := range failed {
		if !present[r] {
			delete(failed, r)
		}
	}
	for r, sh := range registry {
		if !present[r] {
			sh.dropLocked()
		}
	}
}

// dropLocked closes a removed card and forgets it.
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
	if registry[c.reader] == sh {
		delete(registry, c.reader)
	}
}

func listLocked() ([]Device, error) {
	readers, err := sys.Cards()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", keyprovider.ErrUnavailable, err)
	}
	sweepLocked(readers)
	var devs []Device
	for _, r := range readers {
		if !isYubiKeyReader(r) {
			continue
		}
		if d, ok := seen[r]; ok {
			devs = append(devs, d)
			continue
		}
		if sh := registry[r]; sh != nil {
			d := sh.card.device()
			seen[r] = d
			devs = append(devs, d)
			continue
		}
		if t, ok := failed[r]; ok && now().Before(t) {
			continue
		}
		cc, err := sys.Open(r)
		if err != nil {
			continue // not a PIV card, or not ready; retried on the next call
		}
		serial, err := cc.Serial()
		v := cc.Version()
		cc.Close()
		if err != nil {
			// Opens but does not answer: retried every serialRetryInterval
			// rather than on every poll.
			failed[r] = now().Add(serialRetryInterval)
			continue
		}
		delete(failed, r)
		d := Device{Serial: serial, Firmware: firmwareString(v), Reader: r, Supported: supported(v)}
		seen[r] = d
		devs = append(devs, d)
	}
	return devs, nil
}
