package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// fakeAPDUErr mimics piv-go's unexported apduErr: it exposes the status word.
type fakeAPDUErr struct{ sw uint16 }

func (e *fakeAPDUErr) Error() string  { return fmt.Sprintf("smart card error %04x", e.sw) }
func (e *fakeAPDUErr) Status() uint16 { return e.sw }

// errRemoved mimics a PC/SC transport error after the card was pulled out.
var errRemoved = errors.New("transmitting request: the smart card has been removed")

// fakeCard is an in-memory card. It records every call so tests can check
// ordering and the exact secrets that would have been sent to a real card.
type fakeCard struct {
	t *testing.T

	mu sync.Mutex

	version piv.Version
	serial  uint32

	pin, puk     string
	pinRetries   int
	pukRetries   int
	mgmtKey      []byte
	storedMgmt   []byte // PIN-protected metadata key, nil if none
	truncateMeta bool   // simulate a corrupted protected-metadata write
	verified     bool   // PIN verified in this session

	slots map[uint32]piv.KeyInfo
	privs map[uint32]*ecdh.PrivateKey

	pivman byte // ykman PIVMAN flags

	// failure injection
	fail       map[string]failAt // fail the nth call of a method
	counts     map[string]int
	ecdhErr    error // returned by ECDH instead of computing
	ecdhZero   bool  // ECDH returns all zeros
	retriesErr error

	calls    []string
	pinsSent []string // every PIN/PUK value sent as the *current* secret
	genOpts  []piv.Key
	mgmtLens []int
	closed   bool
	ecdhN    int
}

func newFakeCard(t *testing.T, serial uint32) *fakeCard {
	return &fakeCard{
		t:          t,
		version:    piv.Version{Major: 5, Minor: 7, Patch: 1},
		serial:     serial,
		pin:        "246810",
		puk:        "97531086",
		pinRetries: 3,
		pukRetries: 3,
		mgmtKey:    bytes.Repeat([]byte{0x42}, 32),
		slots:      map[uint32]piv.KeyInfo{},
		privs:      map[uint32]*ecdh.PrivateKey{},
	}
}

// fresh makes the card look factory-new: default management key, no stored
// management key. The PIN is still the test PIN so that sending the default
// PIN would be a visible mistake.
func (f *fakeCard) fresh() *fakeCard {
	f.mgmtKey = append([]byte(nil), piv.DefaultManagementKey...)
	f.storedMgmt = nil
	return f
}

func (f *fakeCard) protectMgmt() *fakeCard {
	f.storedMgmt = append([]byte(nil), f.mgmtKey...)
	return f
}

type failAt struct {
	nth int
	err error
}

// failOn makes the nth (1-based) call of method name fail with err.
func (f *fakeCard) failOn(name string, nth int, err error) *fakeCard {
	if f.fail == nil {
		f.fail = map[string]failAt{}
	}
	f.fail[name] = failAt{nth, err}
	return f
}

func (f *fakeCard) record(c string) { f.calls = append(f.calls, c) }

// injected counts a call and returns the injected failure, if any.
func (f *fakeCard) injected(name string) error {
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.counts[name]++
	if fa, ok := f.fail[name]; ok && fa.nth == f.counts[name] {
		return fa.err
	}
	return nil
}

func (f *fakeCard) callCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == name {
			n++
		}
	}
	return n
}

func (f *fakeCard) checkSlot(s piv.Slot) {
	if s.Key < 0x82 || s.Key > 0x95 {
		f.t.Errorf("card touched slot %#x outside the retired range 82-95", s.Key)
	}
}

func (f *fakeCard) occupy(slot uint32, ki piv.KeyInfo) {
	f.slots[slot] = ki
}

func (f *fakeCard) occupyX25519(slot uint32) *ecdh.PrivateKey {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	f.slots[slot] = piv.KeyInfo{
		Algorithm:   piv.AlgorithmX25519,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyNever,
		Origin:      piv.OriginGenerated,
		PublicKey:   sk.PublicKey(),
	}
	f.privs[slot] = sk
	return sk
}

func (f *fakeCard) pinCheck(pin string) error {
	f.pinsSent = append(f.pinsSent, pin)
	if f.pinRetries == 0 {
		return fmt.Errorf("verify pin: %w", piv.AuthErr{Retries: 0})
	}
	if pin != f.pin {
		f.pinRetries--
		f.verified = false
		return fmt.Errorf("verify pin: %w", piv.AuthErr{Retries: f.pinRetries})
	}
	f.pinRetries = 3
	f.verified = true
	return nil
}

func (f *fakeCard) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Close")
	f.closed = true
	return nil
}

func (f *fakeCard) Version() piv.Version { return f.version }

func (f *fakeCard) Serial() (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Serial")
	if f.closed {
		return 0, errRemoved
	}
	return f.serial, nil
}

func (f *fakeCard) Retries() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Retries")
	if f.retriesErr != nil {
		return 0, f.retriesErr
	}
	return f.pinRetries, nil
}

func (f *fakeCard) Metadata(pin string) (*piv.Metadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Metadata")
	if err := f.pinCheck(pin); err != nil {
		return nil, fmt.Errorf("authenticating with pin: %w", err)
	}
	if f.storedMgmt == nil {
		return &piv.Metadata{}, nil
	}
	k := append([]byte(nil), f.storedMgmt...)
	return &piv.Metadata{ManagementKey: &k}, nil
}

func (f *fakeCard) SetMetadata(key []byte, m *piv.Metadata) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetMetadata")
	if err := f.injected("SetMetadata"); err != nil {
		return err
	}
	if !bytes.Equal(key, f.mgmtKey) {
		return &fakeAPDUErr{0x6982}
	}
	if m.ManagementKey == nil {
		f.storedMgmt = nil
		return nil
	}
	k := append([]byte(nil), (*m.ManagementKey)...)
	if f.truncateMeta {
		k = k[:len(k)-1]
	}
	f.storedMgmt = k
	return nil
}

func (f *fakeCard) SetPIN(oldPIN, newPIN string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetPIN")
	if err := f.injected("SetPIN"); err != nil {
		return err
	}
	if err := f.pinCheck(oldPIN); err != nil {
		return err
	}
	f.pin = newPIN
	return nil
}

func (f *fakeCard) SetPUK(oldPUK, newPUK string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetPUK")
	f.pinsSent = append(f.pinsSent, oldPUK)
	if err := f.injected("SetPUK"); err != nil {
		return err
	}
	if oldPUK != f.puk {
		f.pukRetries--
		return piv.AuthErr{Retries: f.pukRetries}
	}
	f.puk = newPUK
	return nil
}

func (f *fakeCard) SetManagementKey(oldKey, newKey []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetManagementKey")
	f.mgmtLens = append(f.mgmtLens, len(newKey))
	if err := f.injected("SetManagementKey"); err != nil {
		return err
	}
	if !bytes.Equal(oldKey, f.mgmtKey) {
		return &fakeAPDUErr{0x6982}
	}
	f.mgmtKey = append([]byte(nil), newKey...)
	return nil
}

func (f *fakeCard) SetPIVManFlags(key []byte, flags byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SetPIVManFlags")
	if err := f.injected("SetPIVManFlags"); err != nil {
		return err
	}
	if !bytes.Equal(key, f.mgmtKey) {
		return fmt.Errorf("authenticating with management key: %w", &fakeAPDUErr{0x6982})
	}
	f.pivman |= flags
	return nil
}

func (f *fakeCard) AuthenticateManagementKey(key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("AuthenticateManagementKey")
	if !bytes.Equal(key, f.mgmtKey) {
		return fmt.Errorf("authenticating with management key: %w", &fakeAPDUErr{0x6982})
	}
	return nil
}

func (f *fakeCard) KeyInfo(slot piv.Slot) (piv.KeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("KeyInfo")
	f.checkSlot(slot)
	ki, ok := f.slots[slot.Key]
	if !ok {
		return piv.KeyInfo{}, fmt.Errorf("command failed: %w", piv.ErrNotFound)
	}
	return ki, nil
}

func (f *fakeCard) GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GenerateKey")
	f.checkSlot(slot)
	f.genOpts = append(f.genOpts, opts)
	if !bytes.Equal(key, f.mgmtKey) {
		return nil, fmt.Errorf("authenticating with management key: %w", &fakeAPDUErr{0x6982})
	}
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f.slots[slot.Key] = piv.KeyInfo{
		Algorithm:   opts.Algorithm,
		PINPolicy:   opts.PINPolicy,
		TouchPolicy: opts.TouchPolicy,
		Origin:      piv.OriginGenerated,
		PublicKey:   sk.PublicKey(),
	}
	f.privs[slot.Key] = sk
	return sk.PublicKey(), nil
}

func (f *fakeCard) PrivateKey(slot piv.Slot, pub crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("PrivateKey")
	f.checkSlot(slot)
	if auth.PIN != "" {
		f.t.Errorf("provider passed a static PIN to piv-go; PINs must come from the prompt only")
	}
	sk, ok := f.privs[slot.Key]
	if !ok {
		return nil, fmt.Errorf("no key in slot %x", slot.Key)
	}
	if !sk.PublicKey().Equal(pub) {
		f.t.Errorf("PrivateKey called with a public key that does not match the slot")
	}
	return &fakeX25519{f: f, sk: sk, auth: auth}, nil
}

// fakeX25519 follows piv-go's KeyAuth flow for PINPolicyOnce: prompt only
// when the PIN is not verified, then run the operation.
type fakeX25519 struct {
	f    *fakeCard
	sk   *ecdh.PrivateKey
	auth piv.KeyAuth
}

func (k *fakeX25519) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	f := k.f
	f.mu.Lock()
	verified := f.verified
	f.mu.Unlock()
	if !verified {
		if k.auth.PINPrompt == nil {
			return nil, errors.New("pin required but wasn't provided")
		}
		// piv-go calls the prompt without holding any lock of ours.
		pin, err := k.auth.PINPrompt()
		if err != nil {
			// piv-go wraps with %v and loses the chain.
			return nil, fmt.Errorf("pin prompt: %v", err)
		}
		if pin == "" {
			return nil, errors.New("pin required but wasn't provided")
		}
		f.mu.Lock()
		err = f.pinCheck(pin)
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ECDH")
	f.ecdhN++
	if f.ecdhErr != nil {
		return nil, fmt.Errorf("command failed: %w", f.ecdhErr)
	}
	if f.ecdhZero {
		return make([]byte, 32), nil
	}
	return k.sk.ECDH(peer)
}

// fakeSystem is a set of fake PC/SC readers.
type fakeSystem struct {
	readers []string
	cards   map[string]*fakeCard
	opened  []string
	openErr map[string]error
}

func (s *fakeSystem) Cards() ([]string, error) { return s.readers, nil }

func (s *fakeSystem) Open(reader string) (card, error) {
	s.opened = append(s.opened, reader)
	if err := s.openErr[reader]; err != nil {
		return nil, err
	}
	c, ok := s.cards[reader]
	if !ok {
		return nil, fmt.Errorf("connecting to smart card: no card in %s", reader)
	}
	c.mu.Lock()
	c.closed = false
	c.verified = false
	c.mu.Unlock()
	return c, nil
}

// useSystem swaps the package's PC/SC access for the duration of a test.
func useSystem(t *testing.T, s system) {
	t.Helper()
	old := sys
	sys = s
	resetRegistry()
	t.Cleanup(func() {
		sys = old
		resetRegistry()
	})
}
