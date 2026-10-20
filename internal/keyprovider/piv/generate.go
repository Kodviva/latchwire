package piv

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// managementKeyLen is the length of the random management key set on a
// factory-fresh card: AES-256. (Upstream piv-go stored only 24-byte keys
// correctly in the protected data object; the vendored copy is patched.)
const managementKeyLen = 32

// minSecretLen and maxSecretLen bound a new PIN or PUK.
const (
	minSecretLen = 6
	maxSecretLen = 8
)

// GenerateOptions controls Card.Generate.
type GenerateOptions struct {
	// Slot is the retired slot 0x82-0x95 to use; 0 picks the first empty one.
	Slot uint8
	// PIN is the card's current PIN. It unlocks a PIN-protected management
	// key and, on a fresh card, is changed to NewPIN.
	PIN string
	// ManagementKey, when set, is used instead of looking one up.
	ManagementKey []byte
	// NewPIN, CurrentPUK and NewPUK are needed only for a factory-fresh card
	// (one that still accepts the default management key).
	NewPIN, CurrentPUK, NewPUK string
	// Force allows replacing a key in an explicitly chosen occupied slot.
	Force bool
}

// Generate creates an X25519 key on the card (PIN policy once, touch policy
// never) and returns its reference and public key. The private key never
// leaves the card.
//
// Order: firmware check; slot choice (so nothing is changed on the card when
// no slot can be used); management key: the given one, else the PIN-protected
// one stored on the card, else - only if the factory default management key
// authenticates - the card is secured first (new PIN and PUK, random
// management key stored under the PIN); then the key is generated.
func (c *Card) Generate(o GenerateOptions) (keyref.Ref, [32]byte, error) {
	var pub [32]byte
	if o.Slot != 0 && !retired(o.Slot) {
		return keyref.Ref{}, pub, fmt.Errorf(msg.PIVSlotOutOfRangeFmt, o.Slot)
	}
	if len(o.PIN) > maxSecretLen || len(o.CurrentPUK) > maxSecretLen {
		return keyref.Ref{}, pub, errors.New(msg.PIVSecretTooLong)
	}

	c.sem <- struct{}{}
	defer func() { <-c.sem }()
	if c.closed {
		return keyref.Ref{}, pub, keyprovider.ErrUnavailable
	}

	if !supported(c.version) {
		return keyref.Ref{}, pub, ErrFirmwareTooOld
	}

	slot, err := c.pickSlot(o)
	if err != nil {
		return keyref.Ref{}, pub, err
	}

	mk, err := c.managementKey(o)
	if err != nil {
		return keyref.Ref{}, pub, err
	}
	defer clear(mk)

	pk, err := c.c.GenerateKey(mk, pivSlot(slot), piv.Key{
		Algorithm:   piv.AlgorithmX25519,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyNever,
	})
	if err != nil {
		return keyref.Ref{}, pub, mapCardErr(err)
	}
	ep, ok := pk.(*ecdh.PublicKey)
	if !ok || ep.Curve() != ecdh.X25519() {
		return keyref.Ref{}, pub, errors.New(msg.PIVUnexpectedPublicKey)
	}
	copy(pub[:], ep.Bytes())
	return keyref.Ref{Serial: c.serial, Slot: slot}, pub, nil
}

func retired(s uint8) bool { return s >= keyref.MinSlot && s <= keyref.MaxSlot }

// pivSlot maps a retired slot number to piv-go's slot. Callers check the
// range first.
func pivSlot(s uint8) piv.Slot {
	ps, ok := piv.RetiredKeyManagementSlot(uint32(s))
	if !ok {
		panic(fmt.Sprintf("piv: slot %#x is not retired", s))
	}
	return ps
}

// Occupied reports whether the retired slot s (0x82-0x95) holds a key. It
// reads only the slot's metadata and changes nothing on the card.
func (c *Card) Occupied(s uint8) (bool, error) {
	if !retired(s) {
		return false, fmt.Errorf(msg.PIVSlotOutOfRangeFmt, s)
	}
	c.sem <- struct{}{}
	defer func() { <-c.sem }()
	if c.closed {
		return false, keyprovider.ErrUnavailable
	}
	return c.occupied(s)
}

func (c *Card) occupied(s uint8) (bool, error) {
	_, err := c.c.KeyInfo(pivSlot(s))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, piv.ErrNotFound):
		return false, nil
	default:
		return false, mapCardErr(err)
	}
}

func (c *Card) pickSlot(o GenerateOptions) (uint8, error) {
	if o.Slot != 0 {
		occ, err := c.occupied(o.Slot)
		if err != nil {
			return 0, err
		}
		if occ && !o.Force {
			return 0, ErrSlotOccupied
		}
		return o.Slot, nil
	}
	for s := uint8(keyref.MinSlot); s <= keyref.MaxSlot; s++ {
		occ, err := c.occupied(s)
		if err != nil {
			return 0, err
		}
		if !occ {
			return s, nil
		}
	}
	return 0, ErrNoFreeSlot
}

// managementKey returns a management key that authenticates, in a fresh
// slice the caller clears.
func (c *Card) managementKey(o GenerateOptions) ([]byte, error) {
	if len(o.ManagementKey) > 0 {
		if err := c.c.AuthenticateManagementKey(o.ManagementKey); err != nil {
			return nil, fmt.Errorf("%w (%v)", ErrManagementKeyRequired, err)
		}
		return append([]byte(nil), o.ManagementKey...), nil
	}

	if o.PIN != "" {
		md, err := c.c.Metadata(o.PIN)
		if err != nil {
			return nil, mapCardErr(err)
		}
		if md.ManagementKey != nil {
			k := *md.ManagementKey
			if c.c.AuthenticateManagementKey(k) == nil {
				return k, nil
			}
			// A stale stored key: ignore it.
			clear(k)
		}
	}

	// Fresh-card detection: only the default management key is tried, never
	// the default PIN or PUK.
	if c.c.AuthenticateManagementKey(piv.DefaultManagementKey) == nil {
		return c.harden(o)
	}
	return nil, ErrManagementKeyRequired
}

func validSecret(s string) bool { return len(s) >= minSecretLen && len(s) <= maxSecretLen }

// harden secures a card that still uses the factory management key.
//
// Order:
//  1. The current PUK is checked (changed to itself) before anything else,
//     so a wrong PUK aborts with the PIN untouched.
//  2. PIN, then PUK, are changed to the caller's new values.
//  3. A random AES-256 management key is stored under the PIN in ykman's
//     protected data object (0x5FC109) and read back, before it replaces the
//     default key: a failed write cannot leave a key nobody knows.
//  4. The management key is changed, then ykman's PIVMAN flag
//     "management key stored" is set with the new key.
//
// Errors after step 2 began say which secrets already have their new value.
func (c *Card) harden(o GenerateOptions) ([]byte, error) {
	if o.PIN == "" || o.CurrentPUK == "" || !validSecret(o.NewPIN) || !validSecret(o.NewPUK) ||
		o.NewPIN == piv.DefaultPIN || o.NewPUK == piv.DefaultPUK {
		return nil, ErrFreshCard
	}
	if err := c.c.SetPUK(o.CurrentPUK, o.CurrentPUK); err != nil {
		return nil, mapPUKErr(err)
	}
	if err := c.c.SetPIN(o.PIN, o.NewPIN); err != nil {
		return nil, mapCardErr(err)
	}
	if err := c.c.SetPUK(o.CurrentPUK, o.NewPUK); err != nil {
		return nil, fmt.Errorf("%s: %w", msg.PIVPINAlreadyChanged, mapPUKErr(err))
	}
	changed := func(err error) error {
		return fmt.Errorf("%s: %w", msg.PIVPINAndPUKAlreadyChanged, err)
	}

	mk := make([]byte, managementKeyLen)
	if _, err := rand.Read(mk); err != nil {
		return nil, changed(err)
	}
	fail := func(err error) ([]byte, error) {
		clear(mk)
		return nil, changed(err)
	}

	stored := append([]byte(nil), mk...)
	err := c.c.SetMetadata(piv.DefaultManagementKey, &piv.Metadata{ManagementKey: &stored})
	clear(stored)
	if err != nil {
		return fail(mapCardErr(err))
	}
	md, err := c.c.Metadata(o.NewPIN)
	if err != nil {
		return fail(mapCardErr(err))
	}
	if md.ManagementKey == nil || subtle.ConstantTimeCompare(*md.ManagementKey, mk) != 1 {
		if md.ManagementKey != nil {
			clear(*md.ManagementKey)
		}
		return fail(errors.New(msg.PIVStoredKeyMismatch))
	}
	clear(*md.ManagementKey)

	if err := c.c.SetManagementKey(piv.DefaultManagementKey, mk); err != nil {
		return fail(mapCardErr(err))
	}
	if err := c.c.SetPIVManFlags(mk, piv.PIVManFlagMgmtKeyStored); err != nil {
		return fail(fmt.Errorf("%s: %w", msg.PIVPIVManFlagFailed, mapCardErr(err)))
	}
	if err := c.c.AuthenticateManagementKey(mk); err != nil {
		return fail(mapCardErr(err))
	}
	return mk, nil
}

func mapPUKErr(err error) error {
	var ae piv.AuthErr
	if errors.As(err, &ae) {
		if ae.Retries == 0 {
			return errors.New(msg.PIVPUKBlocked)
		}
		return fmt.Errorf(msg.PIVWrongPUKFmt, ae.Retries)
	}
	return mapCardErr(err)
}
