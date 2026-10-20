// Package piv is the YubiKey PIV backend. It generates X25519 keys inside a
// retired key management slot (82-95) and exposes them as a
// keyprovider.Provider. Private keys never leave the card.
//
// Rules this package keeps:
//   - The factory default PIN and PUK are never tried. VerifyPIN-like calls
//     only ever receive a PIN the caller supplied.
//   - A factory-fresh card is detected only by whether the default management
//     key authenticates (management keys have no retry counter).
//   - Only slots 82-95 are read or written; 9a, 9c, 9d and 9e are never used.
//   - Only keys generated on the card (Origin = generated) are accepted.
package piv

import (
	"crypto"
	"errors"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

// card is the narrow part of *piv.YubiKey this package uses. Tests replace
// it with a fake.
type card interface {
	Close() error
	Version() piv.Version
	Serial() (uint32, error)
	Retries() (int, error)
	Metadata(pin string) (*piv.Metadata, error)
	SetMetadata(key []byte, m *piv.Metadata) error
	SetPIN(oldPIN, newPIN string) error
	SetPUK(oldPUK, newPUK string) error
	SetManagementKey(oldKey, newKey []byte) error
	// AuthenticateManagementKey reports whether key is the card's management
	// key, without changing anything on the card.
	AuthenticateManagementKey(key []byte) error
	KeyInfo(slot piv.Slot) (piv.KeyInfo, error)
	GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error)
	PrivateKey(slot piv.Slot, pub crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
}

// system is PC/SC reader access. Tests replace it with a fake.
type system interface {
	Cards() ([]string, error)
	Open(reader string) (card, error)
}

var sys system = pcscSystem{}

type pcscSystem struct{}

func (pcscSystem) Cards() ([]string, error) { return piv.Cards() }

func (pcscSystem) Open(reader string) (card, error) {
	yk, err := piv.Open(reader)
	if err != nil {
		return nil, err
	}
	return yubiKey{yk}, nil
}

// isYubiKeyReader filters PC/SC readers so that other smart cards are never
// opened.
func isYubiKeyReader(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "yubikey") || strings.Contains(n, "yubico")
}

// yubiKey adapts *piv.YubiKey to card.
type yubiKey struct {
	*piv.YubiKey
}

// probeSentinel is the exact error piv-go v2.5.0 returns from GenerateKey
// when management key authentication succeeded and the (deliberately invalid)
// key options were then rejected locally, before any GENERATE command is
// sent. See GenerateKey -> ykAuthenticate -> ykGenerateKey in piv/key.go.
const probeSentinel = "unsupported algorithm"

// AuthenticateManagementKey checks a management key without side effects.
// piv-go has no exported "authenticate" call, so this runs GenerateKey with
// a zero piv.Key and a zero slot: piv-go authenticates first, then refuses
// the zero algorithm locally and never transmits a GENERATE command. Even if
// it did, the card would reject algorithm 0 and key reference 0. A failed
// management key authentication has no retry counter, so probing is free.
func (y yubiKey) AuthenticateManagementKey(key []byte) error {
	_, err := y.YubiKey.GenerateKey(key, piv.Slot{}, piv.Key{})
	return probeResult(err)
}

func probeResult(err error) error {
	if err == nil {
		// Cannot happen with a zero piv.Key; never treat it as success.
		return errors.New("piv: management key probe returned no error")
	}
	if err.Error() == probeSentinel {
		return nil
	}
	return err
}
