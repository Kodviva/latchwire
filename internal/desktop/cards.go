// Package desktop is the logic of the desktop app, free of any UI toolkit:
// card inspection and key generation, the [Peer] block, binding a server's
// .conf to the keys on the card, the daemon client and the tunnel view
// model. The Fyne shell in the desktop/ module draws what this package says.
//
// Secret handling: PINs, PUKs and management keys travel as []byte owned by
// the caller of Keygen's Asker callbacks and are wiped here as soon as the
// card has answered. The piv package takes Go strings, which cannot be
// wiped, the same limit the terminal path has (docs/threat-model.md 5.3).
package desktop

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/piv"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// ErrCancelled is what an Asker returns when the user closes a form.
var ErrCancelled = errors.New("cancelled")

// Key is a key on a card. It holds public data only.
type Key struct {
	Ref    keyref.Ref
	Public [32]byte
}

// PublicBase64 is the public key as WireGuard writes it.
func (k Key) PublicBase64() string { return base64.StdEncoding.EncodeToString(k.Public[:]) }

// Device is a connected YubiKey.
type Device struct {
	Serial    uint32
	Firmware  string
	Supported bool
}

// CardInfo is what a card holds. Reading it needs no PIN and writes nothing.
type CardInfo struct {
	FreeSlots []uint8 // retired slots without a key, lowest first
	Keys      []Key   // usable Latchwire keys
	// Fresh says the card still uses the factory management key: creating
	// a key will ask for the current PUK and change the PIN and PUK.
	Fresh bool
}

// CardOps is the part of *piv.Card this package uses. Tests replace it.
type CardOps interface {
	Generate(piv.GenerateOptions) (keyref.Ref, [32]byte, error)
	Provider(ref keyref.Ref, prompt func(retriesLeft int) (string, error)) (keyprovider.Provider, error)
	Occupied(slot uint8) (bool, error)
	PINRetries() (int, error)
	Fresh() (bool, error)
	Close() error
}

// Cards is access to the YubiKeys.
type Cards struct {
	List func() ([]piv.Device, error)
	Open func(serial uint32) (CardOps, error)
}

// RealCards uses the PC/SC backend.
func RealCards() Cards {
	return Cards{List: piv.List, Open: func(serial uint32) (CardOps, error) {
		c, err := piv.Open(serial)
		if err != nil {
			return nil, err
		}
		return c, nil
	}}
}

// Devices lists the connected YubiKeys, sorted by serial. It sends no card
// command for a reader it has seen before, so it is safe to call every
// second.
func (c Cards) Devices() ([]Device, error) {
	list, err := c.List()
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(list))
	for _, d := range list {
		out = append(out, Device{Serial: d.Serial, Firmware: d.Firmware, Supported: d.Supported})
	}
	slices.SortFunc(out, func(a, b Device) int { return int(int64(a.Serial) - int64(b.Serial)) })
	return out, nil
}

// noPIN answers a provider that asks for the PIN: reading a public key never
// needs it.
func noPIN(int) (string, error) { return "", keyprovider.ErrPINRequired }

// Inspect reads which slots of a card are free, which keys it holds and
// whether it is factory-fresh. A slot holding something Latchwire cannot use
// counts as neither.
func (c Cards) Inspect(serial uint32) (CardInfo, error) {
	card, err := c.Open(serial)
	if err != nil {
		return CardInfo{}, err
	}
	defer card.Close()
	var info CardInfo
	if info.Fresh, err = card.Fresh(); err != nil {
		return CardInfo{}, err
	}
	for s := uint8(keyref.MinSlot); s <= keyref.MaxSlot; s++ {
		occ, err := card.Occupied(s)
		if err != nil {
			return CardInfo{}, err
		}
		if !occ {
			info.FreeSlots = append(info.FreeSlots, s)
			continue
		}
		ref := keyref.Ref{Serial: serial, Slot: s}
		p, err := card.Provider(ref, noPIN)
		if err != nil {
			continue
		}
		info.Keys = append(info.Keys, Key{Ref: ref, Public: p.PublicKey()})
		if cl, ok := p.(io.Closer); ok {
			cl.Close()
		}
	}
	return info, nil
}

// FreshSecrets are what securing a factory-fresh card needs. The Asker hands
// over the slices; Keygen wipes them.
type FreshSecrets struct {
	CurrentPUK, NewPIN, NewPUK []byte
}

// Asker collects secrets from the user. Each call returns ErrCancelled when
// the user gives up. Keygen wipes what it gets.
type Asker interface {
	// PIN asks for the card's PIN. retries is how many attempts are left;
	// with 1 the form warns that this is the last.
	PIN(serial uint32, retries int) ([]byte, error)
	// Fresh explains why the card must be secured and asks for the current
	// PUK and a new PIN and PUK.
	Fresh(serial uint32) (FreshSecrets, error)
	// ManagementKey asks for a custom management key in hexadecimal.
	ManagementKey(serial uint32) ([]byte, error)
}

// Keygen creates a key in an empty slot (0 = the first empty one). It never
// sets Force: replacing a key stays a deliberate step of the command line
// (spec §5.4).
func (c Cards) Keygen(serial uint32, slot uint8, a Asker) (Key, error) {
	card, err := c.Open(serial)
	if err != nil {
		return Key{}, err
	}
	defer card.Close()

	retries, err := card.PINRetries()
	if err != nil {
		return Key{}, err
	}
	if retries <= 0 {
		return Key{}, errors.New(msg.AgentPINBlocked)
	}
	pin, err := a.PIN(serial, retries)
	if err != nil {
		return Key{}, err
	}
	defer clear(pin)
	if len(pin) == 0 {
		return Key{}, errors.New(msg.PIVEmptyPIN)
	}

	o := piv.GenerateOptions{Slot: slot, PIN: string(pin)}
	ref, pub, err := card.Generate(o)
	if errors.Is(err, piv.ErrFreshCard) {
		fs, aerr := a.Fresh(serial)
		if aerr != nil {
			return Key{}, aerr
		}
		defer wipe(fs)
		o.CurrentPUK, o.NewPIN, o.NewPUK = string(fs.CurrentPUK), string(fs.NewPIN), string(fs.NewPUK)
		ref, pub, err = card.Generate(o)
		if errors.Is(err, piv.ErrFreshCard) {
			return Key{}, errors.New(msg.KeygenFreshRejected)
		}
	}
	if errors.Is(err, piv.ErrManagementKeyRequired) {
		mk, aerr := askManagementKey(a, serial)
		if aerr != nil {
			return Key{}, aerr
		}
		o.ManagementKey = mk
		ref, pub, err = card.Generate(o)
		clear(mk)
		if errors.Is(err, piv.ErrManagementKeyRequired) {
			return Key{}, errors.New(msg.KeygenManagementKeyRejected)
		}
	}
	if err != nil {
		var pe *keyprovider.PINError
		switch {
		case errors.As(err, &pe):
			return Key{}, fmt.Errorf(msg.AgentWrongPINFmt, pe.RetriesLeft)
		case errors.Is(err, keyprovider.ErrPINBlocked):
			return Key{}, errors.New(msg.AgentPINBlocked)
		}
		return Key{}, err
	}
	return Key{Ref: ref, Public: pub}, nil
}

func wipe(f FreshSecrets) {
	clear(f.CurrentPUK)
	clear(f.NewPIN)
	clear(f.NewPUK)
}

// askManagementKey decodes the hexadecimal answer. Only AES-128, 3DES/AES-192
// and AES-256 lengths are accepted. Errors never contain the input.
func askManagementKey(a Asker, serial uint32) ([]byte, error) {
	src, err := a.ManagementKey(serial)
	if err != nil {
		return nil, err
	}
	defer clear(src)
	switch len(src) {
	case 32, 48, 64:
	default:
		return nil, errors.New(msg.KeygenBadManagementKey)
	}
	mk := make([]byte, len(src)/2)
	if _, err := hex.Decode(mk, src); err != nil {
		clear(mk)
		return nil, errors.New(msg.KeygenBadManagementKey)
	}
	return mk, nil
}
