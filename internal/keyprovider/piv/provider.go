package piv

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"sync"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/curve25519"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Kind is the keyprovider.Description kind of this backend.
const Kind = "yubikey-piv"

// swSecurityStatusNotSatisfied is the card's answer when the PIN
// verification it needs is missing (for example lost after another program
// used the card).
const swSecurityStatusNotSatisfied = 0x6982

// ecdher is what *piv.X25519PrivateKey offers.
type ecdher interface {
	ECDH(peer *ecdh.PublicKey) ([]byte, error)
}

// provider is a keyprovider.Provider backed by a card slot.
type provider struct {
	card   *Card
	sem    chan struct{} // the card's; shared by everything using the card
	key    ecdher
	pub    [32]byte
	desc   keyprovider.Description
	prompt func(retriesLeft int) (string, error)

	closeOnce sync.Once
	closer    func() error // set by Backend; nil for Card.Provider
	// onUnavailable is called (without sem) after an operation failed with
	// keyprovider.ErrUnavailable; set by Backend to drop the dead
	// connection so that the card is opened afresh.
	onUnavailable func()

	// Per-operation state, guarded by sem.
	opCtx     context.Context
	promptErr error
}

var _ keyprovider.Provider = (*provider)(nil)

// Provider returns a provider for an existing key in ref's slot. The key
// must be an X25519 key generated on this card with PIN policy once and
// touch policy never (what Generate creates). prompt is asked for the PIN
// only when the card needs it, with the number of retries left; it is never
// called when the PIN is blocked. The PIN is passed straight to the card and
// not kept.
func (c *Card) Provider(ref keyref.Ref, prompt func(retriesLeft int) (string, error)) (keyprovider.Provider, error) {
	if ref.Serial != c.serial {
		return nil, ErrNotFound
	}
	if !retired(ref.Slot) {
		return nil, fmt.Errorf(msg.PIVSlotOutOfRangeFmt, ref.Slot)
	}

	c.sem <- struct{}{}
	defer func() { <-c.sem }()
	if c.closed {
		return nil, keyprovider.ErrUnavailable
	}

	slot := pivSlot(ref.Slot)
	ki, err := c.c.KeyInfo(slot)
	if errors.Is(err, piv.ErrNotFound) {
		return nil, ErrSlotEmpty
	}
	if err != nil {
		return nil, mapCardErr(err)
	}
	if ki.Origin != piv.OriginGenerated {
		return nil, ErrImportedKey
	}
	if ki.Algorithm != piv.AlgorithmX25519 {
		return nil, ErrNotX25519
	}
	ep, ok := ki.PublicKey.(*ecdh.PublicKey)
	if !ok || ep.Curve() != ecdh.X25519() {
		return nil, ErrNotX25519
	}
	if ki.PINPolicy != piv.PINPolicyOnce || ki.TouchPolicy != piv.TouchPolicyNever {
		return nil, ErrUnsupportedPolicy
	}

	p := &provider{
		card:   c,
		sem:    c.sem,
		prompt: prompt,
		desc: keyprovider.Description{
			Kind:   Kind,
			Model:  "YubiKey " + firmwareString(c.version),
			Serial: c.serial,
			Slot:   ref.Slot,
			Tier:   keyprovider.Tier1,
		},
	}
	copy(p.pub[:], ep.Bytes())

	// The PIN policy comes from the card's own metadata, so piv-go does not
	// need to guess it. KeyAuth.PIN stays empty: the PIN is never stored.
	// With PINPolicyOnce the vendored piv-go asks promptPIN only when an
	// empty VERIFY shows the card holds no verified PIN; if verification is
	// lost between that check and the operation, the card answers 6982 and
	// X25519 returns ErrPINRequired (the agent re-prompts once, R2).
	priv, err := c.c.PrivateKey(slot, ep, piv.KeyAuth{PINPolicy: ki.PINPolicy, PINPrompt: p.promptPIN})
	if err != nil {
		return nil, mapCardErr(err)
	}
	k, ok := priv.(ecdher)
	if !ok {
		return nil, ErrNotX25519
	}
	p.key = k
	return p, nil
}

func (p *provider) PublicKey() [32]byte { return p.pub }

func (p *provider) Describe() keyprovider.Description { return p.desc }

// Close releases the provider. For a provider from Backend the card
// connection is closed with its last provider; for one from Card.Provider
// the Card stays open (close the Card).
func (p *provider) Close() error {
	var err error
	p.closeOnce.Do(func() {
		if p.closer != nil {
			err = p.closer()
		}
	})
	return err
}

// lowOrderScalar is a fixed public scalar. After clamping, any scalar is a
// multiple of the cofactor, so X25519 with it yields zero exactly for the
// low-order points; nothing secret is involved in this check.
var lowOrderScalar = [32]byte{9}

func isLowOrder(peer [32]byte) bool {
	_, err := curve25519.X25519(lowOrderScalar[:], peer[:])
	return err != nil
}

// X25519 runs the Diffie-Hellman operation on the card. Waiting for the card
// is abandoned when ctx ends; a card command already sent cannot be
// interrupted and finishes before the card is used again. After a transport
// error (keyprovider.ErrUnavailable) a Backend provider's connection is
// dropped: this provider keeps failing and a new one must be made.
func (p *provider) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	out, err := p.x25519(ctx, peer)
	if errors.Is(err, keyprovider.ErrUnavailable) && p.onUnavailable != nil {
		p.onUnavailable()
	}
	return out, err
}

func (p *provider) x25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	var out [32]byte
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if isLowOrder(peer) {
		return out, keyprovider.ErrLowOrderPoint
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return out, keyprovider.ErrLowOrderPoint
	}

	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return out, ctx.Err()
	}
	defer func() { <-p.sem }()
	if p.card.closed {
		return out, keyprovider.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}

	p.opCtx = ctx
	p.promptErr = nil
	ss, err := p.key.ECDH(peerKey)
	promptErr := p.promptErr
	p.opCtx, p.promptErr = nil, nil
	if err != nil {
		if promptErr != nil {
			return out, promptErr
		}
		return out, mapCardErr(err)
	}
	defer clear(ss)
	if len(ss) != len(out) {
		return out, fmt.Errorf("piv: card returned a %d-byte shared secret", len(ss))
	}
	copy(out[:], ss)
	if out == ([32]byte{}) {
		return [32]byte{}, keyprovider.ErrLowOrderPoint
	}
	return out, nil
}

// promptPIN is piv-go's PINPrompt. piv-go formats prompt errors with %v,
// losing the error chain, so the mapped error is kept in p.promptErr and
// X25519 returns that instead. It runs inside X25519, holding sem.
func (p *provider) promptPIN() (string, error) {
	fail := func(err error) (string, error) {
		p.promptErr = err
		return "", err
	}
	if p.opCtx != nil {
		if err := p.opCtx.Err(); err != nil {
			return fail(fmt.Errorf("%w: %w", keyprovider.ErrPINRequired, err))
		}
	}
	retries, err := p.card.c.Retries()
	if err != nil {
		return fail(mapCardErr(err))
	}
	if retries == 0 {
		return fail(keyprovider.ErrPINBlocked)
	}
	if p.prompt == nil {
		return fail(keyprovider.ErrPINRequired)
	}
	pin, err := p.prompt(retries)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", keyprovider.ErrPINRequired, err))
	}
	if pin == "" {
		return fail(fmt.Errorf("%w: %s", keyprovider.ErrPINRequired, msg.PIVEmptyPIN))
	}
	if len(pin) > maxSecretLen {
		return fail(fmt.Errorf("%w: %s", keyprovider.ErrPINRequired, msg.PIVPINTooLong))
	}
	return pin, nil
}

// statusErr matches piv-go's (unexported) APDU error type.
type statusErr interface{ Status() uint16 }

// mapCardErr turns piv-go errors into keyprovider errors (Ruling R2):
// wrong PIN -> *PINError, blocked PIN -> ErrPINBlocked, security status not
// satisfied -> ErrPINRequired, other card status words -> as is, anything
// else (PC/SC transport: card removed, reader gone; another card in the
// reader after a reset, piv.ErrCardChanged) -> ErrUnavailable.
func mapCardErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, piv.ErrCardChanged) {
		return fmt.Errorf("%w: %w", keyprovider.ErrUnavailable, err)
	}
	var ae piv.AuthErr
	if errors.As(err, &ae) {
		if ae.Retries == 0 {
			return keyprovider.ErrPINBlocked
		}
		return &keyprovider.PINError{RetriesLeft: ae.Retries}
	}
	var se statusErr
	if errors.As(err, &se) {
		if se.Status() == swSecurityStatusNotSatisfied {
			return fmt.Errorf("%w: %w", keyprovider.ErrPINRequired, err)
		}
		return fmt.Errorf("piv: %w", err)
	}
	return fmt.Errorf("%w: %w", keyprovider.ErrUnavailable, err)
}
