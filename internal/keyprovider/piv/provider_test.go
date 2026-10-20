package piv

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
)

func randPeer(t *testing.T) (*ecdh.PrivateKey, [32]byte) {
	t.Helper()
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return e, [32]byte(e.PublicKey().Bytes())
}

type promptRec struct {
	pins    []string
	retries []int
	err     error
}

func (p *promptRec) fn(retries int) (string, error) {
	p.retries = append(p.retries, retries)
	if p.err != nil {
		return "", p.err
	}
	if len(p.pins) == 0 {
		return "", errors.New("no more PINs")
	}
	pin := p.pins[0]
	p.pins = p.pins[1:]
	return pin, nil
}

func newProvider(t *testing.T, f *fakeCard, slot uint8, pr *promptRec) keyprovider.Provider {
	t.Helper()
	c := mustCard(t, f)
	p, err := c.Provider(keyref.Ref{Serial: f.serial, Slot: slot}, pr.fn)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProviderRejectsImportedKey(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	ki := f.slots[0x82]
	ki.Origin = piv.OriginImported
	f.slots[0x82] = ki
	c := mustCard(t, f)
	_, err := c.Provider(keyref.Ref{Serial: testSerial, Slot: 0x82}, (&promptRec{}).fn)
	if !errors.Is(err, ErrImportedKey) {
		t.Fatalf("err = %v, want ErrImportedKey", err)
	}
}

func TestProviderRejectsNonX25519(t *testing.T) {
	f := newFakeCard(t, testSerial)
	sk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.occupy(0x82, piv.KeyInfo{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyNever,
		Origin:      piv.OriginGenerated,
		PublicKey:   sk.PublicKey(),
	})
	c := mustCard(t, f)
	_, err = c.Provider(keyref.Ref{Serial: testSerial, Slot: 0x82}, (&promptRec{}).fn)
	if !errors.Is(err, ErrNotX25519) {
		t.Fatalf("err = %v, want ErrNotX25519", err)
	}
}

func TestProviderRejectsEmptySlot(t *testing.T) {
	f := newFakeCard(t, testSerial)
	c := mustCard(t, f)
	_, err := c.Provider(keyref.Ref{Serial: testSerial, Slot: 0x85}, (&promptRec{}).fn)
	if !errors.Is(err, ErrSlotEmpty) {
		t.Fatalf("err = %v, want ErrSlotEmpty", err)
	}
}

func TestProviderRejectsOtherSerialAndSlot(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	c := mustCard(t, f)
	if _, err := c.Provider(keyref.Ref{Serial: testSerial + 1, Slot: 0x82}, (&promptRec{}).fn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other serial: err = %v, want ErrNotFound", err)
	}
	for _, s := range []uint8{0x9a, 0x9d, 0x81, 0x96} {
		if _, err := c.Provider(keyref.Ref{Serial: testSerial, Slot: s}, (&promptRec{}).fn); err == nil {
			t.Fatalf("slot %#x accepted", s)
		}
	}
}

func TestProviderX25519MatchesSoftware(t *testing.T) {
	f := newFakeCard(t, testSerial)
	sk := f.occupyX25519(0x83)
	pr := &promptRec{pins: []string{f.pin}}
	p := newProvider(t, f, 0x83, pr)

	if got := p.PublicKey(); got != [32]byte(sk.PublicKey().Bytes()) {
		t.Fatal("PublicKey does not match the slot")
	}
	d := p.Describe()
	if d.Kind != "yubikey-piv" || d.Serial != testSerial || d.Slot != 0x83 || d.Tier != keyprovider.Tier1 {
		t.Fatalf("Describe = %+v", d)
	}

	for i := 0; i < 3; i++ {
		e, epub := randPeer(t)
		got, err := p.X25519(context.Background(), epub)
		if err != nil {
			t.Fatal(err)
		}
		cardPub := p.PublicKey()
		pubKey, _ := ecdh.X25519().NewPublicKey(cardPub[:])
		want, err := e.ECDH(pubKey)
		if err != nil {
			t.Fatal(err)
		}
		if got != [32]byte(want) {
			t.Fatal("card X25519 differs from software X25519")
		}
	}
	// PINPolicyOnce: one prompt for the whole session.
	if len(pr.retries) != 1 || pr.retries[0] != 3 {
		t.Fatalf("prompt calls (retries shown) = %v, want [3]", pr.retries)
	}
}

func TestProviderWrongPIN(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	pr := &promptRec{pins: []string{"000000", f.pin}}
	p := newProvider(t, f, 0x82, pr)
	_, peer := randPeer(t)

	_, err := p.X25519(context.Background(), peer)
	var pe *keyprovider.PINError
	if !errors.As(err, &pe) || pe.RetriesLeft != 2 {
		t.Fatalf("err = %v, want *PINError{2}", err)
	}
	// The provider never retries by itself.
	if len(pr.retries) != 1 {
		t.Fatalf("prompted %d times, want 1", len(pr.retries))
	}
	if _, err := p.X25519(context.Background(), peer); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if len(pr.retries) != 2 || pr.retries[1] != 2 {
		t.Fatalf("retries shown = %v, want [3 2]", pr.retries)
	}
}

func TestProviderBlockedPINNeverPrompts(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	pr := &promptRec{pins: []string{f.pin}}
	p := newProvider(t, f, 0x82, pr)
	f.pinRetries = 0
	_, peer := randPeer(t)
	_, err := p.X25519(context.Background(), peer)
	if !errors.Is(err, keyprovider.ErrPINBlocked) {
		t.Fatalf("err = %v, want ErrPINBlocked", err)
	}
	if len(pr.retries) != 0 {
		t.Fatalf("prompted %d times with a blocked PIN", len(pr.retries))
	}
}

func TestProviderLastWrongPINBlocks(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	f.pinRetries = 1
	pr := &promptRec{pins: []string{"000000"}}
	p := newProvider(t, f, 0x82, pr)
	_, peer := randPeer(t)
	_, err := p.X25519(context.Background(), peer)
	if !errors.Is(err, keyprovider.ErrPINBlocked) {
		t.Fatalf("err = %v, want ErrPINBlocked", err)
	}
}

func TestProviderPromptErrorIsPINRequired(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	cancelled := errors.New("user cancelled")
	pr := &promptRec{err: cancelled}
	p := newProvider(t, f, 0x82, pr)
	_, peer := randPeer(t)
	_, err := p.X25519(context.Background(), peer)
	if !errors.Is(err, keyprovider.ErrPINRequired) || !errors.Is(err, cancelled) {
		t.Fatalf("err = %v, want ErrPINRequired wrapping the prompt error", err)
	}
}

func TestProviderSecurityStatusIsPINRequired(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	p := newProvider(t, f, 0x82, &promptRec{pins: []string{f.pin}})
	f.ecdhErr = &fakeAPDUErr{0x6982}
	_, peer := randPeer(t)
	_, err := p.X25519(context.Background(), peer)
	if !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("err = %v, want ErrPINRequired", err)
	}
}

func TestProviderRemovedCardIsUnavailable(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	p := newProvider(t, f, 0x82, &promptRec{pins: []string{f.pin}})
	f.ecdhErr = errRemoved
	_, peer := randPeer(t)
	_, err := p.X25519(context.Background(), peer)
	if !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestProviderOtherCardErrorIsNotUnavailable(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	p := newProvider(t, f, 0x82, &promptRec{pins: []string{f.pin}})
	f.ecdhErr = &fakeAPDUErr{0x6a80}
	_, peer := randPeer(t)
	_, err := p.X25519(context.Background(), peer)
	if err == nil || errors.Is(err, keyprovider.ErrUnavailable) || errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("err = %v, want a plain card error", err)
	}
}

func TestProviderLowOrderPoint(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	p := newProvider(t, f, 0x82, &promptRec{pins: []string{f.pin}})
	var zero [32]byte // the identity, a low-order point
	one := [32]byte{1}
	for _, peer := range [][32]byte{zero, one} {
		if _, err := p.X25519(context.Background(), peer); !errors.Is(err, keyprovider.ErrLowOrderPoint) {
			t.Fatalf("err = %v, want ErrLowOrderPoint", err)
		}
	}
	if f.ecdhN != 0 {
		t.Fatalf("card used %d times for a low-order point", f.ecdhN)
	}
	// A card that returns zeros is also caught.
	f.ecdhZero = true
	_, peer := randPeer(t)
	if _, err := p.X25519(context.Background(), peer); !errors.Is(err, keyprovider.ErrLowOrderPoint) {
		t.Fatalf("zero output: err = %v, want ErrLowOrderPoint", err)
	}
}

func TestProviderHonoursContext(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	p := newProvider(t, f, 0x82, &promptRec{pins: []string{f.pin}})
	_, peer := randPeer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.X25519(ctx, peer); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if f.ecdhN != 0 {
		t.Fatal("card used with a cancelled context")
	}

	// While another operation holds the card, a caller with a deadline
	// gives up instead of waiting forever.
	pp := p.(*provider)
	pp.sem <- struct{}{}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := p.X25519(ctx, peer); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("X25519 waited far past its deadline")
	}
	<-pp.sem
}

func TestProviderClose(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	p := newProvider(t, f, 0x82, &promptRec{})
	c, ok := p.(io.Closer)
	if !ok {
		t.Fatal("provider does not implement io.Closer")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
