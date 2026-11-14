package desktop

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/piv"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

const serial = 40727512

type fakeProvider struct{ pub [32]byte }

func (p fakeProvider) PublicKey() [32]byte { return p.pub }
func (p fakeProvider) X25519(context.Context, [32]byte) ([32]byte, error) {
	return [32]byte{}, errors.New("no")
}
func (p fakeProvider) Describe() keyprovider.Description { return keyprovider.Description{} }

// fakeCard records what reaches the card.
type fakeCard struct {
	occupied map[uint8]bool
	unusable map[uint8]bool
	retries  int
	results  []error // of successive Generate calls
	opts     []piv.GenerateOptions
	closed   int
	fresh    bool
}

func (c *fakeCard) Generate(o piv.GenerateOptions) (keyref.Ref, [32]byte, error) {
	c.opts = append(c.opts, o)
	if len(c.results) > 0 {
		err := c.results[0]
		c.results = c.results[1:]
		if err != nil {
			return keyref.Ref{}, [32]byte{}, err
		}
	}
	return keyref.Ref{Serial: serial, Slot: 0x82}, [32]byte{9}, nil
}
func (c *fakeCard) Provider(ref keyref.Ref, prompt func(int) (string, error)) (keyprovider.Provider, error) {
	if c.unusable[ref.Slot] {
		return nil, piv.ErrImportedKey
	}
	if _, err := prompt(3); !errors.Is(err, keyprovider.ErrPINRequired) {
		panic("a PIN prompt answered")
	}
	return fakeProvider{[32]byte{ref.Slot}}, nil
}
func (c *fakeCard) Occupied(s uint8) (bool, error) { return c.occupied[s], nil }
func (c *fakeCard) PINRetries() (int, error)       { return c.retries, nil }
func (c *fakeCard) Fresh() (bool, error)           { return c.fresh, nil }
func (c *fakeCard) Close() error                   { c.closed++; return nil }

func cards(c *fakeCard) Cards {
	return Cards{Open: func(uint32) (CardOps, error) { return c, nil }}
}

// asker hands out fresh slices and keeps them to check that they get wiped.
type asker struct {
	pin, puk, newPIN, newPUK, mk string
	cancelPIN                    bool
	freshAsked, mkAsked          int
	retriesSeen                  int
	given                        [][]byte
}

func (a *asker) keep(s string) []byte {
	b := []byte(s)
	a.given = append(a.given, b)
	return b
}
func (a *asker) PIN(_ uint32, retries int) ([]byte, error) {
	a.retriesSeen = retries
	if a.cancelPIN {
		return nil, ErrCancelled
	}
	return a.keep(a.pin), nil
}
func (a *asker) Fresh(uint32) (FreshSecrets, error) {
	a.freshAsked++
	return FreshSecrets{a.keep(a.puk), a.keep(a.newPIN), a.keep(a.newPUK)}, nil
}
func (a *asker) ManagementKey(uint32) ([]byte, error) {
	a.mkAsked++
	return a.keep(a.mk), nil
}
func (a *asker) assertWiped(t *testing.T) {
	t.Helper()
	for _, b := range a.given {
		for _, x := range b {
			if x != 0 {
				t.Fatalf("a secret was not wiped: %d bytes left", len(b))
			}
		}
	}
}

func TestInspectReadOnly(t *testing.T) {
	c := &fakeCard{occupied: map[uint8]bool{0x82: true, 0x83: true}, unusable: map[uint8]bool{0x83: true}}
	info, err := cards(c).Inspect(serial)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Keys) != 1 || info.Keys[0].Ref.Slot != 0x82 {
		t.Fatalf("keys %+v", info.Keys)
	}
	if len(info.FreeSlots) != 18 || info.FreeSlots[0] != 0x84 {
		t.Fatalf("free %x", info.FreeSlots)
	}
	if len(c.opts) != 0 {
		t.Fatal("Inspect called Generate")
	}
	if c.closed != 1 {
		t.Fatal("card not closed")
	}
}

func TestGenerateNeverForces(t *testing.T) {
	c := &fakeCard{retries: 3}
	a := &asker{pin: "123456"}
	k, err := cards(c).Keygen(serial, 0x85, a)
	if err != nil {
		t.Fatal(err)
	}
	if k.Ref.Slot != 0x82 {
		t.Fatalf("key %+v", k)
	}
	if len(c.opts) != 1 || c.opts[0].Force || c.opts[0].Slot != 0x85 || c.opts[0].PIN != "123456" {
		t.Fatalf("opts %+v", c.opts)
	}
	if a.retriesSeen != 3 {
		t.Fatal(a.retriesSeen)
	}
	a.assertWiped(t)
}

func TestSlotOccupiedIsAnError(t *testing.T) {
	c := &fakeCard{retries: 3, results: []error{piv.ErrSlotOccupied}}
	if _, err := cards(c).Keygen(serial, 0x82, &asker{pin: "123456"}); !errors.Is(err, piv.ErrSlotOccupied) {
		t.Fatal(err)
	}
	if len(c.opts) != 1 {
		t.Fatal("retried")
	}
}

func TestBlockedPINIsNeverAsked(t *testing.T) {
	c := &fakeCard{retries: 0}
	a := &asker{pin: "123456"}
	_, err := cards(c).Keygen(serial, 0, a)
	if err == nil || err.Error() != msg.AgentPINBlocked {
		t.Fatal(err)
	}
	if a.retriesSeen != 0 || len(c.opts) != 0 {
		t.Fatal("asked or sent")
	}
}

func TestCancelTouchesNothing(t *testing.T) {
	c := &fakeCard{retries: 3}
	if _, err := cards(c).Keygen(serial, 0, &asker{cancelPIN: true}); !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
	if len(c.opts) != 0 {
		t.Fatal("sent")
	}
}

func TestEmptyPINRefused(t *testing.T) {
	c := &fakeCard{retries: 3}
	if _, err := cards(c).Keygen(serial, 0, &asker{}); err == nil || err.Error() != msg.PIVEmptyPIN {
		t.Fatal(err)
	}
}

func TestWrongPIN(t *testing.T) {
	c := &fakeCard{retries: 3, results: []error{&keyprovider.PINError{RetriesLeft: 2}}}
	a := &asker{pin: "000000"}
	_, err := cards(c).Keygen(serial, 0, a)
	if err == nil || !strings.Contains(err.Error(), "2 attempts") {
		t.Fatal(err)
	}
	if len(c.opts) != 1 {
		t.Fatal("a wrong PIN must not be retried")
	}
	a.assertWiped(t)
}

func TestFreshCardNeedsAllSecrets(t *testing.T) {
	c := &fakeCard{retries: 3, results: []error{piv.ErrFreshCard, nil}}
	a := &asker{pin: "123456", puk: "12345678", newPIN: "654321", newPUK: "87654321"}
	if _, err := cards(c).Keygen(serial, 0, a); err != nil {
		t.Fatal(err)
	}
	if a.freshAsked != 1 || len(c.opts) != 2 {
		t.Fatal(a.freshAsked, len(c.opts))
	}
	o := c.opts[1]
	if o.CurrentPUK != "12345678" || o.NewPIN != "654321" || o.NewPUK != "87654321" || o.PIN != "123456" || o.Force {
		t.Fatalf("%+v", o)
	}
	a.assertWiped(t)
}

func TestFreshRejected(t *testing.T) {
	c := &fakeCard{retries: 3, results: []error{piv.ErrFreshCard, piv.ErrFreshCard}}
	a := &asker{pin: "123456", puk: "1", newPIN: "2", newPUK: "3"}
	if _, err := cards(c).Keygen(serial, 0, a); err == nil || err.Error() != msg.KeygenFreshRejected {
		t.Fatal(err)
	}
}

func TestManagementKey(t *testing.T) {
	c := &fakeCard{retries: 3, results: []error{piv.ErrManagementKeyRequired, nil}}
	a := &asker{pin: "123456", mk: strings.Repeat("ab", 16)}
	if _, err := cards(c).Keygen(serial, 0, a); err != nil {
		t.Fatal(err)
	}
	a.assertWiped(t)
}

func TestManagementKeyBadInputNeverEchoed(t *testing.T) {
	for _, in := range []string{"short", strings.Repeat("zz", 16)} {
		c := &fakeCard{retries: 3, results: []error{piv.ErrManagementKeyRequired}}
		_, err := cards(c).Keygen(serial, 0, &asker{pin: "123456", mk: in})
		if err == nil || err.Error() != msg.KeygenBadManagementKey {
			t.Fatal(err)
		}
		if strings.Contains(err.Error(), in) {
			t.Fatal("input echoed")
		}
	}
}

func TestManagementKeyRejected(t *testing.T) {
	c := &fakeCard{retries: 3, results: []error{piv.ErrManagementKeyRequired, piv.ErrManagementKeyRequired}}
	a := &asker{pin: "123456", mk: strings.Repeat("ab", 16)}
	if _, err := cards(c).Keygen(serial, 0, a); err == nil || err.Error() != msg.KeygenManagementKeyRejected {
		t.Fatal(err)
	}
}

func TestInspectReportsFresh(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		c := &fakeCard{fresh: fresh}
		info, err := cards(c).Inspect(serial)
		if err != nil || info.Fresh != fresh {
			t.Fatalf("Fresh = %v, %v; want %v", info.Fresh, err, fresh)
		}
	}
}
