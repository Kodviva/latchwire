package piv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
)

// The agent drives cards through this backend.
var _ agent.Backend = Backend{}

const (
	readerA     = "Yubico YubiKey OTP+FIDO+CCID 00 00"
	readerB     = "Yubico YubiKey OTP+FIDO+CCID 01 00"
	readerOther = "Generic Smart Card Reader Interface"
)

func twoCards(t *testing.T) (*fakeSystem, *fakeCard, *fakeCard) {
	a := newFakeCard(t, 40727512)
	b := newFakeCard(t, 40727513)
	s := &fakeSystem{
		readers: []string{readerOther, readerA, readerB},
		cards:   map[string]*fakeCard{readerA: a, readerB: b},
	}
	useSystem(t, s)
	return s, a, b
}

func TestOpenSelectsBySerial(t *testing.T) {
	s, a, b := twoCards(t)
	c, err := Open(40727513)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Serial() != 40727513 || c.Reader() != readerB {
		t.Fatalf("opened serial %d on %q, want 40727513 on %q", c.Serial(), c.Reader(), readerB)
	}
	if !a.closed {
		t.Fatal("first card was left open")
	}
	if b.closed {
		t.Fatal("selected card was closed")
	}
	if slices.Contains(s.opened, readerOther) {
		t.Fatal("non-YubiKey reader was opened")
	}
}

func TestOpenNotFound(t *testing.T) {
	twoCards(t)
	if _, err := Open(1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestList(t *testing.T) {
	_, a, _ := twoCards(t)
	a.version = piv.Version{Major: 5, Minor: 4, Patch: 3}
	devs, err := List()
	if err != nil {
		t.Fatal(err)
	}
	want := []Device{
		{Serial: 40727512, Firmware: "5.4.3", Reader: readerA, Supported: false},
		{Serial: 40727513, Firmware: "5.7.1", Reader: readerB, Supported: true},
	}
	if !slices.Equal(devs, want) {
		t.Fatalf("List = %+v, want %+v", devs, want)
	}
}

func TestBackendSerialsWhileProviderOpen(t *testing.T) {
	s, a, b := twoCards(t)
	a.occupyX25519(0x82)
	var be Backend
	p, err := be.Provider(keyref.Ref{Serial: a.serial, Slot: 0x82}, (&promptRec{pins: []string{a.pin}}).fn)
	if err != nil {
		t.Fatal(err)
	}
	// Presence polling must not send commands to held cards or reopen
	// readers already seen.
	if _, err := be.Serials(); err != nil {
		t.Fatal(err)
	}
	opened, aSerial, bSerial := len(s.opened), a.callCount("Serial"), b.callCount("Serial")
	for i := 0; i < 3; i++ {
		serials, err := be.Serials()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(serials, []uint32{a.serial, b.serial}) {
			t.Fatalf("Serials = %v, want both cards", serials)
		}
	}
	if len(s.opened) != opened || a.callCount("Serial") != aSerial || b.callCount("Serial") != bSerial {
		t.Fatalf("polling touched cards: opened %d->%d, Serial calls A %d->%d B %d->%d",
			opened, len(s.opened), aSerial, a.callCount("Serial"), bSerial, b.callCount("Serial"))
	}

	// A provider for the other card must not reopen (and so disturb) the
	// card already held.
	b.occupyX25519(0x82)
	pb, err := be.Provider(keyref.Ref{Serial: b.serial, Slot: 0x82}, (&promptRec{pins: []string{b.pin}}).fn)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(s.opened[len(s.opened)-2:], readerA) {
		t.Fatal("held card was reopened while looking for another serial")
	}
	_ = pb.(io.Closer).Close()

	// A second provider on the same card shares the connection.
	a.occupyX25519(0x83)
	p2, err := be.Provider(keyref.Ref{Serial: a.serial, Slot: 0x83}, (&promptRec{pins: []string{a.pin}}).fn)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.(io.Closer).Close()
	if a.closed {
		t.Fatal("card closed while another provider still uses it")
	}
	_ = p2.(io.Closer).Close()
	if !a.closed {
		t.Fatal("card left open after its last provider closed")
	}
}

func TestBackendCardRemovedAndReinserted(t *testing.T) {
	s, a, b := twoCards(t)
	a.occupyX25519(0x82)
	var be Backend
	p, err := be.Provider(keyref.Ref{Serial: a.serial, Slot: 0x82}, (&promptRec{pins: []string{a.pin}}).fn)
	if err != nil {
		t.Fatal(err)
	}

	// Pull the card out: the open handle dies.
	a.closed = true
	a.ecdhErr = errRemoved
	s.readers = []string{readerB}
	delete(s.cards, readerA)

	serials, err := be.Serials()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(serials, []uint32{b.serial}) {
		t.Fatalf("Serials after removal = %v", serials)
	}
	_, peer := randPeer(t)
	if _, err := p.X25519(context.Background(), peer); !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("X25519 after removal: err = %v, want ErrUnavailable", err)
	}

	// Plug it back in: a new provider opens a fresh connection.
	a.ecdhErr = nil
	s.readers = []string{readerA, readerB}
	s.cards[readerA] = a
	serials, err = be.Serials()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(serials, []uint32{a.serial, b.serial}) {
		t.Fatalf("Serials after reinsertion = %v", serials)
	}
	p2, err := be.Provider(keyref.Ref{Serial: a.serial, Slot: 0x82}, (&promptRec{pins: []string{a.pin}}).fn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.X25519(context.Background(), peer); err != nil {
		t.Fatalf("X25519 after reinsertion: %v", err)
	}
	_ = p.(io.Closer).Close()
	_ = p2.(io.Closer).Close()
}

func TestSerialsOpensEachReaderOnce(t *testing.T) {
	s, _, _ := twoCards(t)
	var be Backend
	for i := 0; i < 5; i++ {
		if _, err := be.Serials(); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(s.opened, []string{readerA, readerB}) {
		t.Fatalf("opened %v, want each YubiKey reader exactly once", s.opened)
	}
	// A reader that disappears and comes back is read again.
	s.readers = []string{readerB}
	if _, err := be.Serials(); err != nil {
		t.Fatal(err)
	}
	s.readers = []string{readerA, readerB}
	if _, err := be.Serials(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.opened, []string{readerA, readerB, readerA}) {
		t.Fatalf("opened %v after reinsertion", s.opened)
	}
}

func TestProbeClassification(t *testing.T) {
	if err := probeResult(errors.New("unsupported algorithm")); err != nil {
		t.Fatalf("authenticated probe reported %v", err)
	}
	for _, e := range []error{
		errors.New("authenticating with management key: smart card error 6982"),
		errors.New("authenticating with management key: invalid management key length: 32 bytes (expected 24)"),
		nil, // a probe that "succeeds" generated something: never treat as authenticated
	} {
		if err := probeResult(e); err == nil {
			t.Fatalf("probeResult(%v) = nil, want error", e)
		}
	}
}

// A card pulled out and put back between two polls leaves the reader list
// unchanged, but the held connection is dead. The first operation that sees
// the transport error must drop the shared connection and the cached serial,
// so the next Serials and Provider calls open the reader again (Ruling R16).
func TestBackendDropsConnectionOnTransportError(t *testing.T) {
	s, a, _ := twoCards(t)
	a.occupyX25519(0x82)
	var be Backend
	ref := keyref.Ref{Serial: a.serial, Slot: 0x82}
	p, err := be.Provider(ref, (&promptRec{pins: []string{a.pin}}).fn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.(io.Closer).Close()
	_, peer := randPeer(t)
	if _, err := p.X25519(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Serials(); err != nil {
		t.Fatal(err)
	}

	a.handleDead = true // re-seated: same reader name, dead handle
	if _, err := p.X25519(context.Background(), peer); !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("X25519 on dead handle: err = %v, want ErrUnavailable", err)
	}

	opened := len(s.opened)
	serials, err := be.Serials()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(serials, a.serial) {
		t.Fatalf("Serials = %v, want card A", serials)
	}
	if !slices.Contains(s.opened[opened:], readerA) {
		t.Fatal("Serials did not reopen the reader whose connection failed")
	}

	p2, err := be.Provider(ref, (&promptRec{pins: []string{a.pin}}).fn)
	if err != nil {
		t.Fatalf("Provider after re-seat: %v", err)
	}
	defer p2.(io.Closer).Close()
	if _, err := p2.X25519(context.Background(), peer); err != nil {
		t.Fatalf("X25519 after re-seat: %v", err)
	}
}

// A transport error while making a provider on a reused connection drops it
// too.
func TestBackendDropsConnectionOnProviderTransportError(t *testing.T) {
	_, a, _ := twoCards(t)
	a.occupyX25519(0x82)
	a.occupyX25519(0x83)
	var be Backend
	p, err := be.Provider(keyref.Ref{Serial: a.serial, Slot: 0x82}, (&promptRec{}).fn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.(io.Closer).Close()

	a.handleDead = true
	ref83 := keyref.Ref{Serial: a.serial, Slot: 0x83}
	if _, err := be.Provider(ref83, (&promptRec{}).fn); !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("Provider on dead handle: err = %v, want ErrUnavailable", err)
	}
	p2, err := be.Provider(ref83, (&promptRec{}).fn)
	if err != nil {
		t.Fatalf("second Provider after transport error: %v", err)
	}
	_ = p2.(io.Closer).Close()
}

// The vendored piv-go refuses to go on when the card answering after a reset
// has another serial; the backend treats that as the card being gone.
func TestBackendCardChangedIsUnavailable(t *testing.T) {
	s, a, _ := twoCards(t)
	a.occupyX25519(0x82)
	var be Backend
	ref := keyref.Ref{Serial: a.serial, Slot: 0x82}
	pr := &promptRec{pins: []string{a.pin}}
	p, err := be.Provider(ref, pr.fn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.(io.Closer).Close()
	_, peer := randPeer(t)
	if _, err := p.X25519(context.Background(), peer); err != nil {
		t.Fatal(err)
	}

	a.ecdhErr = fmt.Errorf("checking card after reset: %w", piv.ErrCardChanged)
	if _, err := p.X25519(context.Background(), peer); !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("X25519 with changed card: err = %v, want ErrUnavailable", err)
	}
	if len(pr.retries) != 1 {
		t.Fatalf("prompted %d times, want only the first PIN", len(pr.retries))
	}
	a.ecdhErr = nil
	opened := len(s.opened)
	p2, err := be.Provider(ref, (&promptRec{pins: []string{a.pin}}).fn)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.(io.Closer).Close()
	if !slices.Contains(s.opened[opened:], readerA) {
		t.Fatal("Provider reused the connection to the changed card")
	}
}

// A reader that opens but whose serial cannot be read is retried at most
// every 10 seconds, not on every poll.
func TestSerialsNegativeCache(t *testing.T) {
	s, a, b := twoCards(t)
	a.serialErr = errors.New("smart card command: timeout")
	clock := time.Unix(1000, 0)
	oldNow := now
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = oldNow })

	var be Backend
	countA := func() int {
		n := 0
		for _, r := range s.opened {
			if r == readerA {
				n++
			}
		}
		return n
	}
	for i := 0; i < 5; i++ {
		serials, err := be.Serials()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(serials, []uint32{b.serial}) {
			t.Fatalf("Serials = %v, want only card B", serials)
		}
		clock = clock.Add(time.Second)
	}
	if n := countA(); n != 1 {
		t.Fatalf("reader with failing serial opened %d times in 5 s, want 1", n)
	}

	clock = clock.Add(5 * time.Second) // 10 s after the failure
	a.serialErr = nil
	serials, err := be.Serials()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(serials, []uint32{a.serial, b.serial}) {
		t.Fatalf("Serials after 10 s = %v, want both cards", serials)
	}
	if n := countA(); n != 2 {
		t.Fatalf("reader opened %d times, want a retry after 10 s", n)
	}

	// A reader that disappears and comes back is retried at once.
	a.serialErr = errors.New("smart card command: timeout")
	s.readers = []string{readerB}
	if _, err := be.Serials(); err != nil {
		t.Fatal(err)
	}
	s.readers = []string{readerA, readerB}
	if _, err := be.Serials(); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Serials(); err != nil {
		t.Fatal(err)
	}
	if n := countA(); n != 3 {
		t.Fatalf("reader opened %d times after reinsertion, want exactly one more", n)
	}
}
