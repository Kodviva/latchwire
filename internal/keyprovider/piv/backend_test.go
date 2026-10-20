package piv

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
)

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
