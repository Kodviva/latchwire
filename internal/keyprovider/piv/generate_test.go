package piv

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
)

const testSerial = 40727512

func mustCard(t *testing.T, f *fakeCard) *Card {
	t.Helper()
	c, err := newCard(f, "Yubico YubiKey OTP+FIDO+CCID 00 00")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGenerateRejectsOldFirmware(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.version = piv.Version{Major: 5, Minor: 6, Patch: 0}
	c := mustCard(t, f)
	_, _, err := c.Generate(GenerateOptions{PIN: f.pin, ManagementKey: f.mgmtKey})
	if !errors.Is(err, ErrFirmwareTooOld) {
		t.Fatalf("err = %v, want ErrFirmwareTooOld", err)
	}
	if n := f.callCount("GenerateKey"); n != 0 {
		t.Fatalf("GenerateKey called %d times", n)
	}
}

func TestGenerateAutoSlotPicksFirstFree(t *testing.T) {
	f := newFakeCard(t, testSerial).protectMgmt()
	f.occupyX25519(0x82)
	f.occupyX25519(0x83)
	c := mustCard(t, f)
	ref, pub, err := c.Generate(GenerateOptions{PIN: f.pin})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Slot != 0x84 || ref.Serial != testSerial {
		t.Fatalf("ref = %+v, want serial %d slot 0x84", ref, testSerial)
	}
	want := f.slots[0x84].PublicKey.(*ecdh.PublicKey).Bytes()
	if !bytes.Equal(pub[:], want) {
		t.Fatalf("returned public key does not match the generated key")
	}
}

func TestGenerateRefusesOccupiedSlot(t *testing.T) {
	f := newFakeCard(t, testSerial).protectMgmt()
	f.occupyX25519(0x82)
	c := mustCard(t, f)
	_, _, err := c.Generate(GenerateOptions{Slot: 0x82, PIN: f.pin})
	if !errors.Is(err, ErrSlotOccupied) {
		t.Fatalf("err = %v, want ErrSlotOccupied", err)
	}
	if n := f.callCount("GenerateKey"); n != 0 {
		t.Fatalf("GenerateKey called %d times", n)
	}
}

func TestGenerateForceReplacesOccupiedSlot(t *testing.T) {
	f := newFakeCard(t, testSerial).protectMgmt()
	f.occupyX25519(0x82)
	c := mustCard(t, f)
	ref, _, err := c.Generate(GenerateOptions{Slot: 0x82, PIN: f.pin, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Slot != 0x82 {
		t.Fatalf("slot = %#x", ref.Slot)
	}
}

func TestOccupiedReportsSlot(t *testing.T) {
	f := newFakeCard(t, testSerial)
	f.occupyX25519(0x82)
	c := mustCard(t, f)
	if occ, err := c.Occupied(0x82); err != nil || !occ {
		t.Fatalf("Occupied(82) = %v, %v; want true", occ, err)
	}
	if occ, err := c.Occupied(0x83); err != nil || occ {
		t.Fatalf("Occupied(83) = %v, %v; want false", occ, err)
	}
	for _, s := range []uint8{0x9a, 0x81, 0x96} {
		if _, err := c.Occupied(s); err == nil {
			t.Errorf("Occupied(%02x) accepted a non-retired slot", s)
		}
	}
	if n := f.callCount("GenerateKey"); n != 0 {
		t.Fatalf("GenerateKey called %d times", n)
	}
	c.Close()
	if _, err := c.Occupied(0x82); !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("Occupied after Close: %v, want ErrUnavailable", err)
	}
}

func TestGenerateNoFreeSlot(t *testing.T) {
	f := newFakeCard(t, testSerial).protectMgmt()
	for s := uint32(0x82); s <= 0x95; s++ {
		f.occupyX25519(s)
	}
	c := mustCard(t, f)
	_, _, err := c.Generate(GenerateOptions{PIN: f.pin})
	if !errors.Is(err, ErrNoFreeSlot) {
		t.Fatalf("err = %v, want ErrNoFreeSlot", err)
	}
}

func TestGenerateRejectsNonRetiredSlot(t *testing.T) {
	for _, s := range []uint8{0x9a, 0x9c, 0x9d, 0x9e, 0x81, 0x96, 0x9b} {
		f := newFakeCard(t, testSerial).protectMgmt()
		c := mustCard(t, f)
		f.calls = nil
		_, _, err := c.Generate(GenerateOptions{Slot: s, PIN: f.pin, Force: true})
		if err == nil {
			t.Fatalf("slot %#x accepted", s)
		}
		if len(f.calls) != 0 {
			t.Fatalf("slot %#x: card calls %v, want none", s, f.calls)
		}
	}
}

func TestGenerateUsesPolicies(t *testing.T) {
	f := newFakeCard(t, testSerial).protectMgmt()
	c := mustCard(t, f)
	if _, _, err := c.Generate(GenerateOptions{PIN: f.pin}); err != nil {
		t.Fatal(err)
	}
	want := piv.Key{Algorithm: piv.AlgorithmX25519, PINPolicy: piv.PINPolicyOnce, TouchPolicy: piv.TouchPolicyNever}
	if len(f.genOpts) != 1 || f.genOpts[0] != want {
		t.Fatalf("GenerateKey opts = %+v, want [%+v]", f.genOpts, want)
	}
}

func TestGenerateUsesGivenManagementKey(t *testing.T) {
	f := newFakeCard(t, testSerial) // management key not stored on the card
	c := mustCard(t, f)
	if _, _, err := c.Generate(GenerateOptions{ManagementKey: f.mgmtKey}); err != nil {
		t.Fatal(err)
	}
	if len(f.pinsSent) != 0 {
		t.Fatalf("PIN sent %d times; an explicit management key needs no PIN", len(f.pinsSent))
	}
}

func TestGenerateRejectsWrongGivenManagementKey(t *testing.T) {
	f := newFakeCard(t, testSerial)
	c := mustCard(t, f)
	_, _, err := c.Generate(GenerateOptions{ManagementKey: bytes.Repeat([]byte{1}, 32)})
	if !errors.Is(err, ErrManagementKeyRequired) {
		t.Fatalf("err = %v, want ErrManagementKeyRequired", err)
	}
	if n := f.callCount("GenerateKey"); n != 0 {
		t.Fatalf("GenerateKey called %d times", n)
	}
}

func TestGenerateNeedsManagementKey(t *testing.T) {
	f := newFakeCard(t, testSerial) // custom key, not stored on the card
	c := mustCard(t, f)
	_, _, err := c.Generate(GenerateOptions{PIN: f.pin})
	if !errors.Is(err, ErrManagementKeyRequired) {
		t.Fatalf("err = %v, want ErrManagementKeyRequired", err)
	}
	if n := f.callCount("SetPIN") + f.callCount("GenerateKey") + f.callCount("SetManagementKey"); n != 0 {
		t.Fatalf("card was modified: %v", f.calls)
	}
}

func TestGenerateWrongPIN(t *testing.T) {
	f := newFakeCard(t, testSerial).protectMgmt()
	c := mustCard(t, f)
	_, _, err := c.Generate(GenerateOptions{PIN: "000000"})
	var pe *keyprovider.PINError
	if !errors.As(err, &pe) || pe.RetriesLeft != 2 {
		t.Fatalf("err = %v, want *PINError with 2 retries", err)
	}
}

func TestGenerateBlockedPIN(t *testing.T) {
	f := newFakeCard(t, testSerial).protectMgmt()
	f.pinRetries = 0
	c := mustCard(t, f)
	_, _, err := c.Generate(GenerateOptions{PIN: f.pin})
	if !errors.Is(err, keyprovider.ErrPINBlocked) {
		t.Fatalf("err = %v, want ErrPINBlocked", err)
	}
}

func TestFreshCardRequiresNewPIN(t *testing.T) {
	cases := []GenerateOptions{
		{PIN: "246810", CurrentPUK: "97531086", NewPUK: "86420975"},                    // no NewPIN
		{PIN: "246810", CurrentPUK: "97531086", NewPIN: "135790"},                      // no NewPUK
		{PIN: "246810", CurrentPUK: "97531086", NewPIN: "12345", NewPUK: "86420975"},   // NewPIN too short
		{PIN: "246810", CurrentPUK: "97531086", NewPIN: "123456789", NewPUK: "864209"}, // NewPIN too long
		{PIN: "246810", NewPIN: "135790", NewPUK: "86420975"},                          // no current PUK
		{CurrentPUK: "97531086", NewPIN: "135790", NewPUK: "86420975"},                 // no current PIN
		{PIN: "246810", CurrentPUK: "97531086", NewPIN: "123456", NewPUK: "86420975"},  // NewPIN is the factory PIN
		{PIN: "246810", CurrentPUK: "97531086", NewPIN: "135790", NewPUK: "12345678"},  // NewPUK is the factory PUK
	}
	for i, o := range cases {
		f := newFakeCard(t, testSerial).fresh()
		c := mustCard(t, f)
		_, _, err := c.Generate(o)
		if !errors.Is(err, ErrFreshCard) {
			t.Fatalf("case %d: err = %v, want ErrFreshCard", i, err)
		}
		for _, name := range []string{"SetPIN", "SetPUK", "SetManagementKey", "SetMetadata", "GenerateKey"} {
			if n := f.callCount(name); n != 0 {
				t.Fatalf("case %d: %s called %d times", i, name, n)
			}
		}
	}
}

func freshOpts() GenerateOptions {
	return GenerateOptions{PIN: "246810", CurrentPUK: "97531086", NewPIN: "135790", NewPUK: "86420975"}
}

func TestFreshCardHardens(t *testing.T) {
	f := newFakeCard(t, testSerial).fresh()
	c := mustCard(t, f)
	ref, _, err := c.Generate(freshOpts())
	if err != nil {
		t.Fatal(err)
	}
	if ref.Slot != 0x82 {
		t.Fatalf("slot = %#x", ref.Slot)
	}

	// Order matters: the new management key is stored (and read back) under
	// the PIN before it replaces the default key, so a failed write can never
	// leave the card with a management key nobody knows.
	var mutating []string
	for _, c := range f.calls {
		switch c {
		case "SetPIN", "SetPUK", "SetMetadata", "Metadata", "SetManagementKey", "SetPIVManFlags", "GenerateKey":
			mutating = append(mutating, c)
		}
	}
	// The first Metadata call is the lookup for a PIN-protected key; the
	// first SetPUK only checks the current PUK (changes it to itself) before
	// the PIN is touched; the second Metadata is the readback with the new PIN.
	want := []string{"Metadata", "SetPUK", "SetPIN", "SetPUK", "SetMetadata", "Metadata", "SetManagementKey", "SetPIVManFlags", "GenerateKey"}
	if !slices.Equal(mutating, want) {
		t.Fatalf("calls = %v, want %v", mutating, want)
	}
	if f.pin != "135790" || f.puk != "86420975" {
		t.Fatalf("PIN/PUK not changed")
	}
	if !slices.Equal(f.mgmtLens, []int{32}) {
		t.Fatalf("new management key lengths = %v, want [32] (AES-256)", f.mgmtLens)
	}
	if f.pivman != piv.PIVManFlagMgmtKeyStored {
		t.Fatalf("PIVMAN flags = %#x, want %#x", f.pivman, piv.PIVManFlagMgmtKeyStored)
	}
	if bytes.Equal(f.mgmtKey, piv.DefaultManagementKey) {
		t.Fatal("management key is still the default")
	}
	if !bytes.Equal(f.storedMgmt, f.mgmtKey) {
		t.Fatal("stored (PIN-protected) management key differs from the card's key")
	}
}

func TestFreshCardAbortsOnBadMetadataReadback(t *testing.T) {
	f := newFakeCard(t, testSerial).fresh()
	f.truncateMeta = true
	c := mustCard(t, f)
	_, _, err := c.Generate(freshOpts())
	if err == nil {
		t.Fatal("Generate succeeded with a corrupted stored management key")
	}
	if !strings.Contains(err.Error(), msg.PIVPINAndPUKAlreadyChanged) || !strings.Contains(err.Error(), msg.PIVStoredKeyMismatch) {
		t.Fatalf("err = %q, want it to say the PIN and PUK were already changed", err)
	}
	if n := f.callCount("SetManagementKey"); n != 0 {
		t.Fatalf("SetManagementKey called %d times after a bad readback", n)
	}
	if !bytes.Equal(f.mgmtKey, piv.DefaultManagementKey) {
		t.Fatal("management key changed after a bad readback")
	}
}

func TestFreshCardChecksPUKBeforePIN(t *testing.T) {
	f := newFakeCard(t, testSerial).fresh()
	c := mustCard(t, f)
	o := freshOpts()
	o.CurrentPUK = "11112222"
	_, _, err := c.Generate(o)
	if err == nil || !strings.Contains(err.Error(), "wrong PUK") {
		t.Fatalf("err = %v, want wrong PUK", err)
	}
	if n := f.callCount("SetPIN"); n != 0 {
		t.Fatalf("SetPIN called %d times with a wrong PUK", n)
	}
	if f.pin != "246810" {
		t.Fatal("PIN changed although the PUK was wrong")
	}
}

func TestFreshCardFailuresAfterPINChangeSaySo(t *testing.T) {
	boom := &fakeAPDUErr{0x6a80}
	cases := []struct {
		method string
		nth    int
		want   string
		pukNew bool
	}{
		{"SetPUK", 2, msg.PIVPINAlreadyChanged, false},
		{"SetMetadata", 1, msg.PIVPINAndPUKAlreadyChanged, true},
		{"SetManagementKey", 1, msg.PIVPINAndPUKAlreadyChanged, true},
		{"SetPIVManFlags", 1, msg.PIVPINAndPUKAlreadyChanged, true},
	}
	for _, tc := range cases {
		f := newFakeCard(t, testSerial).fresh().failOn(tc.method, tc.nth, boom)
		c := mustCard(t, f)
		_, _, err := c.Generate(freshOpts())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s fails: err = %v, want it to contain %q", tc.method, err, tc.want)
		}
		if f.pin != "135790" {
			t.Fatalf("%s fails: PIN is not the new value, the message would lie", tc.method)
		}
		if (f.puk == "86420975") != tc.pukNew {
			t.Fatalf("%s fails: PUK new = %v, want %v", tc.method, f.puk == "86420975", tc.pukNew)
		}
		if n := f.callCount("GenerateKey"); n != 0 {
			t.Fatalf("%s fails: GenerateKey still called", tc.method)
		}
	}
	// The PIVMAN failure happens after the switch: the message says so.
	f := newFakeCard(t, testSerial).fresh().failOn("SetPIVManFlags", 1, boom)
	c := mustCard(t, f)
	_, _, err := c.Generate(freshOpts())
	if !strings.Contains(err.Error(), msg.PIVPIVManFlagFailed) {
		t.Fatalf("err = %v, want %q", err, msg.PIVPIVManFlagFailed)
	}
}

func TestGenerateRejectsOverlongSecrets(t *testing.T) {
	for _, o := range []GenerateOptions{{PIN: "123456789"}, {PIN: "246810", CurrentPUK: "123456789"}} {
		f := newFakeCard(t, testSerial).fresh()
		c := mustCard(t, f)
		f.calls = nil
		_, _, err := c.Generate(o)
		if err == nil || err.Error() != msg.PIVSecretTooLong {
			t.Fatalf("err = %v, want %q", err, msg.PIVSecretTooLong)
		}
		if len(f.calls) != 0 {
			t.Fatalf("card calls %v, want none", f.calls)
		}
	}
}

func TestFreshCardChecksSlotBeforeHardening(t *testing.T) {
	f := newFakeCard(t, testSerial).fresh()
	f.occupyX25519(0x82)
	c := mustCard(t, f)
	o := freshOpts()
	o.Slot = 0x82
	_, _, err := c.Generate(o)
	if !errors.Is(err, ErrSlotOccupied) {
		t.Fatalf("err = %v, want ErrSlotOccupied", err)
	}
	if n := f.callCount("SetPIN"); n != 0 {
		t.Fatalf("card hardened although generation could not proceed")
	}
}

func TestNeverVerifiesDefaultPIN(t *testing.T) {
	type run struct {
		name string
		card func() *fakeCard
		opts GenerateOptions
	}
	runs := []run{
		{"protected", func() *fakeCard { return newFakeCard(t, testSerial).protectMgmt() }, GenerateOptions{PIN: "246810"}},
		{"wrong-pin", func() *fakeCard { return newFakeCard(t, testSerial).protectMgmt() }, GenerateOptions{PIN: "000000"}},
		{"given-key", func() *fakeCard { return newFakeCard(t, testSerial) }, GenerateOptions{PIN: "246810", ManagementKey: bytes.Repeat([]byte{0x42}, 32)}},
		{"no-key", func() *fakeCard { return newFakeCard(t, testSerial) }, GenerateOptions{PIN: "246810"}},
		{"no-pin", func() *fakeCard { return newFakeCard(t, testSerial) }, GenerateOptions{}},
		{"fresh", func() *fakeCard { return newFakeCard(t, testSerial).fresh() }, freshOpts()},
		{"fresh-incomplete", func() *fakeCard { return newFakeCard(t, testSerial).fresh() }, GenerateOptions{PIN: "246810"}},
		{"fresh-no-pin", func() *fakeCard { return newFakeCard(t, testSerial).fresh() }, GenerateOptions{CurrentPUK: "97531086", NewPIN: "135790", NewPUK: "86420975"}},
	}
	for _, r := range runs {
		f := r.card()
		c := mustCard(t, f)
		_, _, _ = c.Generate(r.opts)
		for _, p := range f.pinsSent {
			if p == piv.DefaultPIN || p == piv.DefaultPUK {
				t.Errorf("%s: factory default %q sent to the card", r.name, p)
			}
			if p != r.opts.PIN && p != r.opts.CurrentPUK && p != r.opts.NewPIN {
				t.Errorf("%s: card received secret %q that the caller never gave", r.name, p)
			}
		}
	}
}
