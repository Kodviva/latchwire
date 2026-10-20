//go:build hardware

package piv

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/Kodviva/latchwire/internal/keyref"
)

// TestHardwareGenerateAndECDH generates a key on a real YubiKey and checks
// the card's X25519 against a software computation. It writes to the card,
// so it runs only when explicitly allowed:
//
//	LATCHWIRE_HW_SERIAL=<serial> LATCHWIRE_HW_SLOT=95 LATCHWIRE_HW_ALLOW_WRITE=1 \
//	LATCHWIRE_HW_PIN=<pin> go test -tags hardware ./internal/keyprovider/piv/ -run Hardware -v
//
// LATCHWIRE_HW_FORCE=1 additionally allows replacing a key already in the
// slot. The PIN only ever comes from the environment.
func TestHardwareGenerateAndECDH(t *testing.T) {
	serialStr := os.Getenv("LATCHWIRE_HW_SERIAL")
	slotStr := os.Getenv("LATCHWIRE_HW_SLOT")
	if serialStr == "" || slotStr == "" {
		t.Skip("LATCHWIRE_HW_SERIAL and LATCHWIRE_HW_SLOT not set")
	}
	if os.Getenv("LATCHWIRE_HW_ALLOW_WRITE") != "1" {
		t.Skip("LATCHWIRE_HW_ALLOW_WRITE=1 not set; this test generates a key on the card")
	}
	pin := os.Getenv("LATCHWIRE_HW_PIN")
	if pin == "" {
		t.Skip("LATCHWIRE_HW_PIN not set")
	}
	serial, err := strconv.ParseUint(serialStr, 10, 32)
	if err != nil {
		t.Fatalf("LATCHWIRE_HW_SERIAL: %v", err)
	}
	slot, err := strconv.ParseUint(slotStr, 16, 8)
	if err != nil || slot < keyref.MinSlot || slot > keyref.MaxSlot {
		t.Fatalf("LATCHWIRE_HW_SLOT must be a retired slot 82-95 in hex, got %q", slotStr)
	}

	c, err := Open(uint32(serial))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ref, pub, err := c.Generate(GenerateOptions{
		Slot:  uint8(slot),
		PIN:   pin,
		Force: os.Getenv("LATCHWIRE_HW_FORCE") == "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Serial != uint32(serial) || ref.Slot != uint8(slot) {
		t.Fatalf("ref = %s", ref)
	}
	t.Logf("generated %s", ref)

	prompts := 0
	p, err := c.Provider(ref, func(int) (string, error) {
		prompts++
		return pin, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.PublicKey() != pub {
		t.Fatal("provider public key differs from the generated one")
	}

	for i := 0; i < 2; i++ {
		var e [32]byte
		if _, err := rand.Read(e[:]); err != nil {
			t.Fatal(err)
		}
		ePub, err := curve25519.X25519(e[:], curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		got, err := p.X25519(ctx, [32]byte(ePub))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		want, err := curve25519.X25519(e[:], pub[:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:], want) {
			t.Fatal("card X25519 differs from software X25519")
		}
	}
	if prompts > 1 {
		t.Fatalf("PIN asked %d times; PIN policy once should ask at most once", prompts)
	}
}
