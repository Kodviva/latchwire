// Package keyref parses references to a key slot on a hardware token.
package keyref

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Kodviva/latchwire/internal/msg"
)

const (
	scheme = "piv://"

	// Retired key management slots 82-95 are the only slots Latchwire uses.
	MinSlot = 0x82
	MaxSlot = 0x95
)

// Ref names one key slot on one token: piv://<decimal serial>/<2-digit hex slot>.
type Ref struct {
	Serial uint32
	Slot   uint8
}

// Parse reads the canonical form produced by String. It is strict: the scheme
// is lowercase, the serial is a canonical non-zero uint32 in decimal, and the
// slot is exactly two lowercase hex digits within 0x82-0x95.
func Parse(s string) (Ref, error) {
	bad := func() (Ref, error) { return Ref{}, fmt.Errorf(msg.KeyRefInvalidFmt, s) }

	rest, ok := strings.CutPrefix(s, scheme)
	if !ok {
		return bad()
	}
	serialStr, slotStr, ok := strings.Cut(rest, "/")
	if !ok {
		return bad()
	}

	// ParseUint with base 10 already refuses signs, underscores and prefixes.
	// A leading zero is refused so that String always round-trips.
	if serialStr == "" || (len(serialStr) > 1 && serialStr[0] == '0') {
		return bad()
	}
	serial, err := strconv.ParseUint(serialStr, 10, 32)
	if err != nil || serial == 0 {
		return bad()
	}

	if len(slotStr) != 2 || slotStr != strings.ToLower(slotStr) {
		return bad()
	}
	slot, err := strconv.ParseUint(slotStr, 16, 8)
	if err != nil || slot < MinSlot || slot > MaxSlot {
		return bad()
	}
	return Ref{Serial: uint32(serial), Slot: uint8(slot)}, nil
}

// String returns the canonical reference form.
func (r Ref) String() string {
	return fmt.Sprintf("%s%d/%02x", scheme, r.Serial, r.Slot)
}
