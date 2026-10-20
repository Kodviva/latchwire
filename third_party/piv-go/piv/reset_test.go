// Latchwire addition: unit tests for the card identity check after a reset
// (PATCHES.md, patch 6). None of them touches a card.

package piv

import (
	"errors"
	"testing"
)

// Latchwire patch: after SCARD_W_RESET_CARD and Reconnect, begin re-reads
// the serial and refuses to continue on a different (or unidentifiable)
// card, so a PIN meant for one card is never sent to another.
func TestSameCardAfterReset(t *testing.T) {
	readErr := errors.New("smart card command: transmit failed")
	for _, tc := range []struct {
		name  string
		want  uint32
		known bool
		got   uint32
		err   error
		ok    bool
	}{
		{"same serial", 40727512, true, 40727512, nil, true},
		{"other serial", 40727512, true, 40727513, nil, false},
		{"serial unreadable", 40727512, true, 0, readErr, false},
		{"serial unknown at open", 0, false, 40727512, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sameCard(tc.want, tc.known, tc.got, tc.err)
			if tc.ok {
				if err != nil {
					t.Fatalf("sameCard = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrCardChanged) {
				t.Fatalf("sameCard = %v, want ErrCardChanged", err)
			}
			// The error must not carry the card's status word: callers map
			// it to "card unavailable", not to a PIN or card-command error.
			var ae *apduErr
			if errors.As(err, &ae) {
				t.Fatalf("sameCard error wraps a card status: %v", err)
			}
		})
	}
}
