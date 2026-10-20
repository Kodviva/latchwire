package keyprovider

import (
	"errors"
	"fmt"
	"testing"
)

func TestPINErrorAs(t *testing.T) {
	err := fmt.Errorf("verify: %w", &PINError{RetriesLeft: 2})
	var pe *PINError
	if !errors.As(err, &pe) {
		t.Fatal("errors.As failed through wrapping")
	}
	if pe.RetriesLeft != 2 {
		t.Fatalf("RetriesLeft = %d, want 2", pe.RetriesLeft)
	}
	if errors.Is(err, ErrPINRequired) {
		t.Fatal("PINError must not match ErrPINRequired")
	}
	if pe.Error() == "" {
		t.Fatal("empty error text")
	}
}
