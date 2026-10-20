// Package keyprovider defines the vocabulary shared by every source of the
// device's static X25519 key: hardware tokens and the test-only software key.
package keyprovider

import (
	"context"
	"errors"
	"fmt"
)

// Tier says how strongly a provider protects its private key.
type Tier int

const (
	// Tier1 is a hardware token whose private key never leaves the device.
	Tier1 Tier = 1
	// Tier2 is a weaker provider (for example a software key).
	Tier2 Tier = 2
)

// Description identifies a provider for status output. It never carries
// secrets.
type Description struct {
	Kind   string
	Model  string
	Serial uint32
	Slot   uint8
	Tier   Tier
}

// Provider holds a static X25519 private key and exposes only the public key
// and the Diffie-Hellman operation.
type Provider interface {
	PublicKey() [32]byte
	X25519(ctx context.Context, peer [32]byte) ([32]byte, error)
	Describe() Description
}

var (
	// ErrUnavailable means the key source is gone or unreachable (for
	// example the token was removed).
	ErrUnavailable = errors.New("key provider unavailable")
	// ErrPINRequired means PIN verification is needed or was lost.
	ErrPINRequired = errors.New("PIN required")
	// ErrPINBlocked means the PIN retry counter is exhausted.
	ErrPINBlocked = errors.New("PIN blocked")
	// ErrRateLimited means an operation was refused by a rate limit.
	ErrRateLimited = errors.New("rate limited")
	// ErrLowOrderPoint means the peer point is of low order and the DH
	// result is all zeros.
	ErrLowOrderPoint = errors.New("low-order point")
)

// PINError means a wrong PIN was entered; RetriesLeft attempts remain.
// It has a pointer receiver: return it as *PINError and match it with
// errors.As(err, &pe) where pe is a *PINError.
type PINError struct {
	RetriesLeft int
}

func (e *PINError) Error() string {
	return fmt.Sprintf("wrong PIN, %d retries left", e.RetriesLeft)
}
