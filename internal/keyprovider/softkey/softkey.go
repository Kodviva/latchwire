// Package softkey is an in-memory key provider for tests only. Production
// binaries must never import it.
package softkey

import (
	"context"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"

	"github.com/Kodviva/latchwire/internal/keyprovider"
)

// Key is a software X25519 key.
type Key struct {
	sk [32]byte
	pk [32]byte
}

var _ keyprovider.Provider = (*Key)(nil)

// New generates a random key.
func New() (*Key, error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, err
	}
	return FromPrivate(sk), nil
}

// FromPrivate builds a key from a private scalar.
func FromPrivate(sk [32]byte) *Key {
	k := &Key{sk: sk}
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		// Cannot happen: the base point is not low order.
		panic("softkey: " + err.Error())
	}
	copy(k.pk[:], pk)
	return k
}

func (k *Key) PublicKey() [32]byte { return k.pk }

func (k *Key) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	var out [32]byte
	if err := ctx.Err(); err != nil {
		return out, err
	}
	ss, err := curve25519.X25519(k.sk[:], peer[:])
	if err != nil {
		return out, keyprovider.ErrLowOrderPoint
	}
	copy(out[:], ss)
	return out, nil
}

func (k *Key) Describe() keyprovider.Description {
	return keyprovider.Description{Kind: "soft-test", Model: "software", Tier: keyprovider.Tier2}
}
