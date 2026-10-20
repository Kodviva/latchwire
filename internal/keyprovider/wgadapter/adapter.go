// Package wgadapter plugs a keyprovider.Provider into wireguard-go as its
// static key, adding a per-call timeout and a responder rate limit.
package wgadapter

import (
	"context"
	"time"

	"golang.org/x/time/rate"
	"golang.zx2c4.com/wireguard/device"

	"github.com/Kodviva/latchwire/internal/keyprovider"
)

// Limits bounds card operations.
type Limits struct {
	// ResponderPerSecond and ResponderBurst form the token bucket applied to
	// device.UseResponder only; that use is attacker-triggerable.
	ResponderPerSecond float64
	ResponderBurst     int
	// Timeout applies to every provider call.
	Timeout time.Duration
}

// DefaultLimits: 5 responder ops/s, burst 10, 3 s per operation.
var DefaultLimits = Limits{5, 10, 3 * time.Second}

type adapter struct {
	p       keyprovider.Provider
	timeout time.Duration
	limiter *rate.Limiter
}

// New wraps p as a device.StaticKey.
func New(p keyprovider.Provider, l Limits) device.StaticKey {
	return &adapter{
		p:       p,
		timeout: l.Timeout,
		limiter: rate.NewLimiter(rate.Limit(l.ResponderPerSecond), l.ResponderBurst),
	}
}

func (a *adapter) PublicKey() device.NoisePublicKey {
	return device.NoisePublicKey(a.p.PublicKey())
}

type result struct {
	ss  [32]byte
	err error
}

func (a *adapter) SharedSecret(peer device.NoisePublicKey, use device.KeyUse) (out [device.NoisePublicKeySize]byte, err error) {
	if peer.IsZero() {
		return out, keyprovider.ErrLowOrderPoint
	}
	if use == device.UseResponder && !a.limiter.Allow() {
		return out, keyprovider.ErrRateLimited
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	// Run in a goroutine so a provider that ignores ctx cannot hold the
	// handshake past the deadline. The buffer lets it finish unobserved.
	ch := make(chan result, 1)
	go func() {
		ss, err := a.p.X25519(ctx, [32]byte(peer))
		ch <- result{ss, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return out, r.err
		}
		if r.ss == ([32]byte{}) {
			return out, keyprovider.ErrLowOrderPoint
		}
		return r.ss, nil
	case <-ctx.Done():
		return out, ctx.Err()
	}
}
