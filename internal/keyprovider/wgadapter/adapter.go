// Package wgadapter plugs a keyprovider.Provider into wireguard-go as its
// static key, adding a per-call timeout, per-role rate limits and a cap on
// outstanding provider calls.
package wgadapter

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"golang.zx2c4.com/wireguard/device"

	"github.com/Kodviva/latchwire/internal/keyprovider"
)

// Limits bounds card operations. Any zero field passed to New is replaced by
// the corresponding DefaultLimits field.
type Limits struct {
	// ResponderPerSecond and ResponderBurst form the token bucket for
	// device.UseResponder (consuming a handshake initiation).
	ResponderPerSecond float64
	ResponderBurst     int
	// InitiatorPerSecond and InitiatorBurst form a separate bucket for
	// device.UseInitiator (consuming a handshake response), so a responder
	// flood cannot starve our own handshakes.
	InitiatorPerSecond float64
	InitiatorBurst     int
	// MaxInFlightResponder caps outstanding provider calls for
	// device.UseResponder; MaxInFlightOther caps those for UseInitiator and
	// UseStaticStatic together. The pools are separate so a responder flood
	// cannot starve our own handshakes. Calls that timed out but whose
	// provider has not returned still count. When a pool is full, calls fail
	// fast with keyprovider.ErrUnavailable.
	MaxInFlightResponder int
	MaxInFlightOther     int
	// Timeout applies to every provider call.
	Timeout time.Duration
}

// DefaultLimits: 5 ops/s with burst 10 for each of responder and initiator,
// at most 2 calls in flight per pool (responder, other), 3 s per operation.
var DefaultLimits = Limits{
	ResponderPerSecond:   5,
	ResponderBurst:       10,
	InitiatorPerSecond:   5,
	InitiatorBurst:       10,
	MaxInFlightResponder: 2,
	MaxInFlightOther:     2,
	Timeout:              3 * time.Second,
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits
	if l.ResponderPerSecond == 0 {
		l.ResponderPerSecond = d.ResponderPerSecond
	}
	if l.ResponderBurst == 0 {
		l.ResponderBurst = d.ResponderBurst
	}
	if l.InitiatorPerSecond == 0 {
		l.InitiatorPerSecond = d.InitiatorPerSecond
	}
	if l.InitiatorBurst == 0 {
		l.InitiatorBurst = d.InitiatorBurst
	}
	if l.MaxInFlightResponder == 0 {
		l.MaxInFlightResponder = d.MaxInFlightResponder
	}
	if l.MaxInFlightOther == 0 {
		l.MaxInFlightOther = d.MaxInFlightOther
	}
	if l.Timeout == 0 {
		l.Timeout = d.Timeout
	}
	return l
}

type adapter struct {
	p          keyprovider.Provider
	timeout    time.Duration
	responder  *rate.Limiter
	initiator  *rate.Limiter
	respSlots  chan struct{} // one token per outstanding responder call
	otherSlots chan struct{} // same, for initiator and static-static
}

// New wraps p as a device.StaticKey. UseResponder and UseInitiator each have
// their own token bucket; UseStaticStatic is not rate limited (it runs only
// when a peer or key is set, not in response to network input).
func New(p keyprovider.Provider, l Limits) device.StaticKey {
	l = l.withDefaults()
	return &adapter{
		p:          p,
		timeout:    l.Timeout,
		responder:  rate.NewLimiter(rate.Limit(l.ResponderPerSecond), l.ResponderBurst),
		initiator:  rate.NewLimiter(rate.Limit(l.InitiatorPerSecond), l.InitiatorBurst),
		respSlots:  make(chan struct{}, l.MaxInFlightResponder),
		otherSlots: make(chan struct{}, l.MaxInFlightOther),
	}
}

func (a *adapter) PublicKey() device.NoisePublicKey {
	return device.NoisePublicKey(a.p.PublicKey())
}

type result struct {
	ss  [32]byte
	err error
}

// call carries one provider result back to the caller. Once the caller has
// given up, a late result is zeroed instead of delivered.
type call struct {
	mu        sync.Mutex
	abandoned bool
	ch        chan result // buffered 1
}

func (a *adapter) SharedSecret(peer device.NoisePublicKey, use device.KeyUse) (out [device.NoisePublicKeySize]byte, err error) {
	if peer.IsZero() {
		return out, keyprovider.ErrLowOrderPoint
	}
	slots := a.otherSlots
	switch use {
	case device.UseResponder:
		if !a.responder.Allow() {
			return out, keyprovider.ErrRateLimited
		}
		slots = a.respSlots
	case device.UseInitiator:
		if !a.initiator.Allow() {
			return out, keyprovider.ErrRateLimited
		}
	}

	select {
	case slots <- struct{}{}:
	default:
		return out, keyprovider.ErrUnavailable
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	// Run in a goroutine so a provider that ignores ctx cannot hold the
	// handshake past the deadline. The slot is released only when the
	// provider returns, which bounds the number of such goroutines.
	c := &call{ch: make(chan result, 1)}
	go func() {
		ss, err := a.p.X25519(ctx, [32]byte(peer))
		// The provider has returned: free the slot before the caller can
		// observe the result, so a sequential caller never sees a stale slot.
		<-slots
		c.mu.Lock()
		if c.abandoned {
			setZero(ss[:])
		} else {
			c.ch <- result{ss, err}
		}
		c.mu.Unlock()
	}()

	var r result
	select {
	case r = <-c.ch:
	case <-ctx.Done():
		c.mu.Lock()
		select {
		case r = <-c.ch: // finished just as the deadline hit
		default:
			c.abandoned = true
			c.mu.Unlock()
			return out, ctx.Err()
		}
		c.mu.Unlock()
	}

	if r.err != nil {
		setZero(r.ss[:])
		return out, r.err
	}
	if r.ss == ([32]byte{}) {
		return out, keyprovider.ErrLowOrderPoint
	}
	return r.ss, nil
}

func setZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
