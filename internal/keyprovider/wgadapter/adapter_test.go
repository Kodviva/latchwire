package wgadapter

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/softkey"
)

func randPeer(t *testing.T) device.NoisePublicKey {
	t.Helper()
	var sk, pk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatal(err)
	}
	out, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pk[:], out)
	return device.NoisePublicKey(pk)
}

func newSoft(t *testing.T) *softkey.Key {
	t.Helper()
	k, err := softkey.New()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestLimitRejectsBurst(t *testing.T) {
	l := DefaultLimits
	l.ResponderPerSecond = 0.001 // no refill during the test, whatever the scheduling
	l.MaxInFlightResponder = 16
	sk := New(newSoft(t), l)
	peer := randPeer(t)

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, limited := 0, 0
	for i := 0; i < 11; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := sk.SharedSecret(peer, device.UseResponder)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, keyprovider.ErrRateLimited):
				limited++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 10 || limited != 1 {
		t.Fatalf("ok=%d limited=%d, want 10 and 1", ok, limited)
	}
}

func TestLimitRefills(t *testing.T) {
	sk := New(newSoft(t), DefaultLimits)
	peer := randPeer(t)
	for i := 0; i < 10; i++ {
		if _, err := sk.SharedSecret(peer, device.UseResponder); err != nil {
			t.Fatalf("burst call %d: %v", i, err)
		}
	}
	if _, err := sk.SharedSecret(peer, device.UseResponder); !errors.Is(err, keyprovider.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := sk.SharedSecret(peer, device.UseResponder); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

func TestInitiatorNotLimited(t *testing.T) {
	// Exhausted responder budget does not block initiator or static-static;
	// static-static has no bucket at all.
	sk := New(newSoft(t), DefaultLimits)
	peer := randPeer(t)
	for i := 0; i < 10; i++ {
		if _, err := sk.SharedSecret(peer, device.UseResponder); err != nil {
			t.Fatalf("burst call %d: %v", i, err)
		}
	}
	if _, err := sk.SharedSecret(peer, device.UseResponder); !errors.Is(err, keyprovider.ErrRateLimited) {
		t.Fatalf("responder budget not exhausted: %v", err)
	}
	if _, err := sk.SharedSecret(peer, device.UseInitiator); err != nil {
		t.Fatalf("initiator: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, err := sk.SharedSecret(peer, device.UseStaticStatic); err != nil {
			t.Fatalf("static-static %d: %v", i, err)
		}
	}
}

func exhaust(t *testing.T, sk device.StaticKey, peer device.NoisePublicKey, use device.KeyUse, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := sk.SharedSecret(peer, use); err != nil {
			t.Fatalf("use %d call %d: %v", use, i, err)
		}
	}
	if _, err := sk.SharedSecret(peer, use); !errors.Is(err, keyprovider.ErrRateLimited) {
		t.Fatalf("use %d: want ErrRateLimited, got %v", use, err)
	}
}

func TestInitiatorLimitedSeparately(t *testing.T) {
	l := DefaultLimits
	l.ResponderPerSecond, l.InitiatorPerSecond = 0.001, 0.001
	peer := randPeer(t)

	sk := New(newSoft(t), l)
	exhaust(t, sk, peer, device.UseInitiator, 10)
	for i := 0; i < 10; i++ {
		if _, err := sk.SharedSecret(peer, device.UseResponder); err != nil {
			t.Fatalf("responder starved by initiator: %v", err)
		}
	}

	sk = New(newSoft(t), l)
	exhaust(t, sk, peer, device.UseResponder, 10)
	for i := 0; i < 10; i++ {
		if _, err := sk.SharedSecret(peer, device.UseInitiator); err != nil {
			t.Fatalf("initiator starved by responder: %v", err)
		}
	}
}

// gateProvider blocks every X25519 call until gate is closed, then answers
// like the wrapped provider. entered receives one value per call that started.
type gateProvider struct {
	keyprovider.Provider
	gate    chan struct{}
	entered chan struct{}
}

func newGate(t *testing.T) *gateProvider {
	return &gateProvider{Provider: newSoft(t), gate: make(chan struct{}), entered: make(chan struct{}, 64)}
}

func (g *gateProvider) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	g.entered <- struct{}{}
	<-g.gate // deliberately ignores ctx
	return g.Provider.X25519(context.Background(), peer)
}

func waitEntered(t *testing.T, g *gateProvider, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-g.entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("provider call %d never started", i)
		}
	}
}

// recovers polls until a call succeeds. Only for slots held by calls that
// already timed out: the caller cannot know when their provider returns.
func recovers(t *testing.T, sk device.StaticKey, peer device.NoisePublicKey) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := sk.SharedSecret(peer, device.UseStaticStatic)
		if err == nil {
			return
		}
		if !errors.Is(err, keyprovider.ErrUnavailable) || time.Now().After(deadline) {
			t.Fatalf("call did not recover: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMaxInFlightFailsFast(t *testing.T) {
	g := newGate(t)
	l := DefaultLimits
	l.MaxInFlightOther = 2
	sk := New(g, l)
	peer := randPeer(t)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := sk.SharedSecret(peer, device.UseStaticStatic); err != nil {
				t.Errorf("blocked call: %v", err)
			}
		}()
	}
	waitEntered(t, g, 2)

	start := time.Now()
	_, err := sk.SharedSecret(peer, device.UseInitiator)
	if !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("did not fail fast: %v", time.Since(start))
	}

	close(g.gate)
	wg.Wait() // slots are freed before results are delivered
	if _, err := sk.SharedSecret(peer, device.UseStaticStatic); err != nil {
		t.Fatalf("after providers returned: %v", err)
	}
}

func TestTimedOutCallsCountInFlight(t *testing.T) {
	g := newGate(t)
	l := DefaultLimits
	l.MaxInFlightOther = 2
	l.Timeout = 50 * time.Millisecond
	sk := New(g, l)
	peer := randPeer(t)

	for i := 0; i < 2; i++ {
		if _, err := sk.SharedSecret(peer, device.UseStaticStatic); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("call %d: want DeadlineExceeded, got %v", i, err)
		}
	}
	waitEntered(t, g, 2)

	// Providers are still blocked: both slots are held by timed-out calls.
	start := time.Now()
	_, err := sk.SharedSecret(peer, device.UseStaticStatic)
	if !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if time.Since(start) > 30*time.Millisecond {
		t.Fatalf("did not fail fast: %v", time.Since(start))
	}

	close(g.gate)
	recovers(t, sk, peer)
}

// peerGateProvider blocks only calls for the peer blocked, so one test can
// fill the responder pool while other uses stay fast.
type peerGateProvider struct {
	keyprovider.Provider
	blocked [32]byte
	gate    chan struct{}
	entered chan struct{}
}

func (g *peerGateProvider) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	if peer == g.blocked {
		g.entered <- struct{}{}
		<-g.gate
	}
	return g.Provider.X25519(context.Background(), peer)
}

func TestResponderFloodDoesNotBlockInitiator(t *testing.T) {
	flood := randPeer(t)
	g := &peerGateProvider{Provider: newSoft(t), blocked: flood, gate: make(chan struct{}), entered: make(chan struct{}, 8)}
	l := DefaultLimits
	l.MaxInFlightResponder = 2
	l.Timeout = 50 * time.Millisecond
	sk := New(g, l)
	defer close(g.gate)

	for i := 0; i < 2; i++ {
		if _, err := sk.SharedSecret(flood, device.UseResponder); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("flood call %d: want DeadlineExceeded, got %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		<-g.entered
	}
	if _, err := sk.SharedSecret(flood, device.UseResponder); !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("responder pool should be full, got %v", err)
	}

	peer := randPeer(t)
	if _, err := sk.SharedSecret(peer, device.UseInitiator); err != nil {
		t.Fatalf("initiator starved: %v", err)
	}
	if _, err := sk.SharedSecret(peer, device.UseStaticStatic); err != nil {
		t.Fatalf("static-static starved: %v", err)
	}
}

func TestSequentialCallsAtCapNeverUnavailable(t *testing.T) {
	l := DefaultLimits
	l.MaxInFlightOther = 1
	l.InitiatorPerSecond = 1000
	l.InitiatorBurst = 1000
	sk := New(newSoft(t), l)
	peer := randPeer(t)
	for i := 0; i < 50; i++ {
		if _, err := sk.SharedSecret(peer, device.UseInitiator); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
}

func TestZeroLimitsUseDefaults(t *testing.T) {
	if got := (Limits{}).withDefaults(); got != DefaultLimits {
		t.Fatalf("zero Limits -> %+v, want %+v", got, DefaultLimits)
	}
	got := (Limits{InitiatorBurst: 3}).withDefaults()
	want := DefaultLimits
	want.InitiatorBurst = 3
	if got != want {
		t.Fatalf("partial Limits -> %+v, want %+v", got, want)
	}

	// Behaviour: a zero Limits passed to New behaves like DefaultLimits.
	sk := New(newSoft(t), Limits{})
	exhaust(t, sk, randPeer(t), device.UseResponder, 10)
}

// sleepProvider blocks until its context ends or d passes.
type sleepProvider struct {
	keyprovider.Provider
	d time.Duration
}

func (s sleepProvider) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	select {
	case <-time.After(s.d):
		return s.Provider.X25519(ctx, peer)
	case <-ctx.Done():
		return [32]byte{}, ctx.Err()
	}
}

func TestTimeout(t *testing.T) {
	sk := New(sleepProvider{newSoft(t), 5 * time.Second}, DefaultLimits)
	start := time.Now()
	_, err := sk.SharedSecret(randPeer(t), device.UseInitiator)
	el := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if el < 2800*time.Millisecond || el > 3500*time.Millisecond {
		t.Fatalf("returned after %v, want ~3s", el)
	}
}

// ignoreCtxProvider never looks at its context; the adapter must still return.
type ignoreCtxProvider struct {
	keyprovider.Provider
	d time.Duration
}

func (s ignoreCtxProvider) X25519(_ context.Context, peer [32]byte) ([32]byte, error) {
	time.Sleep(s.d)
	return [32]byte{1}, nil
}

func TestTimeoutIgnoringProvider(t *testing.T) {
	l := Limits{Timeout: 100 * time.Millisecond}
	sk := New(ignoreCtxProvider{newSoft(t), time.Second}, l)
	start := time.Now()
	_, err := sk.SharedSecret(randPeer(t), device.UseInitiator)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("did not return promptly: %v", time.Since(start))
	}
}

func TestAdapterMatchesCurve25519(t *testing.T) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	k := softkey.FromPrivate(priv)
	sk := New(k, DefaultLimits)
	peer := randPeer(t)

	want, err := curve25519.X25519(priv[:], peer[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, use := range []device.KeyUse{device.UseStaticStatic, device.UseInitiator, device.UseResponder} {
		got, err := sk.SharedSecret(peer, use)
		if err != nil {
			t.Fatalf("use %d: %v", use, err)
		}
		if string(got[:]) != string(want) {
			t.Fatalf("use %d: secret mismatch", use)
		}
	}
	wantPub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	if pk := sk.PublicKey(); string(pk[:]) != string(wantPub) {
		t.Fatal("public key mismatch")
	}
}

func TestAdapterRejectsLowOrder(t *testing.T) {
	sk := New(newSoft(t), DefaultLimits)
	var zero device.NoisePublicKey
	_, err := sk.SharedSecret(zero, device.UseInitiator)
	if !errors.Is(err, keyprovider.ErrLowOrderPoint) {
		t.Fatalf("want ErrLowOrderPoint, got %v", err)
	}
}

// zeroProvider returns an all-zero secret with no error.
type zeroProvider struct{ keyprovider.Provider }

func (zeroProvider) X25519(context.Context, [32]byte) ([32]byte, error) { return [32]byte{}, nil }

func TestAdapterRejectsZeroOutput(t *testing.T) {
	sk := New(zeroProvider{newSoft(t)}, DefaultLimits)
	out, err := sk.SharedSecret(randPeer(t), device.UseInitiator)
	if !errors.Is(err, keyprovider.ErrLowOrderPoint) {
		t.Fatalf("want ErrLowOrderPoint, got %v", err)
	}
	if out != ([32]byte{}) {
		t.Fatal("non-zero output on error")
	}
}

func TestProviderErrorPropagates(t *testing.T) {
	want := fmt.Errorf("card gone: %w", keyprovider.ErrUnavailable)
	sk := New(errProvider{newSoft(t), want}, DefaultLimits)
	if _, err := sk.SharedSecret(randPeer(t), device.UseInitiator); !errors.Is(err, keyprovider.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

type errProvider struct {
	keyprovider.Provider
	err error
}

func (e errProvider) X25519(context.Context, [32]byte) ([32]byte, error) { return [32]byte{}, e.err }
