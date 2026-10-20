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
	sk := New(newSoft(t), DefaultLimits)
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
	for i := 0; i < 50; i++ {
		if _, err := sk.SharedSecret(peer, device.UseInitiator); err != nil {
			t.Fatalf("initiator %d: %v", i, err)
		}
		if _, err := sk.SharedSecret(peer, device.UseStaticStatic); err != nil {
			t.Fatalf("static-static %d: %v", i, err)
		}
	}
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
	l := Limits{ResponderPerSecond: 5, ResponderBurst: 10, Timeout: 100 * time.Millisecond}
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
