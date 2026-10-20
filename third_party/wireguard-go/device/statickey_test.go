/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

var errTestKey = errors.New("test key failure")

// countingKey wraps a software key, records every KeyUse it is asked to
// perform and can be switched into a failing state.
type countingKey struct {
	inner   softStaticKey
	failing atomic.Bool

	mu   sync.Mutex
	uses []KeyUse
}

func newCountingKey(t *testing.T) *countingKey {
	t.Helper()
	sk, err := newPrivateKey()
	assertNil(t, err)
	return &countingKey{inner: softStaticKey{sk: sk}}
}

func (k *countingKey) PublicKey() NoisePublicKey { return k.inner.PublicKey() }

func (k *countingKey) SharedSecret(peer NoisePublicKey, use KeyUse) ([NoisePublicKeySize]byte, error) {
	k.mu.Lock()
	k.uses = append(k.uses, use)
	k.mu.Unlock()
	if k.failing.Load() {
		return [NoisePublicKeySize]byte{}, errTestKey
	}
	return k.inner.SharedSecret(peer, use)
}

func (k *countingKey) calls() []KeyUse {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]KeyUse(nil), k.uses...)
}

func newBareDevice() *Device {
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	return NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
}

func newKeyDevice(t *testing.T, k StaticKey) *Device {
	t.Helper()
	dev := newBareDevice()
	t.Cleanup(dev.Close)
	assertNil(t, dev.SetStaticKey(k))
	return dev
}

// handshakePeers creates a started peer on each device referring to the
// other one. Returns (peer of dev1 for dev2, peer of dev2 for dev1).
func handshakePeers(t *testing.T, dev1, dev2 *Device) (*Peer, *Peer) {
	t.Helper()
	p12, err := dev1.NewPeer(dev2.staticIdentity.publicKey)
	assertNil(t, err)
	p21, err := dev2.NewPeer(dev1.staticIdentity.publicKey)
	assertNil(t, err)
	p12.Start()
	p21.Start()
	return p12, p21
}

// fullHandshake runs a complete handshake started by dev1 and returns the
// derived keypairs (initiator side, responder side).
func fullHandshake(t *testing.T, dev1, dev2 *Device, p12, p21 *Peer) (init, resp *Keypair) {
	t.Helper()
	msg1, err := dev1.CreateMessageInitiation(p12)
	assertNil(t, err)
	if dev2.ConsumeMessageInitiation(msg1) == nil {
		t.Fatal("handshake failed at initiation message")
	}
	msg2, err := dev2.CreateMessageResponse(p21)
	assertNil(t, err)
	if dev1.ConsumeMessageResponse(msg2) == nil {
		t.Fatal("handshake failed at response message")
	}
	assertNil(t, p12.BeginSymmetricSession())
	assertNil(t, p21.BeginSymmetricSession())
	return p12.keypairs.Current(), p21.keypairs.next.Load()
}

func assertKeypairsInteroperate(t *testing.T, init, resp *Keypair) {
	t.Helper()
	if init == nil || resp == nil {
		t.Fatal("missing keypair")
	}
	var nonce [12]byte
	msg := []byte("latchwire statickey test message")
	out := init.send.Seal(nil, nonce[:], msg, nil)
	got, err := resp.receive.Open(nil, nonce[:], out, nil)
	assertNil(t, err)
	assertEqual(t, got, msg)
	out = resp.send.Seal(nil, nonce[:], msg, nil)
	got, err = init.receive.Open(nil, nonce[:], out, nil)
	assertNil(t, err)
	assertEqual(t, got, msg)
}

func TestStaticKeyInitiatorCalls(t *testing.T) {
	ck := newCountingKey(t)
	dev1 := newKeyDevice(t, ck)
	dev2 := randDevice(t)
	defer dev2.Close()

	p12, p21 := handshakePeers(t, dev1, dev2)
	init, resp := fullHandshake(t, dev1, dev2, p12, p21)
	assertKeypairsInteroperate(t, init, resp)

	want := []KeyUse{UseStaticStatic, UseInitiator}
	if got := ck.calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("uses = %v, want %v", got, want)
	}
}

func TestStaticKeyResponderCalls(t *testing.T) {
	ck := newCountingKey(t)
	dev2 := newKeyDevice(t, ck)
	dev1 := randDevice(t)
	defer dev1.Close()

	p12, p21 := handshakePeers(t, dev1, dev2)
	init, resp := fullHandshake(t, dev1, dev2, p12, p21)
	assertKeypairsInteroperate(t, init, resp)

	want := []KeyUse{UseStaticStatic, UseResponder}
	if got := ck.calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("uses = %v, want %v", got, want)
	}
}

func TestHandshakeKeysMatchSoftware(t *testing.T) {
	sk, err := newPrivateKey()
	assertNil(t, err)

	soft := randDevice(t)
	defer soft.Close()
	if err := soft.SetPrivateKey(sk); err != nil {
		t.Fatal(err)
	}
	ck := &countingKey{inner: softStaticKey{sk: sk}}
	hw := newKeyDevice(t, ck)

	if soft.staticIdentity.publicKey != hw.staticIdentity.publicKey {
		t.Fatal("public keys differ")
	}

	// Same identity key, same remote peer: precomputed static-static must be identical.
	other := randDevice(t)
	defer other.Close()
	otherPK := other.staticIdentity.publicKey
	ps, err := soft.NewPeer(otherPK)
	assertNil(t, err)
	ph, err := hw.NewPeer(otherPK)
	assertNil(t, err)
	assertEqual(t, ps.handshake.precomputedStaticStatic[:], ph.handshake.precomputedStaticStatic[:])

	// Cross-implementation handshakes in both roles derive matching transport keys.
	t.Run("hardware initiates", func(t *testing.T) {
		peer := randDevice(t)
		defer peer.Close()
		p12, p21 := handshakePeers(t, hw, peer)
		init, resp := fullHandshake(t, hw, peer, p12, p21)
		assertKeypairsInteroperate(t, init, resp)
	})
	t.Run("hardware responds", func(t *testing.T) {
		peer := randDevice(t)
		defer peer.Close()
		p12, p21 := handshakePeers(t, peer, hw)
		init, resp := fullHandshake(t, peer, hw, p12, p21)
		assertKeypairsInteroperate(t, init, resp)
	})
}

func TestUAPIOmitsPrivateKeyForStaticKey(t *testing.T) {
	dev := newBareDevice()
	defer dev.Close()

	sk, err := newPrivateKey()
	assertNil(t, err)
	assertNil(t, dev.SetPrivateKey(sk))
	out, err := dev.IpcGet()
	assertNil(t, err)
	if !strings.Contains(out, "private_key=") {
		t.Fatalf("software key: private_key missing from IpcGet:\n%s", out)
	}

	assertNil(t, dev.SetStaticKey(newCountingKey(t)))
	out, err = dev.IpcGet()
	assertNil(t, err)
	if strings.Contains(out, "private_key=") {
		t.Fatalf("static key: private_key leaked into IpcGet:\n%s", out)
	}
}

func TestSetStaticKeyNilClears(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()
	assertNil(t, dev.SetStaticKey(nil))
	if !dev.staticIdentity.publicKey.IsZero() {
		t.Fatal("public key not cleared")
	}
	out, err := dev.IpcGet()
	assertNil(t, err)
	if strings.Contains(out, "private_key=") {
		t.Fatal("private_key present after clear")
	}
	other := randDevice(t)
	defer other.Close()
	p, err := dev.NewPeer(other.staticIdentity.publicKey)
	assertNil(t, err)
	if !isZero(p.handshake.precomputedStaticStatic[:]) {
		t.Fatal("static-static computed without a key")
	}
	if _, err := dev.CreateMessageInitiation(p); err == nil {
		t.Fatal("initiation created without a key")
	}
}

func TestStaticKeyErrorNoPanic(t *testing.T) {
	t.Run("always failing key", func(t *testing.T) {
		bad := newCountingKey(t)
		bad.failing.Store(true)
		devBad := newKeyDevice(t, bad)
		devGood := randDevice(t)
		defer devGood.Close()
		pBad, pGood := handshakePeers(t, devBad, devGood)

		// Initiating with a failing key must error, not panic.
		if msg, err := devBad.CreateMessageInitiation(pBad); err == nil || msg != nil {
			t.Fatalf("CreateMessageInitiation = %v, %v; want nil, error", msg, err)
		}

		// Responding with a failing key must drop the message.
		msg, err := devGood.CreateMessageInitiation(pGood)
		assertNil(t, err)
		if devBad.ConsumeMessageInitiation(msg) != nil {
			t.Fatal("ConsumeMessageInitiation succeeded with failing key")
		}
		if pBad.keypairs.Current() != nil || pBad.keypairs.next.Load() != nil {
			t.Fatal("keypair created despite key failure")
		}
	})

	t.Run("initiator key fails mid-handshake", func(t *testing.T) {
		ck := newCountingKey(t)
		dev1 := newKeyDevice(t, ck)
		dev2 := randDevice(t)
		defer dev2.Close()
		p12, p21 := handshakePeers(t, dev1, dev2)

		msg1, err := dev1.CreateMessageInitiation(p12)
		assertNil(t, err)
		if dev2.ConsumeMessageInitiation(msg1) == nil {
			t.Fatal("initiation not consumed")
		}
		msg2, err := dev2.CreateMessageResponse(p21)
		assertNil(t, err)

		ck.failing.Store(true)
		if dev1.ConsumeMessageResponse(msg2) != nil {
			t.Fatal("ConsumeMessageResponse succeeded with failing key")
		}
		if p12.handshake.state != handshakeInitiationCreated {
			t.Fatalf("handshake state advanced to %v", p12.handshake.state)
		}
		if p12.keypairs.Current() != nil || p12.keypairs.next.Load() != nil {
			t.Fatal("keypair created despite key failure")
		}
	})
}

func TestRecomputeStaticStatic(t *testing.T) {
	ck := newCountingKey(t)
	ck.failing.Store(true)
	dev1 := newKeyDevice(t, ck)
	dev2 := randDevice(t)
	defer dev2.Close()
	p12, p21 := handshakePeers(t, dev1, dev2)

	if !isZero(p12.handshake.precomputedStaticStatic[:]) {
		t.Fatal("static-static precomputed despite failing key")
	}
	if _, err := dev1.CreateMessageInitiation(p12); err == nil {
		t.Fatal("initiation created without static-static secret")
	}
	if n := dev1.RecomputeStaticStatic(); n != 1 {
		t.Fatalf("RecomputeStaticStatic with failing key = %d, want 1", n)
	}

	ck.failing.Store(false)
	if n := dev1.RecomputeStaticStatic(); n != 0 {
		t.Fatalf("RecomputeStaticStatic = %d, want 0", n)
	}
	init, resp := fullHandshake(t, dev1, dev2, p12, p21)
	assertKeypairsInteroperate(t, init, resp)
}
