/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * Latchwire patch: pluggable static key (see ../PATCHES.md).
 */

package device

import "errors"

// KeyUse tells a StaticKey which step of the Noise IKpsk2 handshake a
// shared-secret request belongs to, so that an implementation can apply
// per-role policy such as rate limits.
type KeyUse int

const (
	// UseStaticStatic is the precomputation of DH(S_priv, S_pub_peer),
	// done when a peer is added or the static key changes.
	UseStaticStatic KeyUse = iota
	// UseInitiator is DH(S_priv, E_pub_responder) while consuming a
	// handshake response (local side initiated the handshake).
	UseInitiator
	// UseResponder is DH(S_priv, E_pub_initiator) while consuming a
	// handshake initiation (local side responds). The ephemeral key is
	// still unauthenticated at this point, so this use is attacker-triggerable.
	UseResponder
)

// StaticKey is the device's long-term X25519 identity. Implementations
// keep the private scalar wherever they like (for example inside a hardware
// token); it never has to be visible to this package.
//
// SharedSecret must be safe for concurrent use. A non-nil error means the
// handshake step fails; implementations should not return an all-zero
// secret without an error, but the device rejects one anyway.
type StaticKey interface {
	PublicKey() NoisePublicKey
	SharedSecret(peer NoisePublicKey, use KeyUse) ([NoisePublicKeySize]byte, error)
}

var (
	errNoStaticKey      = errors.New("no static key set")
	errInvalidStaticKey = errors.New("static key has zero public key")
)

// softStaticKey is the stock in-memory implementation backing SetPrivateKey.
type softStaticKey struct {
	sk NoisePrivateKey
}

func (k softStaticKey) PublicKey() NoisePublicKey {
	return k.sk.publicKey()
}

// SharedSecret ignores use: a software key has no per-role policy.
func (k softStaticKey) SharedSecret(peer NoisePublicKey, use KeyUse) ([NoisePublicKeySize]byte, error) {
	return k.sk.sharedSecret(peer)
}

// staticSharedSecret computes the DH between the device's static key and
// peer. The caller must hold device.staticIdentity (read or write). On any
// failure the returned secret is zero.
func (device *Device) staticSharedSecret(peer NoisePublicKey, use KeyUse) (ss [NoisePublicKeySize]byte, err error) {
	key := device.staticIdentity.key
	if key == nil {
		return ss, errNoStaticKey
	}
	ss, err = key.SharedSecret(peer, use)
	if err == nil && isZero(ss[:]) {
		err = errInvalidPublicKey
	}
	if err != nil {
		setZero(ss[:])
	}
	return ss, err
}

// SetStaticKey installs k as the device's static identity; nil clears it.
// Peers whose public key equals the new identity are removed, per-peer
// static-static secrets are recomputed, and existing keypairs are expired.
// A key that fails some of the precomputations is still installed; the
// affected peers cannot handshake until RecomputeStaticStatic succeeds.
func (device *Device) SetStaticKey(k StaticKey) error {
	var publicKey NoisePublicKey
	if k != nil {
		publicKey = k.PublicKey()
		if publicKey.IsZero() {
			return errInvalidStaticKey
		}
	}

	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	// skip work only when both keys are software keys with the same secret
	switch cur := device.staticIdentity.key.(type) {
	case nil:
		if k == nil {
			return nil
		}
	case softStaticKey:
		if nk, ok := k.(softStaticKey); ok && cur.sk.Equals(nk.sk) {
			return nil
		}
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	if k != nil {
		for key, peer := range device.peers.keyMap {
			if peer.handshake.remoteStatic.Equals(publicKey) {
				peer.handshake.mutex.RUnlock()
				removePeerLocked(device, peer, key)
				peer.handshake.mutex.RLock()
			}
		}
	}

	// update key material

	device.staticIdentity.key = k
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic, _ = device.staticSharedSecret(handshake.remoteStatic, UseStaticStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

// RecomputeStaticStatic redoes the static-static precomputation for every
// peer, for use after a StaticKey that was failing (for example a removed
// token) becomes usable again. It returns the number of peers for which
// the computation failed; those peers cannot handshake.
func (device *Device) RecomputeStaticStatic() (failed int) {
	// Same lock order and handshake read-locking as SetStaticKey: the
	// exclusive staticIdentity lock already keeps out every other reader
	// and writer of precomputedStaticStatic.
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	device.peers.RLock()
	defer device.peers.RUnlock()

	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.mutex.RLock()
		var err error
		handshake.precomputedStaticStatic, err = device.staticSharedSecret(handshake.remoteStatic, UseStaticStatic)
		handshake.mutex.RUnlock()
		if err != nil {
			failed++
		}
	}
	return failed
}
