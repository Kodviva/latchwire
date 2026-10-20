# Latchwire patches to wireguard-go

Base: `git.zx2c4.com/wireguard-go` commit `2631ce99a06f27120d581611cf125d68bc6aa565`
(copied without `.git`). Upstream license (MIT, `LICENSE`) is unchanged.

Purpose: make the device's static X25519 key pluggable, so the private key can
live in a hardware token and never enter this process. Keep the patch small so it
rebases onto upstream.

## Added

- `device/statickey.go`: `KeyUse`, `StaticKey`, the internal `softStaticKey`
  (in-memory key behind `SetPrivateKey`), `Device.SetStaticKey`,
  `Device.RecomputeStaticStatic` and the internal `Device.staticSharedSecret`
  helper. The helper returns `errNoStaticKey` when no key is set and rejects an
  all-zero secret, so every call site keeps the upstream zero-secret check.
- `device/statickey_test.go`: tests for the above (call roles, interop with the
  software key, UAPI, error paths, recompute, no stall/deadlock while the key is slow).

`RecomputeStaticStatic` locking: the key can take seconds per call, so it is
never called with a device lock held. It snapshots the key, a generation counter
(`staticIdentity.gen`, bumped by `SetStaticKey`) and the peer list under
`staticIdentity.RLock` + `peers.RLock`, computes each secret with no lock held,
then stores it under `staticIdentity.RLock` + `handshake.mutex.Lock` (the order
`CreateMessageInitiation` uses) only if the generation is unchanged; otherwise
the pass restarts. Handshakes and `SetStaticKey` therefore proceed while a slow
token is being queried. `SetStaticKey` itself still calls the key under the
exclusive lock, as upstream `SetPrivateKey` did for its DH.

## Changed

- `device/device.go`
  - `staticIdentity.privateKey NoisePrivateKey` becomes
    `staticIdentity.key StaticKey`. Reason: the private key must not be a field
    of the device.
  - `SetPrivateKey` now wraps the key in `softStaticKey` and calls
    `SetStaticKey`; its body moved to `SetStaticKey`. An all-zero private key
    now clears the static key (same as `SetStaticKey(nil)`); upstream kept
    using the zero scalar. The "same key, do nothing" shortcut applies only when
    the old and new keys are both `softStaticKey`.
- `device/peer.go` (`NewPeer`): static-static precomputation goes through
  `staticSharedSecret(pk, UseStaticStatic)`.
- `device/noise-protocol.go`
  - `ConsumeMessageInitiation`: DH with the static key uses `UseResponder`.
  - `ConsumeMessageResponse`: DH with the static key uses `UseInitiator`.
  - On error the message is dropped, as upstream already did for a bad DH.
- `device/uapi.go` (`IpcGetOperation`): `private_key` is written only when the
  static key is a `softStaticKey`. Other keys never expose a secret.
- `device/noise_test.go`, `device/device_test.go`: upstream tests that read
  `staticIdentity.privateKey` now use `staticIdentity.publicKey` and
  `staticIdentity.key.(softStaticKey).sk`.

## Not changed

- UAPI `private_key=` (set) still installs a software key, replacing any other
  static key. Callers that use a hardware key must not pass it to `IpcSet`.
