# Latchwire patches to piv-go

Base: `github.com/go-piv/piv-go/v2` **v2.5.0**, copied verbatim from the Go
module cache (no `.git`). The unmodified copy is its own commit
(`chore: vendor piv-go v2.5.0 unmodified`), so `git diff` against it shows
exactly these patches. License (Apache-2.0, `LICENSE`, and
`third_party/rsa/LICENSE`) unchanged. Used through
`replace github.com/go-piv/piv-go/v2 => ./third_party/piv-go` in the root
`go.mod` (Ruling R12).

Every patched spot carries a `Latchwire patch` comment.

## 1. Shared PC/SC connection (`piv/pcsc_unix.go`, `piv/pcsc_windows.go`)

- `scContext.Connect`: `SCARD_SHARE_SHARED` instead of
  `SCARD_SHARE_EXCLUSIVE` (Windows: constant `scardShareShared = 2`
  replaces `scardShareExclusive = 1`).
- New `scHandle.Reconnect()` (`SCardReconnect`, shared, T=1,
  `SCARD_LEAVE_CARD`), used after another program reset the card.
  Windows adds `procSCardReconnect`.

## 2. One transaction per operation (`piv/piv.go`, `piv/key.go`)

Upstream `client.Open` called `h.Begin()` once and kept the transaction for
the handle's lifetime, locking every other program out of the card.

- `YubiKey.txDepth` and `YubiKey.begin()`: begin a PC/SC transaction, on
  `SCARD_W_RESET_CARD` (0x80100068) reconnect and begin again, then
  `ykEnsureSelected`. Nested calls (an exported method calling another)
  only count depth; the outermost ends the transaction.
- `ykEnsureSelected`: an empty VERIFY (`00 20 00 80`) answers 9000 or
  63Cx/6983 only when PIV is the selected applet, and it keeps the PIN
  verification state; only if it fails is PIV selected again. This is
  libykpiv's `_ykpiv_ensure_application_selected` approach. Between our
  transactions another program may have selected another applet (OpenPGP,
  OATH) or verified/reset the PIN.
- Every exported `*YubiKey` method that talks to the card begins with
  `end, txErr := yk.begin(); ...; defer end()`: `Serial`, `VerifyPIN`,
  `VerifyBiometrics`, `Retries`, `Reset`, `SetManagementKey`, `SetPIN`,
  `Unblock`, `SetPUK`, `SetRetries`, `Metadata`, `SetMetadata`, `Attest`,
  `KeyInfo`, `Certificate`, `SetCertificate`, `GenerateKey`,
  `SetPrivateKeyInsecure` (and the new `PIVManFlags`/`SetPIVManFlags`).
  `AttestationCertificate` and `PrivateKey` call wrapped methods.
- `KeyAuth.do` (all private-key operations: Sign, Decrypt, SharedKey, ECDH)
  runs PIN verification and the operation in one transaction.
- `KeyAuth.authTx` is replaced by `KeyAuth.pinFor`, which keeps upstream's
  decision and only moves it out of the operation's transaction:
  PINPolicyNever and the match policies take no PIN; PINPolicyAlways always
  does; otherwise an empty VERIFY in a short transaction of its own tells
  whether the card still holds a verified PIN, and only if not is
  `PINPrompt` called. The prompt runs outside any transaction, so the card
  is not locked while the user types. If verification is lost between the
  check and the operation, the card answers 6982 and the caller sees it.
- `piv_test.go` `TestMultipleConnections` (runs only with
  `--wipe-yubikey`): a second `Open` of the same card now succeeds.

## 3. `client.Open` handle leak (`piv/piv.go`)

Upstream returned without closing the handle and the context when
`h.Begin()` failed, and without closing them when selecting the applet
failed (it only ended the transaction). Now every error path after
`Connect` calls `yk.Close()` (handle and context).

## 4. Protected metadata key length (`piv/piv.go`)

`Metadata.marshal` hard-coded `0x88 26 0x89 24` (nil-raw path) and
`0x89 24` (raw path) whatever the key length, so 16- and 32-byte (AES-128/
AES-256) management keys were stored corrupted and read back truncated.
Both paths now use `marshalASN1(0x88, marshalASN1(0x89, key))` /
`marshalASN1(0x89, key)`, i.e. `0x88, len(key)+2, 0x89, len(key)` for these
short keys. New `checkManagementKeyLen` refuses lengths other than 16, 24,
32 (the same set `unmarshal` accepts).

## 5. ykman PIVMAN flags (new `piv/pivman.go`)

- `PIVManFlagMgmtKeyStored = 0x02`.
- `(*YubiKey).PIVManFlags() (byte, error)`: reads object 0x5FFF00, returns
  the 0x81 flags byte or 0.
- `(*YubiKey).SetPIVManFlags(key []byte, flags byte) error`: reads 0x5FFF00,
  ORs `flags` into the 0x81 field (adding it first if absent; creating
  `80 03 81 01 <flags>` if the object is absent or empty), keeps every other
  field (0x82 salt, 0x83 PIN timestamp, ...) byte for byte, then writes it
  back with PUT DATA after authenticating the management key, in one
  transaction. Malformed content is refused, never overwritten.
- Format source: ykman 5.9.2 `ykman/piv.py`, `class PivmanData`: object
  `OBJECT_ID_PIVMAN_DATA` (0x5FFF00) holds `Tlv(0x80, Tlv(0x81, flags) +
  Tlv(0x82, salt) + Tlv(0x83, timestamp))`; `mgm_key_protected` is flag bit
  0x02 and `has_stored_key` returns it; `ykman piv info` prints
  "Management key is stored on the YubiKey, protected by PIN." when
  `has_stored_key` is true. The key itself is in 0x5FC109
  (`PivmanProtectedData`, `Tlv(0x88, Tlv(0x89, key))`).
- `piv/pivman_test.go`: unit tests for 4 and 5 (no card).

## Tests

`cd third_party/piv-go && go test ./...` runs only the unit tests: every
upstream test that opens a card is gated behind the `--wipe-yubikey` flag
and skips without it.
