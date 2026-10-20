# Latchwire threat model

This document says what Latchwire protects, what it does not, and where in the
code each protection lives. It describes the core CLI (macOS and Linux) at the
same revision as this file; its git history shows which code each version
matches. Latchwire is pre-release software and has not
had an independent security review. If a claim here and the code disagree, the
code is right and this document has a bug: please report it (see
[SECURITY.md](../SECURITY.md)).

## 1. The one-sentence claim

The static WireGuard private key is generated inside a YubiKey PIV slot and
never leaves it, so an attacker has to be on a machine that has your card
plugged in (and, for a PIN-verified card, a process that can reach the card
through the operating system's smart-card service) to use it, and cannot take
the key away with them. Which processes can reach the card depends on the
platform's PC/SC access policy: on some systems only your own login session,
on others any local user (section 5.2).

The claim is about **extraction**, not about **use**. Latchwire does not make
the tunnel unusable to malware that is running while the card is present (see
section 5).

## 2. Tier 1 and Tier 2

Latchwire distinguishes how strongly a key provider protects the private key:

- **Tier 1**: a hardware token whose private key never leaves the device.
  The YubiKey PIV backend is Tier 1.
- **Tier 2**: backends such as a TPM / Windows Hello, a Secure Enclave /
  Touch ID, or a FIDO2 hmac-secret (WebAuthn PRF) passkey. The key is stored
  encrypted by hardware, but it is revealed in RAM while it is in use. A Tier 2
  backend never carries the Tier 1 "cannot be copied" claim.

The architecture allows Tier 2 backends, but version 1 contains **Tier 1
only**. The only other provider in the source tree,
`internal/keyprovider/softkey`, is an in-memory key for tests (it is not even
encrypted at rest and is only tagged `Tier2` in code so that it can never be
mistaken for Tier 1); no production code imports it, and the tunnel
configuration has no way to select it. If a Tier 2 provider is
ever added, it must be labelled as Tier 2 wherever the key is shown (CLI, user
interface, web site) and must never be described with the Tier 1 claim.

Where this is enforced: `internal/keyprovider/provider.go` (`Tier1`, `Tier2`,
`Description.Tier`); `internal/keyprovider/piv/provider.go` (the PIV provider
reports `Tier1`); `internal/keyprovider/softkey/softkey.go` (reports `Tier2`,
test only).

## 3. Components and trust

Three programs (all in the one `latchwire` binary) cooperate:

| Component | Runs as | Does |
| --- | --- | --- |
| `latchwire daemon` | root | Owns the TUN device, the wireguard-go device and the routes. Never touches the card. Asks the agent for every X25519 operation that needs the static key. |
| `latchwire agent` | the logged-in user | Talks to the card over PC/SC, asks for the PIN on the terminal, answers the daemon's key requests. |
| `latchwire` CLI | the caller | `keygen`, `devices`, `pubkey` talk to the card directly; `add`, `remove`, `up`, `down`, `status` talk to the daemon. |

They talk over one unix socket, `/var/run/latchwire.sock`, mode `0666`. The
file mode is deliberately open; **who may do what is decided from the peer's
uid, which the kernel reports** (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on
macOS), never from anything the peer says about itself.

Trusted: the operating system kernel and root, the YubiKey hardware and
firmware, the WireGuard protocol and the server you connect to, and you (the
person who knows the PIN).

Where this is enforced: `internal/ipc/peercred_linux.go`,
`internal/ipc/peercred_darwin.go`, `internal/ipc/ipc.go` (`Listen`, `Accept`).

## 4. What Latchwire protects against

| Threat | Why it fails | Where this is enforced |
| --- | --- | --- |
| **Copying the key from disk or from a backup.** | No private key is ever written anywhere: not to a file, a log line, an environment variable or an IPC message. The key exists only on the card. IPC carries public keys and X25519 outputs only. | `internal/ipc/ipc.go` (transport never logs message bodies); `internal/keyprovider/piv/provider.go` (the card does the DH; the key never enters the process); `third_party/wireguard-go/device/statickey.go` and `PATCHES.md` (the device holds a `StaticKey` interface, not a private key; `private_key` is never written by the UAPI for hardware keys). |
| **Configuration files that carry a private key.** | A `PrivateKey` line anywhere in a tunnel configuration is an error, not ignored (ignoring it would hide that you still have a software key). The check runs before the value is looked at, and the error text never echoes it. Hook keys such as `PostUp` are refused too: Latchwire never runs commands from configuration files. Stored configuration files are `0600` in a `0700` directory. | `internal/config/config.go` (`ErrPrivateKeyNotAllowed`, `hookKeys`); `internal/daemon/store.go` (`writeAtomic`, `ensureDir`). |
| **A stolen or imaged laptop without the card.** | The disk holds the tunnel configuration (peer public keys, endpoints, and a preshared key if you use one) but nothing that can do the client's half of the handshake. Without the card, no handshake can be completed. | Same as the two rows above. |
| **A key that was not created on the card.** | Latchwire only accepts keys the card reports as generated on the card (not imported), X25519, PIN policy "once", touch policy "never". There is no import path in v1. | `internal/keyprovider/piv/provider.go` (`Card.Provider` checks `Origin`, algorithm and policies); `internal/keyprovider/piv/generate.go` (`Card.Generate`). |
| **A fake local agent pretending to be your card.** | Each identity in a tunnel configuration carries the expected `PublicKey` (written by the administrator, **never learned from the card**). Before the daemon binds a tunnel to an agent it requires (1) that the agent's `key.public` equals the configured key, and (2) a proof of possession: the agent must compute X25519 against a **fresh random ephemeral point** chosen by the daemon, and the result must equal what the daemon computes from its ephemeral private key and the configured public key. Only a process that can use the real private key on the card can do that. This proves access to the card, **not which user is asking**: another local user who can reach your PIN-verified card passes it too (section 5.2). The ephemeral point is random, not a peer's key, so a fake agent learns nothing that helps it impersonate the server. No device, route or state change exists until this succeeds. | `internal/daemon/manager.go` (`proveOne`, `prove`, `connect`); `internal/config/config.go` (a missing `PublicKey` is a parse error). Tests: `TestFakeAgentWithWrongPublicKeyRefused`, `TestFakeAgentEchoingRightPublicKeyFailsPoP`, `TestProofOfPossessionBeforeDeviceAndWrongPIN` in `internal/daemon/manager_test.go`. |
| **A fake daemon.** | The agent and the CLI refuse a socket served by any uid other than root or the current user, because configuration text and X25519 results travel over it. | `internal/agent/agent.go` (`session`); `cmd/latchwire/main.go` (`dialDaemon`). |
| **Other local users reconfiguring your tunnels, or taking over a tunnel bound to you.** | `tunnel.add` and `tunnel.remove` are administrator-only (root, macOS `admin`, Linux `sudo`, `wheel` or `latchwire`). A non-administrator can connect only through **its own** agent, which must pass the proof of possession, and can disconnect only a tunnel bound to its own uid. A tunnel bound to you (`connecting`, `connected`, `card_removed`) cannot be taken over by a non-administrator. An administrator tries its own agents first. A failed or stalled connect by one user cannot bind or block a tunnel. **Limits:** this does not stop a local user who can reach your card through PC/SC from binding your tunnels that are not bound to you, and tunnel status is readable by any local user (section 5.2). | `internal/daemon/manager.go` (`handle`, `requestConnect`, `requestDisconnect`, `candidatesLocked`, `connect`, `boundTo`); `internal/ipc/admin_linux.go`, `internal/ipc/admin_darwin.go`. Tests: `TestNonAdminCannotAddTunnel`, `TestNonAdminConnectUsesOnlyOwnAgent`, `TestNonAdminCannotSquatTunnel`, `TestAdminTriesOwnAgentsAcrossAllIdentitiesFirst`. |
| **A card that is swapped or re-seated under a connection.** | The vendored piv-go checks the card serial again after any reconnect, inside the new transaction, and refuses to send anything to a different card. A PIN meant for card A is never sent to card B. | `third_party/piv-go/PATCHES.md` (patch 6); `internal/keyprovider/piv/provider.go` (`mapCardErr`: `ErrCardChanged` becomes "unavailable"). |
| **Handshake floods used to wear out or block the card.** | See section 8. | `internal/keyprovider/wgadapter/adapter.go`. |
| **The program storing or leaking your PIN.** | The PIN is never stored: no struct field, file or environment variable. It is read from the terminal (no echo), handed straight to the card, and never logged. The buffer read from the terminal is cleared; the Go string passed on to the card cannot be erased (see 5.3). | `internal/agent/prompt_tty.go`, `internal/agent/agent.go` (package comment, `prompt`), `internal/keyprovider/piv/provider.go` (`promptPIN`), `cmd/latchwire/tty.go`. |

## 5. What Latchwire does NOT protect against

Read this section before you rely on Latchwire.

### 5.1 Malware running as you while the card is plugged in

A hardware key stops **copying**, not **using**. If malicious code runs as your
user (or as root, or, where the platform's PC/SC policy lets other users reach
the card, as any local user; see 5.2) while your card is plugged in and the PIN
has been entered, it can use the card and therefore the tunnel, and it can connect to the same
servers you can. What it cannot do is take the key with it: once the card is
unplugged, or the machine is cleaned, the attacker has nothing reusable. This
is the main difference to a key file, and it is also the limit of the design.

The touch policy is "never" (see 5.2 for why), so using the key needs no
physical gesture.

Malware can also, without knowing the PIN, use up the PIN retry counter by
trying wrong PINs, which blocks the PIV PIN until the PUK is used. That is a
denial of service, not a break.

### 5.2 Card sharing: the PIN is verified once and other programs can use it

Latchwire opens the card in PC/SC **shared** mode and holds a card transaction
only for the duration of each operation. This is a deliberate choice, made so
that macOS smart-card login, `sudo` with a smart card, `ykman`, Yubico
Authenticator and GPG keep working while the tunnel is up.

The consequence is standard PIV behaviour (macOS CryptoTokenKit has the same
property): the PIN policy of the Latchwire key is "once". After the PIN has
been verified, **any process that can reach the card can use that card's
"PIN once" PIV keys without a PIN until the card is removed or reset** (or the
verification is dropped by another program). That is always every process
running as you; depending on the platform it can be every local user (see
"Other local users" below). This covers the Latchwire key
**and every other PIN-once key on the same card**, for example the key in slot
`9a` used for macOS login. The PIN-verified state belongs to the card, not to
Latchwire.

**Other local users.** Whether other local users or sessions can reach the
card depends on the operating system's PC/SC access policy, which Latchwire
does not change:

- **macOS** restricts smart-card access to the console user's session.
- **Linux** depends on how `pcscd` is built and configured. With polkit, the
  `org.debian.pcsc-lite.access_pcsc` and `org.debian.pcsc-lite.access_card`
  actions decide, and their defaults differ between distributions; some allow
  any local user, including SSH sessions. Without polkit, any local user who
  can open the `pcscd` socket can use the card. Check with
  `pkaction --verbose --action-id org.debian.pcsc-lite.access_card` and
  restrict both actions to the console user on a machine with other users.

Where other local users can reach the card, they get, while your card is
plugged in and PIN-verified, the same powers as a process running as you,
including in Latchwire:

- Their agent passes the proof of possession with **your** card, because it
  proves access to the card, not which user asks. So they can connect (and
  bind to their own uid) any of your tunnels that is not currently bound to
  you (state `disconnected` or `error`), and then disconnect it again. A
  tunnel bound to you cannot be taken over by a non-administrator.
- They do not need Latchwire at all: without root, they can run a userspace
  WireGuard implementation that uses your card as its static key and connect
  to any server that accepts your key.
- Tunnel status (names, states, KeyRefs, last handshake) is readable by any
  local user: the daemon shows it to any user with a registered agent, and
  registering an agent needs no card.

A per-tunnel allowed-user policy (only listed users' agents may bind a
tunnel) is planned work; whether and how it is added is an open decision of
the project owner. It would only limit Latchwire's daemon, not the second
point above: the real fix is the PC/SC access policy.

Also note: Latchwire's fresh-card hardening stores a random management key on
the card protected by the PIN, which is what `ykman` calls "stored on the
YubiKey, protected by PIN". By design of PIN-protected management keys, whoever
can use the card in the PIN-verified state can read that stored key, and with it keys
on the card can be generated, replaced or deleted. For the Latchwire slot this
shows up as a failed connect rather than as silent impersonation, because the
tunnel configuration pins the expected `PublicKey` (section 4, fake agent), but
it is a destructive capability for the other slots.

Why Latchwire does not use PIN policy "always" for its own key: a WireGuard
client needs a card operation at about every handshake (roughly every two
minutes per peer), with a 3-second limit per operation, so a PIN prompt each
time is not practical. Touch policy "cached" lasts only about 15 seconds on a
YubiKey, which is shorter than the handshake interval, so in practice it would
also mean a touch at every handshake. Both policies are fixed when the key is
generated.

**Recommendation.** Give the keys you care about, in particular the `9a` login
key, PIN policy **always**. Then they ask for the PIN on every use and a
verified PIN cannot be reused by another process. The general form is:

```sh
ykman piv keys generate --algorithm ECCP256 --pin-policy ALWAYS 9a 9a-public.pem
```

(use the algorithm and touch policy you need; `ykman` asks for the management
key or PIN as it requires; then create or install the matching certificate,
for example with `ykman piv certificates generate`). PIN and touch policy are
properties of the key and cannot be changed afterwards, so this **requires
generating a new key**: the old key in that slot is destroyed, and you need a
new certificate and re-enrolment with whatever uses it (your login
configuration, your CA). Do not do this in a slot that holds a key you cannot
replace. Other mitigations:
unplug the card when you do not need it, and do not run untrusted software as
the user that owns the card.

Latchwire itself only ever uses the retired slots `82` to `95` and never reads
or writes `9a`, `9c`, `9d` or `9e`.

Where this is enforced (or visible): `third_party/piv-go/PATCHES.md` (patches 1
and 2, shared connection and one transaction per operation);
`internal/keyprovider/piv/card.go` (package comment, rules);
`internal/keyprovider/piv/generate.go` (`PINPolicyOnce`, `TouchPolicyNever`);
`internal/keyref/keyref.go` (`MinSlot`, `MaxSlot`).

### 5.3 What is in memory

Latchwire keeps the private key out of the process, but WireGuard itself still
needs some secrets in memory, and an attacker who can read the memory of the
daemon (root, or a debugger, or a core dump or swap file) gets them:

- **Session keys** (the symmetric transport keys). Reading them lets the
  attacker read and forge traffic of the current session only. They are
  replaced at every rekey (about every two minutes of use). wireguard-go drops
  them when they expire or the device is closed, so closing the device when the
  card is removed ends their use; but they are held in Go objects that are
  released, not overwritten, so their bytes can stay in process memory until
  the memory is reused.
- **The cached static-static secret `ss`** = X25519(your private key, the
  peer's public key). wireguard-go computes it once per peer and keeps it
  (`precomputedStaticStatic`); Latchwire computes it with the card when the
  tunnel is brought up. It lives as long as the peer exists in the device
  (wireguard-go's per-handshake cleanup does not erase it) and is released,
  not overwritten, when the device is closed. See section 6 for why this is
  accepted.
- **The X25519 output as it crosses local IPC.** Each result travels from the
  agent to the daemon as a base64 string in a JSON message. Go strings cannot
  be wiped, so copies of these values can stay in the memory of both processes
  until the garbage collector reuses it. This is a known limitation of the
  language; the code clears the byte slices it can reach. These outputs are
  never written to logs or disk by Latchwire (the IPC layer does not log message
  bodies), but the memory of the two processes is not hardened against a reader
  with the rights of the process.
- **The PIN in the agent's memory.** The PIN is not stored by Latchwire, but
  while you type it, it passes through the agent as a Go string, which cannot
  be wiped. It can stay in the agent's memory until that memory is reused.
- **Swap and hibernation.** Latchwire does not lock memory. Secrets above can
  be written to swap or a hibernation image like any other process memory.

None of these is the long-term private key, and none lets an attacker
complete a handshake without the card (section 6), but they are real secrets
for the time they live.

### 5.4 A compromised root account or kernel

Root can read daemon memory, replace the binary, edit stored configurations
and talk to the socket as anyone. Latchwire does not defend against a
compromised root.

### 5.5 Other limits

- **A stolen laptop with the card, and the PIN.** The PIN is the only
  remaining barrier; the card's retry counter (3 attempts on a YubiKey by
  default) limits guessing. A stolen card without the machine gives an
  attacker the key for use only with the PIN, and the key still cannot be
  copied.
- **Traffic outside the tunnel.** Version 1 supports split tunnels only
  (default routes `0.0.0.0/0` and `::/0` are refused), has no kill switch, and
  does not configure DNS. When the tunnel is torn down, for example because the
  card was removed, traffic follows the normal routes.
- **Endpoint name resolution.** Endpoint host names are resolved by the system
  resolver at every connect. A hostile resolver can send the tunnel to the
  wrong address, but cannot read or forge traffic, because the server is
  identified by its public key. It can deny service.
- **Preshared keys.** If a configuration uses `PresharedKey`, that key is a
  secret stored on disk (`0600`, root). It is not the identity key, and
  stealing it does not allow a connection without the card, but it is a secret
  and is not hardware protected.
- **Counterfeit or compromised tokens and firmware.** Latchwire trusts what the
  card reports about where a key came from. It does not (yet) verify a PIV
  attestation certificate. This is a possible future addition.
- **The PIN prompt.** The agent asks for the PIN on its terminal when the
  daemon's request needs it. A process that can request a connect as your user
  can cause a prompt, and an administrator whose own card is missing can cause
  a prompt in another user's agent. Do not type your PIN into a prompt you did
  not expect.
- **Builds and supply chain.** Latchwire vendors patched copies of wireguard-go
  and piv-go (`third_party/*/PATCHES.md` lists every change). Reproducible
  builds and signed releases are goals and do not exist yet.
- **Windows, other platforms, and GUI.** Not implemented in the core CLI.

## 6. Why the cached `ss` alone cannot build a tunnel

A WireGuard handshake (Noise IK) uses the static private key in two kinds of
Diffie-Hellman operation:

1. `ss` = DH(static private, peer's static public). One value per peer,
   computed once and cached.
2. `es` / `se`: DH(static private, the other side's **ephemeral** public key).
   This value is different in **every handshake**, because the other side
   picks a new ephemeral key each time.

Latchwire computes `ss` with the card once, when the tunnel is brought up or
the PIN has just been entered (`UseStaticStatic`), and the card is asked again
for the second kind at every handshake: as responder when it consumes an
initiation (`UseResponder`), as initiator when it consumes the response
(`UseInitiator`).

If an attacker reads `ss` from memory, they still cannot complete a handshake
as you. Playing the client, they could assemble an initiation message that the
server accepts as authentic (that needs `ss` and values they can compute
themselves), but to read the server's response and derive the transport keys
they need `se` = DH(your static private key, the server's fresh ephemeral
key). That value did not exist before the handshake began, and without the
card it cannot be computed. So `ss` cannot be turned into a working session.
One side effect is worth knowing: a forged but authentic-looking initiation
moves the server's replay timestamp for your key. The attacker chooses that
timestamp (a TAI64N value), so a far-future value makes the server reject your
real initiations until the server's in-memory state is reset (the server
restarts or the peer is removed and added again) or the server's clock passes
the forged timestamp. This is a denial of service, not impersonation: the
attacker still gets no session. It needs the attacker to have read the
daemon's memory already, at which point the session keys of the
running session are exposed as well (section 5.3). The session ends at the
next rekey or card removal.

This is the accepted trade-off of caching `ss` in memory instead of asking the
card for it at every handshake.

Where this is enforced: `third_party/wireguard-go/PATCHES.md` and
`device/peer.go` and `device/noise-protocol.go` (the three use sites), `device/statickey.go`
(`KeyUse`), `internal/keyprovider/wgadapter/adapter.go`.

## 7. Local authorization in short

| Request | Who may make it |
| --- | --- |
| `tunnel.add`, `tunnel.remove` | Administrators only: root, macOS `admin`, Linux `sudo`, `wheel` or `latchwire`. |
| `tunnel.connect` | An administrator, or a user whose own agent is registered and passes the proof of possession. Non-administrators use only their own agent and cannot take over a tunnel bound to another user. The proof shows access to the card, not which user owns it: a user who can reach your card through PC/SC can bind your unbound tunnels (section 5.2). |
| `tunnel.disconnect` | An administrator, or the user the tunnel is bound to. |
| `tunnel.status` | An administrator or a user with a registered agent. Registering needs no card, so in practice any local user. |
| `key.public`, `key.x25519` | The daemon, to the agent. The agent refuses a daemon that is neither root nor its own user. |

Where this is enforced: `internal/daemon/manager.go` (`handle`), tests listed
in section 4.

## 8. Handshake flood limits

An attacker who can send UDP to the client can make it process many handshake
initiations. In WireGuard, the responder does a DH with the static key on an
**unauthenticated** ephemeral key, so each one costs a card operation (tens to
hundreds of milliseconds). Latchwire bounds that:

- The **responder** role (consuming a handshake initiation, `UseResponder`) and
  the **initiator** role (consuming a handshake response, `UseInitiator`) have
  **separate token buckets: 5 operations per second, burst 10, each**.
- In-flight card calls are capped **per role: 2 for the responder, 2 shared by
  the initiator and the static-static computation** (separate pools).
  When a pool is full, the call fails at once (`ErrUnavailable`) rather than
  queueing. A call that timed out but whose card operation has not returned
  still counts until it returns.
- Every card operation has a **3-second timeout**. A late result is zeroed, not
  delivered.
- The static-static computation (`UseStaticStatic`) is not rate limited because
  it happens when a peer or key is set, not in response to network input.

Because the buckets and pools are separate, a flood of forged initiations can
use up the responder budget but cannot starve the client's own handshakes
(`TestResponderFloodDoesNotBlockInitiator`, and
`TestInitiationFloodDoesNotStarveHandshake` in `internal/daemon`, which sends
600 initiations in 3 seconds and sees about 24 card calls, within the limit of
28, with the client's own handshake unaffected).

Consequences you should know:

- While a flood lasts, legitimate **incoming** handshake initiations from peers
  beyond the budget are dropped. A normal client initiates its own handshakes,
  so this is rarely visible. Existing sessions are not affected.
- The initiator bucket is consumed by handshake **responses**. An attacker who
  can forge one needs to know a receiver index, which only an on-path attacker
  sees, and an on-path attacker could drop the client's packets anyway. The
  bucket therefore bounds the card's load; it does not add a new way to deny
  service.

Where this is enforced: `internal/keyprovider/wgadapter/adapter.go`
(`DefaultLimits`, `SharedSecret`); the daemon passes `wgadapter.DefaultLimits`
in `internal/daemon/manager.go` (`build`).

## 9. PIN, PUK and fresh cards

- **The default PIN is never tried.** `VerifyPIN`-style calls and PIN changes
  only ever receive a PIN or PUK that you typed. If your card still has the
  factory PIN, you type it yourself. Latchwire never guesses it, so it cannot
  burn your retry counter by trying factory values.
- **Fresh-card detection** uses only the factory *management key*, which has
  no retry counter. If it works, the card is considered unconfigured.
- **A fresh card is hardened before a key is generated.** `latchwire keygen`
  explains why (otherwise anyone who knows the factory settings could replace
  the new key), then: checks the current PUK first (so a wrong PUK stops with the
  PIN untouched); changes the PIN and the PUK to new values you choose (6 to 8
  characters, not the factory values, each entered twice); generates a random
  **AES-256** management key; stores it on the card protected by the PIN, and
  reads it back before replacing the factory key; and sets the flag that makes
  `ykman` report "Management key is stored on the YubiKey, protected by PIN",
  so you are never asked for a 24-byte key and `ykman` keeps working.
- **A custom management key is asked for, never guessed.** If the card has a
  management key that is neither the factory key nor stored under the PIN,
  `latchwire keygen` asks for it on the terminal (no echo, hexadecimal, 16, 24
  or 32 bytes), tries it once, and clears the decoded key afterwards. It is
  never stored or printed.
- **Errors after a change say what is already active.** If anything fails after
  the PIN has been changed, the error says that the PIN (and, if applicable,
  the PUK) now has the new value.
- **The last attempt is flagged.** The remaining retries are shown; with one
  left you get an explicit warning, and with none left you are never asked.
- **Existing slots are not overwritten without `--force` and a confirmation.**
  The default is the first empty retired slot. With `--force` on an occupied
  slot, `latchwire keygen` first shows what the slot holds and warns that the
  key is destroyed, then requires `yes` typed on the terminal (read from
  `/dev/tty`, never from standard input, so a pipe cannot confirm). Without a
  terminal, or with any other answer, nothing is changed.
- **A wrong PIN ends the request.** After a wrong or cancelled entry, requests
  that were already waiting get the same outcome without asking again, so a
  queued burst cannot spend your retries.

Where this is enforced: `internal/keyprovider/piv/generate.go` (`harden`,
`managementKey`, `Generate`, `Occupied`), `internal/keyprovider/piv/card.go` (package
comment), `internal/agent/agent.go` (PIN rules in the package comment,
`prompt`, `x25519`), `cmd/latchwire/keygen.go` (`askManagementKey`,
`confirmForce`), `cmd/latchwire/tty.go` (`readLineTTY`), `internal/msg/en.go`
(`FreshCardExplain`, `PIVPINAlreadyChanged`, `PIVPINAndPUKAlreadyChanged`,
`LastPINRetry`), `third_party/piv-go/PATCHES.md` (patches 4 and 5).

## 10. Card removal

The agent checks which cards are present every second. When a card that backs a
connected tunnel disappears, the daemon closes the wireguard-go device **first**
(so no packet uses it any more, and its session keys are dropped), and only then
removes the addresses and routes. The design target is a teardown within
**2 seconds** of removal; the test `TestCardRemovalTearsDownWithin2s` measured
about 1 second with a fake card. The tunnel is rebuilt from scratch, with a new
device, when the card is back (and you enter the PIN again).

Limitations:

- **When the agent exits, the tunnel is torn down after a 10-second grace
  period.** Without an agent, nobody watches the card, so the daemon does not
  let the session outlive it. For 10 seconds after the agent's connection
  closes the tunnel stays up, so that restarting the agent does not cost a
  reconnect; during that time no new handshake can succeed (the daemon has
  nobody to ask for card operations), but the current session keeps carrying
  traffic. If no agent of the same user reports the tunnel's card by then, the
  daemon tears the tunnel down to state `card_removed` exactly as for a removed
  card (device closed first, then routes). An agent that comes back later and
  reports the card reconnects the tunnel; no PIN is asked if the card is still
  PIN-verified. An agent that comes back reporting the card missing takes the
  tunnel down at once.
- **A card removed while no agent is running is noticed late**: at the latest
  when the grace period ends (the tunnel is torn down then), or earlier if an
  agent of that user registers again without the card. The daemon cannot see
  the card itself, so a card pulled within the grace period leaves the current
  session usable for up to those 10 seconds.
- **Sleep and power loss.** If the card loses power, its PIN verification is
  lost and the PIN is asked again on the next use.

Where this is enforced: `internal/agent/agent.go` (`session`, poll interval),
`cmd/latchwire/main.go` (`agentPoll`), `internal/daemon/manager.go`
(`agentRegister`, `reconcile`, `dropAgent`, `closeDevice`, `teardown`). Tests:
`TestCardRemovalTearsDownWithin2s`, `TestAgentGoneFailsHandshakeDuringGrace`,
`TestAgentExitTearsDownAfterGrace`, `TestAgentRestartWithinGraceKeepsTunnel`
in `internal/daemon/manager_test.go` (`agentGrace` in `manager.go` is the
10-second constant).

## 11. Verification you can do

- `go test ./...` runs the unit and integration tests, including the
  security-relevant ones named above, with fake cards.
- [docs/hardware-checklist.md](hardware-checklist.md) lists the checks that need
  real YubiKeys, including card removal and re-seating while connected and
  smart-card login or `sudo` while the tunnel is up.
- Run `ykman piv info` before and after `latchwire keygen`: the slots `9a` and
  `9d` must be unchanged and the new key must be in a retired slot.

## 12. Reporting

If you find a way around any of the protections in section 4, or a claim here
that is wrong, please follow [SECURITY.md](../SECURITY.md).
