# Latchwire threat model

This document says what Latchwire protects, what it does not, and where in the
code each protection lives. It describes the core CLI with network parity
(full tunnel, DNS, kill switch, on-demand; macOS and Linux) at the
same revision as this file; its git history shows which code each version
matches. The Windows port has its own section (5.8): it compiles and its
pure logic is tested, but **it has never run on Windows**, so everything said
about Windows is design, not observed behaviour. Latchwire is pre-release software and has not
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

Three programs (all in the one `latchwire` binary) cooperate. The desktop app
(`desktop/`, a separate binary) is a fourth way to run the agent:

| Component | Runs as | Does |
| --- | --- | --- |
| `latchwire daemon` | root (LocalSystem as a service on Windows) | Owns the TUN device, the wireguard-go device, the routes and policy rules, the tunnel's DNS settings and the kill switch's firewall rules (section 5.7). Never touches the card. Asks the agent for every X25519 operation that needs the static key. |
| `latchwire agent` | the logged-in user | Talks to the card over PC/SC, asks for the PIN (a dialog when started by launchd or systemd, else the terminal), answers the daemon's key requests. |
| Desktop app | the logged-in user | Hosts the same agent code in its own process and shows its own PIN form instead of the terminal or system dialog. Creates keys on the card, reads which keys a card holds, and calls the daemon over the same socket and with the same permissions as the CLI. See section 5.8. |
| `latchwire` CLI | the caller | `keygen`, `devices`, `pubkey` talk to the card directly; `add`, `remove`, `up`, `down`, `status`, `policy`, `network` talk to the daemon. |

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
| **Other local users reconfiguring your tunnels, or taking over a tunnel bound to you.** | `tunnel.add`, `tunnel.remove` and `tunnel.policy.set` are administrator-only (root, macOS `admin`, Linux `sudo`, `wheel` or `latchwire`). A non-administrator can connect only a tunnel whose policy lists it as an **allowed user** (section 5.2), only through **its own** agent, which must pass the proof of possession, and can disconnect only a tunnel bound to its own uid. A tunnel bound to you (`connecting`, `connected`, `card_removed`) cannot be taken over by a non-administrator. An administrator tries its own agents first. A failed or stalled connect by one user cannot bind or block a tunnel. **Limits:** this does not stop a local user who can reach your card through PC/SC from binding your tunnels that are not bound to you, and tunnel status is readable by any local user (section 5.2). | `internal/daemon/manager.go` (`handle`, `requestConnect`, `requestDisconnect`, `candidatesLocked`, `connect`, `boundTo`); `internal/daemon/policy.go` (`allows`, `revoke`); `internal/ipc/admin_linux.go`, `internal/ipc/admin_darwin.go`. Tests: `TestNonAdminCannotAddTunnel`, `TestNonAllowedUserCannotConnect`, `TestDenyRevokesUserBinding`, `TestNonAdminConnectUsesOnlyOwnAgent`, `TestNonAdminCannotSquatTunnel`, `TestAdminTriesOwnAgentsAcrossAllIdentitiesFirst`. |
| **A card that is swapped or re-seated under a connection.** | The vendored piv-go checks the card serial again after any reconnect, inside the new transaction, and refuses to send anything to a different card. A PIN meant for card A is never sent to card B. | `third_party/piv-go/PATCHES.md` (patch 6); `internal/keyprovider/piv/provider.go` (`mapCardErr`: `ErrCardChanged` becomes "unavailable"). |
| **Handshake floods used to wear out or block the card.** | See section 8. | `internal/keyprovider/wgadapter/adapter.go`. |
| **Traffic leaving outside the tunnel** (a removed card, a failed or still connecting tunnel, a crashed daemon). | With the kill switch on (by default for a full tunnel with one peer), only the tunnel interfaces, loopback, the endpoints and link setup pass; it keeps blocking while the tunnel is connecting, waiting for its card or failed, and after a crash of the daemon. Only `latchwire down`, `remove` or an orderly stop of the service lifts it. See section 5.7 for the details and the limits. | `internal/daemon/policy.go:103` (`armed`); `internal/daemon/manager.go:2174` (`killSwitchStatus`), `:410` (startup keeps the kill switch), `:2655` (`startKillSwitch`); `internal/killswitch/nft.go:100`, `internal/killswitch/pf.go:79`. Linux end-to-end: `testKillSwitchCard`, `testCrash` in `test/e2e/linux/e2e_test.go`. |
| **DNS queries going to the local network's resolver while a full tunnel is up.** | A full tunnel's DNS servers answer every name (macOS: the primary service's DNS; Linux: systemd-resolved with `~.`, or openresolv exclusively). With the kill switch on, DNS can only leave through a tunnel interface. Limits in section 5.7. | `internal/daemon/manager.go:2029` (`dnsRoleLocked`); `internal/netcfg/linuxplan_dns.go:50`, `internal/netcfg/darwinplan_dns.go:521`; `internal/killswitch/nft.go:90` (no DNS exception). Linux end-to-end: `testDNS`, `testFull`. |
| **The program storing or leaking your PIN.** | The PIN is never stored: no struct field, file or environment variable. It is read from the terminal (no echo), handed straight to the card, and never logged. The buffer read from the terminal is cleared; the Go string passed on to the card cannot be erased (see 5.3). The desktop app reads it into one byte array that it wipes and draws only dots; the same limit applies from there on (see 5.9). | `internal/agent/prompt_tty.go`, `internal/agent/agent.go` (package comment, `prompt`), `internal/keyprovider/piv/provider.go` (`promptPIN`), `cmd/latchwire/tty.go`, `desktop/ui/secret.go`, `desktop/ui/dialogs.go`. |

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

- **macOS** is expected to restrict smart-card access to the console user's
  session. This has not been verified for Latchwire; check it on your system
  (see the hardware checklist).
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

**Allowed users.** Each tunnel's policy lists the users who may connect it
besides the administrators (`AllowedUsers`). `sudo latchwire add` sets it to
the user who ran `sudo` (`SUDO_UID`); without `sudo` (a root shell) the list
is empty and only administrators may connect. `sudo latchwire policy <name>
--allow-user NAME` / `--deny-user NAME` change it. The check is part of every
non-administrator connect (the user's own `up`, AutoConnect, on-demand and
the reconnect when the card comes back) and is made again, with the policy
file read afresh, when the tunnel is reserved, before any device or route
exists. A refused user gets no PIN prompt. Denying a user who holds a tunnel
takes it from them at once, unless an administrator made that binding: an
unarmed tunnel goes down; a tunnel whose kill switch is on stays blocking,
bound to nobody, until an administrator runs `latchwire down` (a deny removes
access, it is not a way out of the kill switch). This includes a tunnel that
failed (`error`) while bound to the denied user, so a restart of the daemon
cannot hand it back to them. A user whose own connect failed may take that
failed tunnel down while still an allowed user, and a connect its user gave
up on (Ctrl-C during `latchwire up`) leaves the tunnel as it was. A policy file that cannot be
read safely counts as "kill switch on, nothing automatic, administrators
only".

The first point above is narrowed by this list: another user's agent can bind
your tunnel only if that user is on its allowed users. The list limits only
Latchwire's daemon, not the second point: the real fix is still the PC/SC
access policy.

Where this is enforced: `internal/daemon/manager.go:900` (`add`, owner as
the only allowed user), `:1460` and `:1526` (`connect`: the gate before any
agent call and again at the reservation with a fresh policy read), `:883`
(`tunnel.policy.set` administrator-only); `internal/daemon/policy.go:69`
(`allows`), `:288` (`revoke`, also of a failed tunnel; `:304` keeps an
armed tunnel blocking, unbound), `:66` (`failClosedPolicy`); `cmd/latchwire/policy.go:193`
(`sudoUID`). Tests: `TestAddRecordsOwnerAsAllowedUser`,
`TestNonAllowedUserCannotConnect`, `TestDenyRevokesUserBinding`,
`TestAdminBindingSurvivesDeny` in `internal/daemon/policy_test.go`; Linux
end-to-end: `testAllowedUsers` in `test/e2e/linux/e2e_test.go`.

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
- **Traffic outside the tunnel.** Without the kill switch, traffic follows
  the normal routes whenever the tunnel is not connected, for example after
  the card was removed. Full tunnels, DNS and the kill switch, and what they
  do not cover, are in section 5.7.
- **Endpoint name resolution.** Endpoint host names are resolved by the system
  resolver at every connect. A hostile resolver can send the tunnel to the
  wrong address, but cannot read or forge traffic, because the server is
  identified by its public key. It can deny service. While the kill switch
  blocks, the resolver reaches no DNS server, so the last address found for
  that endpoint is used (`internal/daemon/manager.go:2207`,
  `resolveTunnel`); a Linux full tunnel resolves with its fwmark, outside
  the tunnel (`internal/daemon/resolver_linux.go:15`), and a kill switch
  that blocks already lets that mark through before the lookup.
- **Preshared keys.** If a configuration uses `PresharedKey`, that key is a
  secret stored on disk (`0600`, root). It is not the identity key, and
  stealing it does not allow a connection without the card, but it is a secret
  and is not hardware protected.
- **Counterfeit or compromised tokens and firmware.** Latchwire trusts what the
  card reports about where a key came from. It does not (yet) verify a PIV
  attestation certificate. This is a possible future addition.
- **The PIN prompt.** The agent asks for the PIN on its terminal, or in the
  desktop app's window, when the daemon's request needs it. A process that can request a connect as your user
  can cause a prompt, and an administrator whose own card is missing can cause
  a prompt in another user's agent. Do not type your PIN into a prompt you did
  not expect.
- **Builds and supply chain.** Latchwire vendors patched copies of wireguard-go
  and piv-go (`third_party/*/PATCHES.md` lists every change). Reproducible
  builds and signed releases are goals and do not exist yet.
- **Windows and GUI.** The Windows port compiles but has never run (section
  5.8). The GUI is a separate desktop app (section 5.9).

### 5.6 Trusted networks (on-demand)

On-demand connects a tunnel on networks that are not in its policy's trusted
networks and takes it down on a trusted one. A network is recognised by its
network ID: the first 16 hex digits of SHA-256 over the default gateway's IP
address and MAC address (`latchwire network` prints it). The SSID is not used,
because a root service cannot read it on macOS.

- **The ID is not authenticated.** Anyone on the local network segment can
  give their own router, or a rogue access point, the IP and MAC address of
  your trusted network's gateway. Latchwire then recognises that network as
  trusted. This is the same weakness as the SSID and BSSID rules of the
  official WireGuard clients. Latchwire does not authenticate the network; an
  authenticated network probe is out of scope for version 1.
- **Trusting a network means accepting cleartext traffic there.** On a trusted
  network, on-demand does not connect, and it takes down tunnels it connected
  itself. Their traffic then leaves the machine unprotected. Trust only
  networks whose operator and local segment you would trust without a VPN.
  On-demand trust is a convenience, not a security boundary.
- **An explicit kill switch wins.** A tunnel whose kill switch is set to `on`
  is never taken down because the network is trusted: on such a network
  on-demand only does not connect it. A spoofable signal must not lift an
  explicit fail-closed choice. Tunnels whose kill switch is `auto` or `off`
  are taken down like a `down` and their kill switch stops blocking.
- **An unidentified network is never trusted.** When there is a gateway but
  its MAC address cannot be read (`unknown`), Latchwire looks once more after
  about two seconds, and then treats the network as untrusted. `unknown` and
  `none` (no network) can never be added to the trusted networks. With no
  network, on-demand does nothing.
- **On-demand connects only for users who may connect the tunnel.** The
  key comes from the agent of an allowed user or an administrator (section
  5.2); a manual `down`
  keeps on-demand from reconnecting it until the machine is on another
  identified network.

Where this is enforced: `internal/netmon/identity.go:43` (`NetworkID`;
`:22` `unknown`, `:18` `none`); `internal/daemon/ondemand.go:106`
(`currentNetwork`, the second look), `:140` (`evaluateOnDemand`), `:204`
(a kill switch set to `on` is never taken down on a trusted network);
`internal/daemon/policy.go:92` (`ValidTrustedNetwork`);
`internal/msg/en.go:339` (`PolicyTrustWarning`, printed with the policy
usage). Tests: `internal/daemon/ondemand_test.go`; Linux end-to-end:
`testOnDemand` in `test/e2e/linux/e2e_test.go` (untrusted network connects,
`--trust-current-network` takes the tunnel down).

### 5.7 Full tunnel, DNS and the kill switch

This section covers what Latchwire changes in the system's network
configuration and where that protection ends. "Where" lines name
`file:line` at this revision. The Linux behaviour is checked end to end in a
privileged container (`test/e2e/linux`, section 11); the macOS behaviour is
checked by hand (docs/hardware-checklist.md, sections 8 to 15).

**Journal and cleanup.** Every change to the system (route, policy rule,
sysctl, nft or pf rules, DNS) is written to the journal
`/var/run/latchwire/journal.json` (`0600`, root) before it is made, and
undone from there. At startup the daemon undoes whatever a crashed run left,
except an active kill switch (below). An undo that fails when a tunnel goes
down (a DNS restore, a policy rule) stays journaled and is retried every 30
seconds while the daemon runs, whatever interface it was on, and again at
the next start. `/var/run` does not survive a reboot,
and neither do the routes, rules or firewall state it describes.
Where: `internal/netcfg/netcfg.go:381` (`applyStepLocked`: the undo reaches
the journal first), `internal/netcfg/journalpath_unix.go:6`, `:262` (`Cleanup`:
failed persistent undos stay journaled; tunnels that are up are left
alone), `internal/daemon/manager.go:410` (the kill switch is kept), `:571`
(`retryLeftovers`, the 30-second retry). Linux end-to-end:
`testCrash` (the policy rules and the tunnel DNS left by `kill -9` are gone
after the restart).

**Full tunnel.** A tunnel is a full tunnel when a peer's `AllowedIPs` holds
`0.0.0.0/0` or `::/0`. Only one full tunnel can be up at a time, and the
`AllowedIPs` of two tunnels that are up may not overlap.

- Linux: the default route of each family goes into a routing table of its
  own (the first free one from 51820; its number is also the fwmark). Two
  policy rules, tagged `protocol 251`, send every packet without the mark to
  that table, except where the main table has a more specific route
  (`suppress_prefixlength 0`). The WireGuard socket and the endpoint
  resolver carry the mark, so the endpoint stays reachable outside the
  tunnel. `src_valid_mark` is set, and an nft table drops packets addressed
  to the tunnel that arrive on other interfaces (reverse-path filter);
  without `nft` the tunnel still runs without that filter and a warning is
  logged.
- macOS: `0.0.0.0/1` and `128.0.0.0/1` (`::/1`, `8000::/1`) on the utun
  interface, and a host route to each endpoint through the physical
  gateway, which follows gateway changes. With no gateway the endpoint gets
  a blackhole route, so its packets never enter the tunnel.
- **The local subnet stays outside the tunnel** (it has a more specific
  route on both platforms, as with `wg-quick`). With the kill switch on, it
  is blocked instead (checked in `testFull`).
- **A family without a default route in the configuration is not
  tunnelled.** With only `0.0.0.0/0`, IPv6 leaves through the physical
  interface unless the kill switch is on. Add `::/0` to keep IPv6 in the
  tunnel.

Where: `internal/daemon/manager.go:1858` (`routesAll`), `:1976`
(`conflictLocked`); `internal/netcfg/linuxplan_fulltunnel.go:62`
(`LinuxTable`), `:152` (`src_valid_mark`), `:171` and `:175` (the rules),
`:182` (reverse-path filter), `internal/msg/en.go:120` (`NetNoRPFilterFmt`);
`internal/netcfg/darwinplan_fulltunnel.go:57` (endpoint host routes; `:76`
blackhole), `:89` (the `/1` routes), `:501` (`refreshDarwin`). Linux
end-to-end: `testFull`, `testMulti` (a full and a split tunnel together).

**DNS.** A full tunnel's DNS servers answer every name. A split tunnel's do
so only when no other tunnel holds that role; otherwise they answer the
tunnel's search domains only, or are not used (status `ignored`). A full
tunnel takes the role from a split tunnel when it connects, **also when it
has no DNS servers of its own**: the system's DNS then goes into the full
tunnel with all other traffic, rather than every name going to the split
tunnel's resolver. A split tunnel that connects while a full tunnel is up
does not take the role either. When the full tunnel goes down, the split
tunnels that gave the role up to it get it back. A tunnel whose DNS waits
for another tunnel's DNS undo to be retried shows `busy` until then.
`latchwire status` shows the outcome in the DNS column.

- Linux with systemd-resolved: `resolvectl dns`, `domain ~.` and
  `default-route` on the tunnel link. Programs that bypass resolved (a
  `resolv.conf` that does not point at its stub, a resolver of their own)
  are not covered.
- Linux with openresolv: `resolvconf -x` (exclusive). With the classic
  Debian `resolvconf` there is no exclusive mode: the tunnel's servers are
  added to the others, so names can still go to the local network's
  resolver (status `shared`, with a warning). Scoped DNS (search domains
  only) cannot be expressed with either `resolvconf` and is not applied
  (`ignored`, with a warning). With none of them installed, a tunnel with
  DNS servers is refused.
- macOS: the tunnel's servers are written to the DNS of the primary network
  service (`State:` in the configuration store) and follow it when the
  primary service changes. Scoped DNS uses a resolver for the search
  domains. **DNS set by hand in System Settings wins** (status
  `overridden`, with a warning). A DHCP renewal can rewrite the service's
  DNS without a network event; the daemon checks every 30 seconds and puts
  the tunnel's servers back, so names can leak for up to that long.
  Configuration profiles (`NEDNSSettings`, MDM), another VPN's resolvers
  and a browser's own DNS over HTTPS are outside Latchwire's control.
- **The kill switch has no DNS exception**: DNS passes only through a
  tunnel interface. With the kill switch on, none of the leaks above can
  leave through the physical interface (names then fail to resolve
  instead).

Where: `internal/daemon/manager.go:2029` (`dnsRoleLocked`), `:1892`
(`demotionLocked`), `:1911` (`demote`), `:2080` (`promoteDNS`), `:2146`
(`dnsStatus`), `:504` and `:507` (network changes and the 30-second check),
`:599` (`retakeDNS`); `internal/netcfg/netcfg.go:243` (`SetDNSRole`),
`:564` (one primary owner per daemon); `internal/netcfg/linuxplan_dns.go:50`
(`linuxDNS`: resolved, then openresolv `:209`, then classic `:74`, else
refused `:62`); `internal/netcfg/darwinplan_dns.go:521` (`darwinDNS`),
`:468` (`manualDNS`), `:614` (`moveDNSLocked`). Linux end-to-end: `testDNS`
(openresolv: only the tunnel's server in `resolv.conf`, a name resolves
through the tunnel, the original list returns after `down`).

**Kill switch.** The policy value is `auto` (default), `on` or `off`. `auto`
means on for a tunnel with exactly one peer whose `AllowedIPs` hold
`0.0.0.0/0` or `::/0`. While any tunnel's kill switch is on, only these pass:
loopback, the tunnel interfaces, UDP to the endpoints (and from them only to
the tunnel's own listen port), the Linux full tunnel's marked packets, DHCP
from root's sockets to the broadcast address or private and link-local
ranges, and IPv6 neighbour discovery and MLD on the link. Everything else is
rejected (outbound, so programs fail at once) or dropped (inbound and, on
Linux, forwarded). A kill switch set to `on` on a split tunnel therefore
blocks all traffic outside that tunnel's `AllowedIPs`. Linux uses the nft
table `inet latchwire`, macOS the pf anchor `com.apple/250.latchwire` with an
enable reference of its own (`pfctl -E`), released when the kill switch
comes off. A tunnel whose kill switch is on is not connected when the
firewall cannot be set up (Linux without `nft`; macOS when the main pf
ruleset lacks the `com.apple/*` anchor point).

Where: `internal/daemon/policy.go:103` (`armed`);
`internal/daemon/manager.go:2625` (`armKillSwitch`: refused without a
firewall), `:2174` (`killSwitchStatus`); `internal/killswitch/nft.go:18`,
`:51` to `:54` (DHCP), `:90` (no DNS rule), `:100` (`nftScript`), `:176`
(forward chain); `internal/killswitch/pf.go:24`, `:48` and `:50` (DHCP,
`user root`), `:79` (`pfRules`), `:110`, `:228` (anchor point), `:240`
(`pfctl -E`). Linux end-to-end: `testFull` (armed: the local subnet is
blocked), `testKillSwitchCard`.

**Fail-closed.** The kill switch blocks while its tunnel is connecting,
waiting for its card (`card_removed`) or failed (`error`), not only while
it is connected. Only `latchwire down`, `latchwire remove` or an orderly
stop of the daemon lift it.

- **The daemon crashes** (`kill -9`, a panic): the firewall rules stay in
  place and keep blocking. At the next start the daemon keeps them and
  restores the tunnels it blocked for as `card_removed`, with their key and
  user, so the card's return reconnects them and their user can take them
  down. Everything else (routes, rules, DNS) is undone.
- **Something removes the rules** (`pfctl -d`, `nft delete table`): the
  daemon checks every 30 seconds and sets them again. On macOS the check also
  sees a main ruleset replaced (`pfctl -f`) by one that no longer evaluates
  `com.apple/*`: setting the rules again cannot fix that, so the daemon logs
  a warning once and `latchwire status` warns on every tunnel whose kill
  switch is on, until the anchor point is back.
- **A connect that fails** leaves the tunnel in `error`, still blocking;
  the user whose connect it was (while still an allowed user) or an
  administrator can take it down. A connect its requester gives up on after
  the tunnel was reserved (Ctrl-C during `latchwire up`, after the PIN)
  puts the tunnel back as it was instead.
- **A deny of the user who holds an armed tunnel** keeps it blocking
  (section 5.2), unbound, also when it had failed.
- **The kill switch does not survive a reboot**, and it does not block
  before a tunnel with the kill switch has started connecting: until then
  the machine's traffic is not blocked.
- **A corrupt journal fails open**: when the journal cannot be read at
  startup, what it held is unknown, so the daemon removes the well-known
  kill switch objects and logs a warning, rather than leaving a block that
  nothing could lift.

Where: `internal/daemon/manager.go:2174` (`killSwitchStatus`), `:410`,
`:2655` (`startKillSwitch`; `:2657` corrupt journal, `:2665` crash),
`:2694` (`restoreKillSwitchTunnels`), `:2566` (`verifyKillSwitch`), `:741`
(`requestDisconnect`: who may lift a failed tunnel), `:639` (`shutdown`);
`internal/killswitch/pf.go:271` (`Verify`: also a main ruleset that no longer
evaluates the anchor); `internal/daemon/store.go:258` (`killswitch.state`, the record
of the tunnels to restore). Linux end-to-end: `testKillSwitchCard` (card
removed: blocked; card back: connected; `down`: open), `testCrash` (blocked
while the daemon is dead and after its restart; the card's return
reconnects), `testShutdown` (an orderly stop lifts it).

**What the kill switch does not cover.**

- Root and the kernel (section 5.4). On Linux a process with
  `CAP_NET_ADMIN` can give its packets the full tunnel's fwmark and pass.
- DHCP servers outside the private and link-local ranges (for example a
  carrier-grade NAT range, or a public address that a unicast renewal goes
  to) are not reachable while the kill switch blocks; the lease then runs
  out.
- On Linux the forward chain drops routed traffic that does not go into a
  tunnel: containers and virtual machines behind a bridge or NAT on the host
  lose their network while the kill switch is on.
- On macOS, pf states created earlier by the rules of other anchors are not
  removed and can keep passing. Latchwire's own rules keep state only for
  the endpoint traffic. On Linux no earlier connection survives (the
  rules do not accept established traffic in general).
- On macOS a main ruleset without the `com.apple/*` anchor point leaves
  the kill switch not in effect until it is restored: it is reported (above),
  not repaired. On Linux the 30-second check sees that the table exists, not
  its contents.
- Trusted networks (on-demand) take down tunnels whose kill switch is `auto`
  or `off`, on a signal anyone on the local network can fake (section 5.6).

### 5.8 Windows

**Status: compiled, never run.** No Windows machine was available. `GOOS=windows
go build` and `go vet` pass and the logic that does not need Windows is tested
on other systems: the commands generated, the parsing of `route print` and
`arp`, the filter list, the C structure layouts and the user table. Every call
into Windows is unverified: the named pipe, token reads, the service, Wintun,
`netsh`, the registry keys, `fwpuclnt.dll`, the IP helper notifications, the
PIN window, WinSCard. Section 17 of the hardware checklist lists them. Until
they pass, treat this section as a statement of intent; in particular, do not
rely on the Windows kill switch.

**Local authorization.** There is no socket with peer credentials, so the
daemon listens on the named pipe `\\.\pipe\latchwire`
(`internal/ipc/transport_windows.go`).

- A client is identified from its token, read by impersonating it at
  identification level. A process ID would be open to reuse, and a token cannot
  be forged by the client. A client that connects anonymously is refused.
- A token with `BUILTIN\Administrators` enabled, which means elevated through
  UAC, or LocalSystem, is uid 0: elevation is `sudo`. **A member of
  Administrators who is not elevated is an ordinary user here.** That is
  stricter than macOS, where membership of `admin` is enough. Note that
  Microsoft does not treat UAC as a security boundary, so this raises the bar
  for a program running as that user without being a guarantee.
- Other users get a uint32 from a table of SIDs,
  `%ProgramData%\Latchwire\users.json` (`internal/ipc/usertable.go`). Numbers
  are never reused and the table is never rebuilt: renumbering would hand one
  user's tunnels to another, so a damaged file refuses every unprivileged
  client until an administrator deals with it, and elevated clients keep
  working.
- **Pipe squatting:** the first process to create a pipe name owns it, so a
  client refuses a pipe whose owner is not SYSTEM or Administrators, before it
  sends anything, and the service refuses to start on a name that exists.
  Clients get read and write access without `FILE_CREATE_PIPE_INSTANCE`, which
  `GENERIC_WRITE` includes on a pipe: with it, any user could add an instance
  and answer other clients while the owner check still passed. Remote clients
  are rejected.
- `tunnel.add` from an elevated client records the user behind the token as the
  allowed user, the counterpart of `SUDO_UID`. With over-the-shoulder elevation
  that is the administrator who typed the password, not the logged-in user:
  use `--allow-user`.

**Data directory.** `%ProgramData%\Latchwire` holds the journal, which holds
commands the daemon replays as SYSTEM, plus the tunnels, policies and user
table. Any user may create folders in `%ProgramData%`, and Windows files have
no mode bits to check, so the daemon's checks on Unix do not exist here.
Instead `datadir.Secure` runs before anything is read, and its failure stops the
service: the directory must be owned by SYSTEM or Administrators, reparse points
are refused, and the directory and everything in it get a protected DACL for
SYSTEM and Administrators only, through handles that do not follow reparse
points. A user who creates the directory before Latchwire is installed
can therefore stop the service from starting, but cannot get in;
`latchwire service install` claims it first. Replayed commands run only from
System32.

**Kill switch.** WFP filters at the ALE connect and receive-accept layers, IPv4
and IPv6, in a sublayer of Latchwire's own, replaced in one transaction
(`internal/killswitch/wfp*.go`). The design is meant to fail closed like pf and
nft: the session is not dynamic, so filters stay when the process dies. They
are not persistent: they go when the Base Filtering Engine restarts or Windows
reboots. The journal lives on disk here, not in `/var/run`, so after a crash
followed by a reboot the service blocks again when it starts, which Linux and
macOS do not do; `Verify` also notices an engine restart within 30 seconds.
**Between boot and the service's start nothing is blocked**, and neither is
anything during an engine restart until that check.

Limits that differ from nft and pf:

- DHCP rules cannot be tied to the system's DHCP client: any program can use
  ports 68 and 546 to reach the private and link-local networks on the DHCP
  server ports.
- WFP cannot match the hop limit of neighbour discovery and MLD.
- ALE layers do not see forwarded traffic, so Internet Connection Sharing,
  Hyper-V and WSL guests are not limited by the kill switch. Docker Desktop and
  virtual machines may bypass it.
- A permit is a hard permit only for endpoints; other firewalls' blocks still
  apply to the tunnel interface. A third-party firewall with a higher-weight
  sublayer can override the block.
- Whether connections opened before the kill switch came on are cut depends on
  ALE reauthorization: unverified (checklist).

**DNS.** `DNSPrimary` sets the servers on the interface, a low interface metric
and an NRPT rule for every name, because Windows may ask several interfaces at
once and the metric alone leaks; `DNSScoped` sets only an NRPT rule. Rules are
written to the local key with `reg.exe`. **Group policy NRPT rules replace
local ones**, so a managed machine may ignore them silently. A rule outlives the
tunnel and is journaled for undo. Without the kill switch, programs that use
their own resolver are not covered, as on the other systems.

**Full tunnel.** As on macOS: `/1` routes on the tunnel and a host route to each
endpoint through the default gateway, following it when the network changes.
With no default route the endpoint's route goes to the loopback interface, which
stands in for a blackhole route; whether Windows really drops those packets is
unverified.

**Output parsing.** `netsh`, `route` and `arp` speak the system's language, so
nothing reads their words: parsers take numbers and addresses from known columns
and a failed command is judged by re-reading the routing table. Network identity
(section 5.6) is as weak as elsewhere.

**PIN.** The agent's window keeps the PIN in a fixed buffer that is wiped, and
clears the edit control; the string handed to the card layer cannot be wiped,
as on the other systems. The window closes by itself after 100 seconds. Any
program on the same desktop can send messages to it or log keystrokes (a
limit of the Windows desktop, section 5.1); it is not a secure desktop.

**Cards.** Card access uses WinSCard in the user's session. Which processes can
reach a card, and how fast user switching and RDP redirection behave, is
unverified; section 5.2 does not yet apply to Windows from observation.

**Distribution.** `wintun.dll` must sit next to `latchwire.exe`, and that folder
must be writable only by administrators, since the service runs from it as
SYSTEM and loads the DLL from there. `latchwire service install` refuses a
program outside Program Files; it trusts that folder's default permissions and
does not inspect them, and a service created by other means is not checked. Signing and Store packaging are not done
(spec section 12, item 4).

### 5.9 The desktop app

The app adds a user interface, not a new trust level: it runs as you, and
everything in this section is on top of the limits above.

- **No web engine.** The window is drawn by Fyne (Go and OpenGL). No HTML or
  JavaScript runs in the process that handles your PIN.
- **The PIN field.** `SecretField` keeps input in one byte array, wiped when
  the form closes, and has no undo history and no paste. The PIN then reaches
  the card as a Go string, as in the terminal path (5.3). Key events pass
  through the window system and the toolkit first, and a program that can read
  your keyboard or your process memory sees the PIN; that is true of any
  dialog. PUK, new PIN and management key follow the same path, for the time
  key creation takes.
- **A larger process.** The app links a GUI toolkit and its dependencies, about
  390 packages. They share an address space with the agent, so a bug in them is
  closer to your PIN than in the small `latchwire agent` process. Use the CLI
  agent if you prefer the smaller one.
- **Fake windows.** Any program running as you can draw a window that looks
  like the PIN form. As in 5.5: do not enter the PIN into a prompt you did not
  expect. The form appears only when a tunnel you or a login item started needs
  the card.
- **Key creation never replaces a key.** The app offers empty slots only and
  never sets `Force`. Replacing a key stays a deliberate `latchwire keygen
  --force`.
- **Importing a `.conf`.** A `PrivateKey` line, and any comment naming one, is
  dropped while reading, the file's bytes are wiped, and the form says so. The
  key stays in the file on your disk until you delete it, and copies can remain
  in memory until it is reused. The app does not touch the file.
- **The clipboard** only ever receives public values: public keys, `[Peer]`
  blocks, allowed-IP entries, the message for a server administrator, and
  setup commands for a server that are built from those same values. The QR
  code holds the same kind of text.
- **The server-details form** treats a preshared key the way `.conf` import
  does: it is typed into a field that shows only dots and takes no paste, and
  the field and the buffers built from it are wiped once the tunnel is added or
  the form closes. On the way to the daemon it also passes through Go strings,
  which cannot be wiped, as on the import path. The message for an
  administrator, whether copied or handed to the e-mail program, holds public
  values only: never a preshared key, a PIN or a key reference.
- **Status is polled** every 2 seconds, so a removed card appears on screen up
  to about 3 seconds later, even though the daemon closes the tunnel sooner.
- **Quitting stops the agent.** Tunnels then close after the 10-second grace
  period (section 10). The app asks first when a tunnel is connected.
- **Do not run a second agent.** With `latchwire agent` running as the same
  user too, the daemon uses whichever registered first, so PIN prompts can
  appear in a place you do not expect. Two copies of the app are refused by a
  per-user lock; a CLI agent next to the app is not.

The demo build (`-tags demo`) uses made-up data and is not what is shipped;
`desktop/deps_test.go` checks that the normal build links neither it nor the
software key.

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
| `tunnel.add`, `tunnel.remove`, `tunnel.policy.set` | Administrators only: root, macOS `admin`, Linux `sudo`, `wheel` or `latchwire`. |
| `tunnel.connect` | An administrator, or one of the tunnel's allowed users whose own agent is registered and passes the proof of possession. Non-administrators use only their own agent and cannot take over a tunnel bound to another user. The proof shows access to the card, not which user owns it: an allowed user who can reach your card through PC/SC can bind your unbound tunnels (section 5.2). |
| `tunnel.disconnect` | An administrator, the user the tunnel is bound to, the user whose own connect left it failed (`error`) while still one of its allowed users, or an allowed user abandoning an automatic connect (on-demand, AutoConnect) that is pending for that user. A tunnel left blocking by a deny can be taken down only by an administrator. |
| `tunnel.status`, `tunnel.policy.get`, `network.current` | An administrator or a user with a registered agent. Registering needs no card, so in practice any local user. |
| `key.public`, `key.x25519` | The daemon, to the agent. The agent refuses a daemon that is neither root nor its own user. |

Where this is enforced: `internal/daemon/manager.go:810` (`handle`), `:741`
(`requestDisconnect`), `internal/daemon/ondemand.go:299`
(`handleNetwork`), tests listed in sections 4 and 5.2.

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
  security-relevant ones named above, with fake cards. System commands are
  checked against recorded command lists, never run.
- `test/e2e/linux/run.sh` runs the Linux network behaviour for real, in
  network namespaces inside a throw-away privileged container (the command
  is in the script's header; it refuses to run outside a container or as
  non-root): split and full tunnel, DNS through openresolv, the kill switch
  on card removal and return, `kill -9` and restart of the daemon, an
  orderly stop, a full and a split tunnel together, allowed users, and
  on-demand. The production daemon and CLI are used; only the agent (with a
  software key) and the WireGuard server are test binaries.
- [docs/hardware-checklist.md](hardware-checklist.md) lists the checks that need
  real YubiKeys, including card removal and re-seating while connected and
  smart-card login or `sudo` while the tunnel is up, and the macOS (and
  real-distribution Linux) network checks: full tunnel, DNS leaks, kill
  switch, crashes, several tunnels, on-demand.
- Run `ykman piv info` before and after `latchwire keygen`: the slots `9a` and
  `9d` must be unchanged and the new key must be in a retired slot.

## 12. Reporting

If you find a way around any of the protections in section 4, or a claim here
that is wrong, please follow [SECURITY.md](../SECURITY.md).
