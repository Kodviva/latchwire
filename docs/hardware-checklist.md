# Hardware verification checklist

These steps need real YubiKeys, a root shell and a test WireGuard server. They
are done by a person; automated runs never perform them. The PIN is typed by
the person at the prompt each time. Never put a PIN in a script, an environment
file or a shell history, with one exception: the PIV hardware test below reads
`LATCHWIRE_HW_PIN` from the environment, so set it only for that one command
and unset it afterwards.

Use a spare slot for every test. Slots 9a and 9d (and 9c, 9e) hold other
credentials such as sudo or SSH keys and must stay untouched. Latchwire only
uses retired slots 82 to 95.

Serial numbers below are the project's two test keys; replace them if needed.

## 1. Detect the keys

- [ ] `latchwire devices` lists both YubiKeys, each with `Supported: yes`
      (firmware 5.7.0 or later).
- [ ] A key with older firmware shows `Supported: no` and a hint about 5.7.0.

## 2. PIV hardware test (writes to a card)

This generates a key in one slot and compares the card's X25519 with a
software computation. Choose a free retired slot; add `LATCHWIRE_HW_FORCE=1`
only if you accept destroying a key that is already in that slot.

- [ ] Run (the PIN is the real PIN of that card):

```sh
LATCHWIRE_HW_SERIAL=<serial> LATCHWIRE_HW_SLOT=95 LATCHWIRE_HW_ALLOW_WRITE=1 \
LATCHWIRE_HW_PIN=<pin> go test -tags hardware ./internal/keyprovider/piv/ -run Hardware -v
```

- [ ] The test passes. Then `unset LATCHWIRE_HW_PIN` and clear the shell
      history line if your shell stored it.

## 3. Generate a key

- [ ] `latchwire keygen --serial 40727512` picks slot 82 (the first free
      retired slot) and asks for the PIN without echo.
- [ ] On a card that still has factory settings it explains why, asks for the
      current PUK and for a new PIN and a new PUK (each twice), and secures the
      card before generating the key.
- [ ] `ykman piv info` shows slots 9a and 9d with their certificates exactly as
      before. The new key appears only in slot 82.
- [ ] On a card hardened by Latchwire, `ykman piv info` shows
      `Management key is stored on the YubiKey, protected by PIN`.
- [ ] `latchwire keygen --serial 40727512 --slot 82` stops with a message that
      shows the key in the slot and says to use `--force`. Nothing changes on
      the card.
- [ ] `latchwire keygen --serial 40727512 --slot 82 --force` shows the key in
      the slot, warns that it is destroyed, and asks you to type `yes` before
      it asks for the PIN. Any other answer stops with nothing changed on the
      card; so does `echo yes | latchwire keygen ...` (the answer is read from
      the terminal, not from standard input). Only test the `yes` path on a
      slot whose key you can afford to lose.
- [ ] `latchwire pubkey piv://40727512/82` prints the same public key that
      `keygen` printed, without asking for a PIN.

## 4. Server and configuration

- [ ] Add the printed `[Peer]` block (with this client's tunnel IP as
      `AllowedIPs = <ip>/32`; use `--address <ip>` to have it filled in) as a new
      peer on the test server (for example OPNsense).
- [ ] Write the tunnel file with `KeyRef = piv://40727512/82` and the matching
      `PublicKey = <base64>` in `[Interface]`, plus the server `[Peer]`.

## 5. Run a tunnel

- [ ] Terminal 1: `sudo latchwire daemon`.
- [ ] Terminal 2: `latchwire agent`.
- [ ] `sudo latchwire add office office.conf`, then `latchwire status` shows
      `office` as `disconnected`.
- [ ] `latchwire up office` makes the agent ask for the PIN (terminal 2); after
      the PIN, `ping` to the server's tunnel IP succeeds and `latchwire status`
      shows `connected` with a recent handshake.
- [ ] A wrong PIN shows the retries left and does not connect. A second wrong
      PIN shows the last-attempt warning before the PIN would be blocked.
- [ ] `latchwire down office` disconnects; running it again prints
      `already disconnected`.
- [ ] `latchwire up office` as a user who is not an administrator works
      (through their own agent); `sudo latchwire add` / `remove` are refused
      for that user.

## 6. Card removal and return

- [ ] With the tunnel up, unplug the YubiKey: `latchwire status` shows
      `card_removed` within 2 seconds and traffic stops.
- [ ] Plug it back in: the agent asks for the PIN again and the tunnel returns
      to `connected` after the PIN.
- [ ] Unplug and replug while the tunnel is down; the agent keeps running and
      `latchwire up` works afterwards.
- [ ] Unplug and replug the other YubiKey (not used by the tunnel); the tunnel
      is not affected.
- [ ] With the tunnel up, stop the agent (Ctrl-C) and start it again within a
      few seconds: the tunnel stays `connected` and no PIN is asked.
- [ ] With the tunnel up, stop the agent and wait: about 10 seconds later
      `latchwire status` shows `card_removed` and traffic stops. Start the
      agent again: the tunnel returns to `connected` (no PIN if the card was
      not unplugged meanwhile).

## 7. Sharing the card with other programs

- [ ] While the tunnel is up, use YubiKey sudo (slot 9a) in another terminal.
      It works, and the tunnel keeps working afterwards.
- [ ] While the tunnel is up, run `ykman piv info`. It works, and Latchwire
      keeps working afterwards (the agent may ask for the PIN again if another
      program reset the verification; entering it restores the tunnel).
- [ ] Verify who else can reach the card while it is PIN-verified: from a
      second local user account (or an SSH session as another user) run
      `ykman list` and `ykman piv info`. Record whether the card is visible;
      update docs/threat-model.md if macOS does not restrict it.
- [ ] Note for the threat model: after the PIN was entered, any process that
      can reach the card (on macOS expected to be only the console user —
      verify below; on Linux, depending on the pcscd/polkit configuration,
      possibly any local user) can use the
      PIN-verified card until it is removed or reset, 9a included. For slot 9a
      prefer PIN policy `always`.

## 8. Clean up

- [ ] `sudo latchwire remove office`; stop the daemon with Ctrl-C and check
      that no tunnel interface and no route is left. On Linux the interface
      has the tunnel's name (`office`; `ip link show office` must fail); on
      macOS it is a `utunN` (compare `ifconfig -l` with the list from before
      the test: no extra `utun` may remain).
- [ ] Remove the test peer from the server.
