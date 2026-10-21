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
- [ ] `latchwire up office` as the non-administrator user who ran `sudo
      latchwire add` works (through their own agent; that user is the
      tunnel's allowed user, section 15); `sudo latchwire add` / `remove` are
      refused for a user who is not an administrator.

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

## 8. Network checks: before you start

Sections 8 to 15 check full tunnels, DNS, the kill switch, on-demand and the
service. They need root and change the machine's network; do them on a test
machine or be ready to recover (below). The Linux behaviour is also covered
automatically by `test/e2e/linux/run.sh` in a privileged container (split and
full tunnel, openresolv DNS, kill switch on card removal, `kill -9` and
restart, orderly stop, two tunnels, allowed users, on-demand); on Linux, these
sections check what a container cannot: a real distribution with its own
network manager and resolver.

Prepare:

- [ ] A test server peer that accepts `AllowedIPs = 0.0.0.0/0, ::/0` from this
      client and forwards to the internet, with a DNS server reachable inside
      the tunnel (for example the server's tunnel address).
- [ ] Two tunnel files for the same card: `full` (`AllowedIPs = 0.0.0.0/0,
      ::/0`, `DNS = <server tunnel IP>`) and `split` (a small range, and
      for the DNS checks also `DNS = <ip>, corp.example`). For section 14 a
      second split tunnel with another slot and a range that does not overlap.
- [ ] Record the state before the test, to compare after each `down`:
  - macOS: `netstat -rn > before-routes.txt`, `scutil --dns >
    before-dns.txt`, `sudo pfctl -s info | head -1`, `sudo pfctl -sr`.
  - Linux: `ip rule`, `ip route show table all`, `sudo nft list ruleset`,
    `cat /etc/resolv.conf`, `resolvectl status` (if systemd-resolved runs).

Recovery, if the kill switch blocks and the daemon cannot lift it: first
`sudo latchwire down <name>`. If the daemon is gone for good:

- macOS: `sudo pfctl -a com.apple/250.latchwire -F all`, then release
  Latchwire's pf reference with the token from the journal
  (`sudo cat /var/run/latchwire/journal.json`, the `pfctl -X <token>` step),
  or reboot.
- Linux: `sudo nft delete table inet latchwire`, or reboot.

A reboot clears all of it: the journal lives in `/var/run`.

## 9. macOS: full tunnel and routes

- [ ] `sudo latchwire up full` (0.0.0.0/0, and once more with ::/0 only):
  - `netstat -rn` shows `0/1` and `128.0/1` (and `::/1`, `8000::/1`) on
    `utunN`, and a host route to the endpoint through the Wi-Fi gateway.
  - `route -n get default` still shows the physical gateway.
  - `route -n get <endpoint>` shows `destination: <endpoint>`, the gateway
    and the `HOST` flag.
  - `route -n get -inet 0.0.0.0/1` and `route -n get -inet6 8000::/1` parse
    as the `/1` routes on the utun (`destination: default`, `mask:
    128.0.0.0` / `mask: 8000::`).
  - `curl https://ifconfig.co` shows the server's address.
- [ ] Switch Wi-Fi networks, or go from Ethernet to Wi-Fi, with a different
      gateway:
  - within about 1 s the endpoint host route moves to the new gateway;
  - the handshake recovers and traffic keeps flowing;
  - `/var/run/latchwire/journal.json` holds only the new route's undo.
- [ ] Turn Wi-Fi off while connected, then on again: the endpoint first gets
      a blackhole route (`route -n get <endpoint>` shows `BLACKHOLE`) or keeps
      its old route; after Wi-Fi returns it gets the gateway route.
- [ ] Connect while offline: a blackhole route, which moves to the gateway
      once online.
- [ ] `latchwire down full`: the host route and the `/1` routes are gone, the
      journal is empty and `netstat -rn` matches `before-routes.txt`.
- [ ] `kill -9` the daemon while connected, restart it: the startup cleanup
      removes the host route.
- [ ] Add a foreign host route to the endpoint (`sudo route add -inet <ep>
      -gateway <other>`), connect and disconnect: the foreign route stays.
- [ ] `route delete -inet <ep> 127.0.0.1 -blackhole` is accepted and removes
      only a blackhole route.
- [ ] Find out whether `route delete -inet <ep> -gateway <wrong>` deletes a
      route through another gateway (this tells whether the ownership check
      before a delete is strictly needed).
- [ ] With another VPN's `0/1` routes in place (for example OpenVPN `def1`),
      `kill -9` the daemon, restart it, and check that the other VPN's routes
      survive.
- [ ] Auto MTU: on a network with a path MTU below 1500 (PPPoE, tethering),
      `ifconfig utunN` shows the interface MTU minus 80 after the switch.
- [ ] IPv6 endpoint with `::/0`: the host route is through `fe80::…%en0` and
      moves on a network change.
- [ ] Network monitor: toggling Wi-Fi produces a network event (daemon log
      with `LATCHWIRE_DEBUG=1`), and there is no refresh loop caused by the
      daemon's own endpoint routes (no repeating log lines while idle).

## 10. macOS: DNS and DNS leaks

- [ ] Connect `split` with `DNS = 10.x.x.x, corp.example` as the only tunnel:
  - `scutil --dns` shows the tunnel servers and the search domain as
    resolver #1;
  - `echo "show State:/Network/Service/<PrimaryService>/DNS" | scutil` shows
    exactly `ServerAddresses` and `SearchDomains`.
- [ ] Connect `full`: `latchwire status` shows DNS `primary`; `dig
      example.com` and `dscacheutil -q host -a name example.com` are answered
      by the tunnel's server; `sudo tcpdump -ni en0 port 53` shows no query
      while browsing (no DNS leak).
- [ ] With `full` up, connect a split tunnel with search domains: it gets
      DNS `scoped`; `State:/Network/Service/latchwire-utunN/DNS` has
      `SupplementalMatchDomains`; `scutil --dns` lists a resolver for those
      domains; the key is removed on disconnect. A split tunnel that was the
      DNS primary is demoted when `full` connects.
- [ ] Check which interface the tunnel servers' resolver is bound to
      (`scutil --dns` `if_index`): a resolver tied to `en0` would send the
      queries outside the tunnel.
- [ ] A minute after connecting, `show State:/Network/Service/<id>/DNS`
      still holds only the tunnel's keys. If configd adds keys of its own, the
      daemon takes the dict for a foreign one and `down` leaves it in place:
      note it.
- [ ] `latchwire down` restores the original dict: `scutil --dns` matches
      `before-dns.txt`. Repeat with a service that had no `State:` DNS key:
      the key is removed.
- [ ] Kill the daemon (`kill -9`) while connected: the tunnel's DNS stays
      until the daemon starts again; after the restart the cleanup restores
      the original dict (DNS comes back).
- [ ] While connected, let DHCP rewrite the key (reconnect Wi-Fi or `sudo
      ipconfig set en0 DHCP`): within 30 s the daemon puts the tunnel's
      servers back (logged once). Then disconnect: a foreign or DHCP dict is
      not overwritten ("leaving them alone" in the log). Note how long the
      leak window was.
- [ ] Switch Wi-Fi to Ethernet (or tether) while connected: the old service
      gets its DNS back, the new primary service gets the tunnel's, and the
      journal holds one scutil undo, for the new service.
- [ ] Set DNS by hand in System Settings, then connect: the log shows the
      manual-DNS warning and `latchwire status` shows DNS `overridden`.
- [ ] Note which other resolvers stay in `scutil --dns` (configuration
      profiles, another VPN, iCloud Private Relay) and whether the browser
      uses its own DNS over HTTPS.
- [ ] Reboot while connected: no `State:` key survives, and the cleanup at
      start leaves nothing behind.

## 11. macOS: kill switch (pf)

Confirm the pf assumptions first (unprivileged runs could not read pf):

- [ ] `sudo pfctl -sr` prints `anchor "com.apple/*" all` on a stock system.
- [ ] `sudo pfctl -E` prints `Token : <n>` (check the exact spacing and
      whether it goes to stderr).
- [ ] `sudo pfctl -X <unknown token>`, and `-X` while pf is disabled, fail
      with text containing "Invalid argument", "No such file or directory"
      or "not enabled" (matched in `internal/netcfg/darwinplan_pf.go`).
- [ ] `sudo pfctl -a com.apple/250.latchwire -F all` on a missing anchor
      succeeds or prints "Anchor does not exist." (both count as undone), and
      with `-a` flushes only that anchor (rules, nat, tables), not global
      states or statistics.
- [ ] The generated rules load: `echo "<rules>" | sudo pfctl -a
      com.apple/250.latchwire -nf -`, in particular `icmp6-type { 133, 134,
      135, 136 }`, `from { fe80::/10, ::/128 }`, `all ... no state`, `user
      root` on the UDP `no state` rules, `from { 0.0.0.0, ... }`, `to
      ff02::1:2`, `to { fe80::/10, ff02::/16 }`.
- [ ] `sudo pfctl -s info` begins with `Status: Enabled ...`; `sudo pfctl -a
      com.apple/250.latchwire -sr` lists the rules while blocking and is empty
      after `down`.

Behaviour, with `full` (kill switch `auto`, so on):

- [ ] Connected: `curl` outside the tunnel works only through the tunnel; the
      local network (printer, router web page) is blocked; the handshake
      works.
- [ ] Pull the card: `latchwire status` shows `card_removed` and `blocking`;
      `curl https://example.com` fails at once; `dig @8.8.8.8 example.com`
      fails; no internet. Put the card back: the tunnel reconnects after the
      PIN.
- [ ] Pull the card, then `latchwire down full`: the internet is back, and
      `pfctl -s References` (or `pfctl -s info`) no longer lists Latchwire's
      token.
- [ ] DHCP renewal while blocking works (`sudo ipconfig set en0 DHCP`, or
      wait for the lease): configd's DHCP packets match `user root` or bypass
      pf.
- [ ] IPv6 router advertisements and neighbour discovery while blocking: the
      default router stays reachable (`ndp -an`); an IPv6 endpoint through
      the router works.
- [ ] Name lookups behind pf: with the tunnel `card_removed`, note what
      `dscacheutil -q host -a name <endpoint host>` returns (expected: no such
      host, or a timeout) and that the reconnect uses the cached endpoint
      (daemon log).
- [ ] pf already enabled before Latchwire (`sudo pfctl -e` with your own
      rules): connect and disconnect `full`; afterwards pf is still enabled
      and your rules are unchanged.
- [ ] `sudo pfctl -d` while blocking: within 30 s the daemon logs a WARNING
      and pf is enabled again with the rules. Also load a main ruleset
      without the `com.apple/*` anchor point (`sudo pfctl -f <file>`): within
      30 s the daemon logs `WARNING: the kill switch is NOT in effect` once
      (not every 30 s), `latchwire status` shows the warning on the tunnel,
      and after `sudo pfctl -f /etc/pf.conf` the log says the kill switch is
      in effect again and the warning goes.
- [ ] Other `com.apple/*` anchors sort before `250.latchwire`: none of them
      passes traffic `quick` before ours (AirDrop and the application firewall
      are expected only to block). Note whether connections opened before the
      kill switch came on keep working (pf states of other rules).
- [ ] `kill -9` the daemon while blocking: the rules stay and nothing passes.
      Restart it: `/Library/Application Support/Latchwire/tunnels/killswitch.state`
      lists the tunnel, the tunnel shows `card_removed` with its identity,
      putting the card back reconnects it, and the non-administrator owner can
      run `latchwire down`.
- [ ] An orderly stop (`sudo launchctl bootout system/com.latchwire.daemon`)
      while blocking lifts the kill switch.

## 12. macOS: on-demand and trusted networks

- [ ] `latchwire network` on Wi-Fi, then again with `full` up: the ID is the
      same, and `route -n get default` still shows en0 and the physical
      gateway.
- [ ] At home: `sudo latchwire policy <t> --on-demand=true
      --trust-current-network`. Switch to a hotspot: the tunnel connects with
      one PIN prompt. Return home: it goes down and the kill switch is lifted
      (`sudo pfctl -a com.apple/250.latchwire -sr` is empty). With
      `--kill-switch on` it stays up at home.
- [ ] On the hotspot, cancel the PIN prompt: no new prompt on later route
      events or within 2 minutes; re-plugging the YubiKey or changing networks
      prompts once.
- [ ] On the hotspot, `latchwire down`: it stays down through sleep and wake
      on the same hotspot and reconnects on another network.
- [ ] Join a network whose ARP entry is cold (fresh join): the log shows no
      flapping between trusted and untrusted.
- [ ] No connect and disconnect loop in `log stream` (endpoint host routes
      cause route events): no repeated "connecting on demand" lines.

## 13. macOS: two tunnels at the same time

- [ ] `full` and a second split tunnel up together: both `connected`; traffic
      to the split tunnel's range uses its utun (`route -n get <ip>`), the
      rest the full tunnel; with the kill switch on both tunnels' traffic
      passes.
- [ ] A second full tunnel is refused with a message; so is a split tunnel
      whose range overlaps one that is up.
- [ ] Taking either down leaves the other working; after both are down, the
      routes, DNS and pf match the state before the test.

## 14. Linux on a real distribution

- [ ] Full tunnel with systemd-resolved: `resolvectl status <tunnel>` shows the
      servers, `~.` and default route yes; `resolvectl query example.com`
      goes to the tunnel's server; `latchwire down` reverts the link. Check
      whether `/etc/resolv.conf` points at the stub (programs reading it
      directly bypass resolved otherwise).
- [ ] With classic Debian `resolvconf` (not openresolv): `latchwire status`
      shows DNS `shared` with a warning; `/etc/resolv.conf` also lists the
      other servers; with the kill switch on, queries to them fail.
- [ ] `ip rule` shows the two `protocol 251` rules; `ip route show table
      51820` the default route; `sysctl net.ipv4.conf.all.src_valid_mark` is
      1 while connected and back to its old value after `down`.
- [ ] With firewalld (Fedora): the IPv6 reverse-path filter does not drop the
      tunnel's packets; note the rule order against firewalld's `rpfilter`.
- [ ] Without `nft` installed: a full tunnel connects and the log has the
      "runs without its reverse-path filter" warning; a tunnel whose kill
      switch is on is refused.
- [ ] Kill switch with Docker or libvirt on the host: containers and VMs lose
      their network while it blocks (documented); they get it back after
      `down`.
- [ ] DHCP renewal while blocking with systemd-networkd and NetworkManager: a
      unicast RENEW to a DHCP server outside the private ranges fails (known
      limit); a renewal through a private-range server works.
- [ ] IPv6 full tunnel (`::/0`): `curl -6` goes through the tunnel; with only
      `0.0.0.0/0` and the kill switch off, IPv6 leaves directly (documented).
- [ ] `latchwire network` before and after a full-tunnel `up`: the ID is the
      same, `ip route show default` still shows the physical gateway, and the
      table-51820 default is ignored.
- [ ] On-demand: repeat section 12, items 2 to 4, with NetworkManager
      switching Wi-Fi networks; after the trusted-network disconnect the nft
      table `inet latchwire` is gone.
- [ ] Two users: on-demand never connects for a user who is not an allowed
      user, and no pinentry appears for them.

## 15. Allowed users, auto-connect and the service (both platforms)

- [ ] `sudo latchwire add office office.conf` from a user shell: `latchwire
      policy office` shows that user as the only allowed user. From a root
      shell without `sudo`, no user is listed.
- [ ] A second, non-administrator user who is not listed: `latchwire up
      office` is refused before any PIN prompt; after `sudo latchwire policy
      office --allow-user <name>` it works. `--deny-user <name>` while that
      user's tunnel is up takes it down; with the kill switch on it stays
      blocking until an administrator runs `latchwire down` (the CLI prints a
      note).
- [ ] `sudo latchwire policy office --auto-connect=true`, then log out and in
      (agent start): one PIN prompt and the tunnel connects. Cancel the PIN:
      exactly one prompt, no loop; replug the card: one new prompt.
- [ ] `latchwire down office`, replug the card: no auto-connect; restart the
      agent: it auto-connects.
- [ ] macOS: user names of directory-service users (not in `/etc/passwd`)
      resolve for `--allow-user`.
- [ ] Service install, PIN dialogs and the service checks: run the `Check:`
      steps of both install sections and every item of "Manual checks of the
      PIN dialogs" in [manual-install.md](manual-install.md) (osascript and
      pinentry dialogs, cancel, timeout, last-attempt warning, no PIN in the
      process list or environment, launchd and systemd units running).

## 16. Clean up

- [ ] `sudo latchwire remove office`; stop the daemon with Ctrl-C and check
      that no tunnel interface and no route is left. On Linux the interface
      has the tunnel's name (`office`; `ip link show office` must fail); on
      macOS it is a `utunN` (compare `ifconfig -l` with the list from before
      the test: no extra `utun` may remain).
- [ ] After the network sections: routes, policy rules, DNS and firewall
      match what you recorded in section 8, `/var/run/latchwire/journal.json`
      has no owners, and `killswitch.state` is gone from the tunnel store.
- [ ] Remove the test peer from the server.
