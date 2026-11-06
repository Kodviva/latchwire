# Installing the service files

Packages do everything below: see [Packages](#packages). This page also
describes the same setup by hand, with the files under `packaging/`. Every
step is run by a person; automated runs never perform them.

## Packages

Build instructions, the check that two builds match and the release steps
are in `packaging/README.md`. The packages depend on PC/SC, `nft`, `ip` and
`sysctl`. A pinentry and `pcscd` are recommended; DNS needs systemd-resolved
or resolvconf. glibc 2.34 or later is required (Debian 12, Ubuntu 22.04,
RHEL 9 or later). Use `dnf` for the `.rpm`: it is not signed yet, and plain
`rpm -i` refuses it on current Fedora.

| | Install | Remove, keeping tunnels | Remove with tunnels |
| --- | --- | --- | --- |
| `.deb` | `sudo apt install ./latchwire_*.deb` | `sudo apt remove latchwire` | `sudo apt purge latchwire` |
| `.rpm` | `sudo dnf install ./latchwire-*.rpm` | `sudo dnf remove latchwire` | then `sudo rm -rf /etc/latchwire` |
| tarball | `sudo ./install.sh` | `sudo /usr/local/lib/latchwire/uninstall.sh` | add `--purge` |
| macOS `.pkg` | `sudo installer -pkg latchwire-*.pkg -target /` | `sudo /usr/local/latchwire/lifecycle.sh uninstall` | add `--purge` |

On Linux the daemon starts at once and at every boot, and the agent starts at
each user's next login. To start it in the current session:
`systemctl --user start latchwire-agent.service`. On macOS both start at once
for the console user. Stop here unless you want the setup by hand; the
"Linux" section below still applies to pinentry and logs.

The deb and rpm binary is `/usr/bin/latchwire`, the tarball's is
`/usr/local/bin/latchwire`. On macOS the package installs
`/usr/local/latchwire/bin/latchwire`, plus a link from `/usr/local/bin` for
your shell. launchd never goes through that link: the daemon runs the program
as root, and on Intel Macs Homebrew gives `/usr/local/bin` to a user.

**Upgrades do not disconnect you.** Stopping the daemon takes every tunnel
down and lifts the kill switch, so an upgrade restarts it only when nothing
is up. Otherwise the old daemon keeps running, and the upgrade says so (on
macOS, in `/var/log/install.log`). Take the tunnels down, then run
`sudo systemctl restart latchwire-daemon` or
`sudo launchctl kickstart -k system/com.latchwire.daemon`. A reboot does the
same.

**Removal leaves no network state behind.** The daemon is stopped, which
takes tunnels down and lifts the kill switch. If it had crashed, the journal
still lists what to undo: the removal starts it once to clean up, and then
deletes the kill switch rules in any case. If something still could not be
undone, it prints a warning and keeps `/var/run/latchwire/journal.json`; a
reboot clears those changes.

**Coming from a manual installation:** remove the old unit files or property
lists first (see below). On Linux, a unit in `/etc/systemd` overrides the
packaged one, and the package warns about it.

Membership of the group `latchwire` also makes a Linux user an administrator
of Latchwire. The packages do not create it. To use it:
`sudo groupadd latchwire && sudo usermod -aG latchwire NAME`.

## By hand

By hand, the binary is expected at `/usr/local/bin/latchwire`, owned by root and not
writable by anyone else (`root:wheel 0755` on macOS, `root:root 0755` on
Linux): the daemon runs it as root and every user's agent runs it too.

    sudo install -o root -m 0755 latchwire /usr/local/bin/latchwire

## What runs where

- **Daemon** (`latchwire daemon`, root): TUN devices, routes, DNS, kill
  switch. One per machine, started at boot.
- **Agent** (`latchwire agent`, each logged-in user): holds the YubiKey and
  asks for its PIN. Started at login. When it has no terminal (always the
  case as a login item) it asks with a dialog: `osascript` on macOS,
  `pinentry` on Linux. Started from a shell instead, it asks on the terminal.

## macOS

Install the property lists (owner root, mode 0644, or launchd refuses them):

    sudo install -o root -g wheel -m 0644 packaging/macos/com.latchwire.daemon.plist /Library/LaunchDaemons/
    sudo install -o root -g wheel -m 0644 packaging/macos/com.latchwire.agent.plist /Library/LaunchAgents/

Create the daemon's log file before the first start, readable only by root
and administrators (launchd keeps the mode of an existing file; a file it
creates itself would be readable by every user):

    sudo install -o root -g admin -m 0640 /dev/null /var/log/latchwire-daemon.log

Start the daemon now (it also starts at every boot):

    sudo launchctl bootstrap system /Library/LaunchDaemons/com.latchwire.daemon.plist

The agent starts at the next login of every user (GUI sessions only,
`LimitLoadToSessionType=Aqua`). To start it now in the current session, as
the logged-in user (not with sudo):

    launchctl bootstrap gui/$(id -u) /Library/LaunchAgents/com.latchwire.agent.plist

Check: `sudo launchctl print system/com.latchwire.daemon` and
`launchctl print gui/$(id -u)/com.latchwire.agent` show `state = running`.
The daemon logs to `/var/log/latchwire-daemon.log` (tunnel names and
endpoints, never keys or PINs; mode 0640 from the step above). The agent's log
goes nowhere when started by launchd; start it from a terminal to see it.

Remove:

    launchctl bootout gui/$(id -u)/com.latchwire.agent
    sudo launchctl bootout system/com.latchwire.daemon
    sudo rm /Library/LaunchAgents/com.latchwire.agent.plist /Library/LaunchDaemons/com.latchwire.daemon.plist

## Linux (systemd)

Install the units:

    sudo install -m 0644 packaging/linux/latchwire-daemon.service /etc/systemd/system/
    sudo install -m 0644 packaging/linux/latchwire-agent.service /etc/systemd/user/
    sudo systemctl daemon-reload
    sudo systemctl enable --now latchwire-daemon.service

Then, as each user who uses Latchwire (not with sudo):

    systemctl --user daemon-reload
    systemctl --user enable --now latchwire-agent.service

The agent asks for the PIN with the first of `pinentry`, `pinentry-gnome3`,
`pinentry-qt`, `pinentry-curses` found in `/usr/bin`, `/bin` or
`/usr/local/bin` (PATH is not used). Install one, for example
`apt install pinentry-gnome3`. `pinentry-curses` needs a terminal, so it
cannot work for an agent started by systemd. Without any pinentry every PIN
request fails with "PIN required" and the reason is in the agent's log.

pinentry gets only the session variables `DISPLAY`, `WAYLAND_DISPLAY`,
`XAUTHORITY`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`,
`XDG_SESSION_TYPE`, `XDG_CURRENT_DESKTOP`, `HOME`, `LANG`, `LC_ALL`,
`LC_CTYPE`, `LC_MESSAGES` from the agent. A systemd user service sees them
only if the desktop imported them into the user manager (GNOME and KDE do;
otherwise run `systemctl --user import-environment DISPLAY WAYLAND_DISPLAY
XAUTHORITY` in the session start-up and restart the agent).

Check: `systemctl status latchwire-daemon` and
`systemctl --user status latchwire-agent`; logs with
`journalctl -u latchwire-daemon` and `journalctl --user -u latchwire-agent`.

The daemon unit is sandboxed: read-only system (`ProtectSystem=strict`), no
home directories, `/dev/net/tun` as its only device, and only the
capabilities `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE`.
`packaging/linux/test` runs a real full tunnel with kill switch under this
unit, with openresolv and with systemd-resolved. If a resolvconf hook of
yours writes elsewhere, add the path with
`systemctl edit latchwire-daemon.service` and `ReadWritePaths=`. On a system
with SELinux enforcing, check `ausearch -m avc -c latchwire` after the first
tunnel: containers cannot test that.
The agent's sandbox is light, because pinentry needs the desktop session.

Remove:

    systemctl --user disable --now latchwire-agent.service
    sudo systemctl disable --now latchwire-daemon.service
    sudo rm /etc/systemd/user/latchwire-agent.service /etc/systemd/system/latchwire-daemon.service
    sudo systemctl daemon-reload

## Upgrading from an earlier version (Plan 1)

Two things change for tunnels stored by a version without tunnel policies
(`/Library/Application Support/Latchwire/tunnels` on macOS,
`/etc/latchwire/tunnels` on Linux):

- **A tunnel without a policy file is for administrators only.** Its
  policy has no allowed users, so only an administrator (`sudo latchwire
  up`) can connect it. The daemon logs this for each such tunnel at start.
  Give a user access back with:

      sudo latchwire policy <tunnel> --allow-user NAME

  Tunnels added from now on get the user who ran `sudo latchwire add` as
  their allowed user.
- **A stored configuration whose `MTU` is outside 1280-9000 is not
  loaded** (`0` or no `MTU` line means automatic). The daemon logs a
  warning naming the file and the reason, and the tunnel is missing from
  `latchwire status`. Fix the `MTU` line in the file and restart the
  daemon, or remove the tunnel and add it again with a valid
  configuration.

## Manual checks of the PIN dialogs

These need a real desktop session and a YubiKey (see
`docs/hardware-checklist.md` for the key rules). Each check costs no PIN
attempt unless a wrong PIN is typed on purpose.

- [ ] macOS: with the agent started by launchd, `latchwire up <name>` shows
      a Latchwire dialog with a hidden field, the YubiKey serial and slot and
      the attempts left. The right PIN connects.
- [ ] macOS: Cancel in the dialog ends `up` with "PIN required"; no attempt
      is used (`ykman piv info` shows the same count).
- [ ] macOS: leaving the dialog open for 100 seconds closes it and counts as
      cancelled.
- [ ] macOS: with one attempt left the dialog carries the last-attempt
      warning and a notification shows it too.
- [ ] macOS: `ps -axww -o args | grep osascript` while the dialog is open
      shows no PIN (only `osascript -` and the display texts).
- [ ] Linux: same three checks with pinentry-gnome3 (or -qt) under the
      systemd user unit; Cancel ends with "PIN required".
- [ ] Linux: `cat /proc/<pinentry pid>/environ | tr '\0' '\n'` lists only
      `PATH` and the session variables above.
- [ ] Linux: with no pinentry installed the agent log says so and `up` ends
      with "PIN required".
- [ ] Both: `latchwire agent` started from a terminal still asks on the
      terminal, not with a dialog.
- [ ] Linux, packaged: with polkit running, `pcscd` accepts the agent
      started by the systemd user unit (the journal has no "NOT authorized"),
      and a YubiKey shows up in `latchwire devices`.
- [ ] macOS, packaged: the same dialogs appear with the Developer ID signed
      binary under the hardened runtime.
