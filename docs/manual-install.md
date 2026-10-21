# Manual installation of the service files

Packaged installers come later (Plan 5). Until then the daemon and the user
agent can be installed by hand with the files under `packaging/`. Every step
below is run by a person; automated runs never perform them.

The binary is expected at `/usr/local/bin/latchwire`, owned by root and not
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

Start the daemon now (it also starts at every boot):

    sudo launchctl bootstrap system /Library/LaunchDaemons/com.latchwire.daemon.plist

The agent starts at the next login of every user (GUI sessions only,
`LimitLoadToSessionType=Aqua`). To start it now in the current session, as
the logged-in user (not with sudo):

    launchctl bootstrap gui/$(id -u) /Library/LaunchAgents/com.latchwire.agent.plist

Check: `sudo launchctl print system/com.latchwire.daemon` and
`launchctl print gui/$(id -u)/com.latchwire.agent` show `state = running`.
The daemon logs to `/var/log/latchwire-daemon.log` (readable by all users;
it holds tunnel names and endpoints, never keys or PINs). The agent's log
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

The daemon unit has no sandboxing options yet: it needs `/dev/net/tun`,
netlink, `nft`, `ip`, `sysctl` and the DNS configuration, and options such as
`ProtectSystem=`, `ProtectKernelTunables=` or `NoNewPrivileges=` can break
them. Hardening comes with Plan 5.

Remove:

    systemctl --user disable --now latchwire-agent.service
    sudo systemctl disable --now latchwire-daemon.service
    sudo rm /etc/systemd/user/latchwire-agent.service /etc/systemd/system/latchwire-daemon.service
    sudo systemctl daemon-reload

## Manual checks of the PIN dialogs

These need a real desktop session and a YubiKey (see
`docs/hardware-checklist.md` for the key rules). Each check costs no PIN
attempt unless a wrong PIN is typed on purpose.

- [ ] macOS: with the agent started by launchd, `latchwire up <name>` shows
      a Latchwire dialog with a hidden field, the YubiKey serial and slot and
      the attempts left. The right PIN connects.
- [ ] macOS: Cancel in the dialog ends `up` with "PIN required"; no attempt
      is used (`ykman piv info` shows the same count).
- [ ] macOS: leaving the dialog open for 2 minutes closes it and counts as
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
