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

- **Desktop app** (`desktop/`, optional): a menu bar or tray app that runs the
  agent itself. Use it instead of the agent login item, not next to it: with
  both, the daemon uses whichever registered first. Build it on macOS with
  `desktop/build_macos.sh`; it needs Xcode's command line tools. On Linux,
  `go build` in `desktop/` needs a C compiler and the OpenGL and X11 headers
  (Debian: `libgl1-mesa-dev xorg-dev`). `LATCHWIRE_LANG=tr` picks a language.
  `desktop/build_macos.sh -tags demo` builds a demo that uses no card and no
  daemon.

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

The daemon unit has no sandboxing options yet: it needs `/dev/net/tun`,
netlink, `nft`, `ip`, `sysctl` and the DNS configuration, and options such as
`ProtectSystem=`, `ProtectKernelTunables=` or `NoNewPrivileges=` can break
them. Hardening comes with Plan 5.

Remove:

    systemctl --user disable --now latchwire-agent.service
    sudo systemctl disable --now latchwire-daemon.service
    sudo rm /etc/systemd/user/latchwire-agent.service /etc/systemd/system/latchwire-daemon.service
    sudo systemctl daemon-reload

## Windows

**This has never been run:** see section 17 of the
[hardware checklist](hardware-checklist.md).

Put `latchwire.exe` and `wintun.dll` in a folder only administrators can write,
such as `C:\Program Files\Latchwire`: the service runs from it as SYSTEM and
loads the DLL from there. In an elevated prompt:

```
latchwire service install
```

That claims `%ProgramData%\Latchwire` and starts the `Latchwire` service.
Administrator commands (`add`, `remove`, `policy` with changes) need an elevated
prompt, the counterpart of `sudo`. To run the agent at logon as the user, with
no console:

```
schtasks /create /tn "Latchwire agent" /sc onlogon /rl limited /tr "\"C:\Program Files\Latchwire\latchwire.exe\" agent"
```

The task's console may flash at logon until packaging provides a build without
one. To remove the service, keeping tunnels: `latchwire service uninstall`.

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
