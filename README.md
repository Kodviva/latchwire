# Latchwire

Latchwire is an open-source WireGuard-compatible client that keeps the static X25519 private key inside a hardware token (YubiKey PIV): the key is generated on the card and never leaves it, the protocol and the server stay unchanged, and no card means no tunnel. Design: [docs/design.md](docs/design.md). WireGuard is a registered trademark of Jason A. Donenfeld.

**Status: macOS and Linux command line, with network parity: full tunnel, DNS, kill switch, on-demand and allowed users.** The Linux network behaviour is tested end to end in a privileged container (`test/e2e/linux/run.sh`); the macOS network behaviour and everything that needs a real YubiKey are still to be verified with [docs/hardware-checklist.md](docs/hardware-checklist.md). The Windows port (service, named pipe IPC, Wintun, network configuration, WFP kill switch, PIN window) compiles and its pure logic is tested on other systems, but **it has never run on Windows**: treat it as unverified, and do not rely on its kill switch, until [section 17 of the checklist](docs/hardware-checklist.md#17-windows-nothing-here-has-ever-been-run) passes. Latchwire is pre-release software: it has not had an independent security review, and there are no signed releases yet.

- Security: [threat model](docs/threat-model.md) (what is and is not protected, including the card-sharing caveat and the limits of the kill switch and DNS handling) and [security policy](SECURITY.md) (how to report a vulnerability).
- Testing with real hardware: [docs/hardware-checklist.md](docs/hardware-checklist.md).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Desktop app

`desktop/` is a menu bar and tray app built with Fyne, in its own Go module. It hosts the key agent, so run it instead of `latchwire agent`. Test it with `cd desktop && go test ./...`; `desktop/build_macos.sh -tags demo` builds a demo that needs no card or daemon.

## Translations

Messages live in `internal/msg/locales/*.arb` (ICU MessageFormat); `en.arb` is the source. The steps for adding a message or a language are in `internal/msg/doc.go`.
