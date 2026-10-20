# Latchwire

Latchwire is an open-source WireGuard-compatible client that keeps the static X25519 private key inside a hardware token (YubiKey PIV): the key is generated on the card and never leaves it, the protocol and the server stay unchanged, and no card means no tunnel. Design: [docs/superpowers/specs/2026-10-20-latchwire-design.md](docs/superpowers/specs/2026-10-20-latchwire-design.md). WireGuard is a registered trademark of Jason A. Donenfeld.

**Status: core, macOS and Linux command-line only.** Latchwire is pre-release software: it has not had an independent security review, and there are no signed releases yet.

- Security: [threat model](docs/threat-model.md) (what is and is not protected, including the card-sharing caveat) and [security policy](SECURITY.md) (how to report a vulnerability).
- Testing with real hardware: [docs/hardware-checklist.md](docs/hardware-checklist.md).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
