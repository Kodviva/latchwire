# Latchwire

Latchwire is an open-source WireGuard-compatible client that keeps the static X25519 private key inside a hardware token (YubiKey PIV): the key is generated on the card and never leaves it, the protocol and the server stay unchanged, and no card means no tunnel. Design: [docs/superpowers/specs/2026-10-20-latchwire-design.md](docs/superpowers/specs/2026-10-20-latchwire-design.md). WireGuard is a registered trademark of Jason A. Donenfeld.
