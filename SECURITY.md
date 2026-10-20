# Security policy

Latchwire keeps a WireGuard static key inside a hardware token. Security
reports are taken seriously. This page says how to report a problem and what
to expect.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security
problem.** Send a private report by email to:

> security@kodviva.com

Keep working exploit details out of the first email if you can; we will
arrange a safe channel in our reply.

Please include:

- What you found and what an attacker gains (for example: key extraction, PIN
  exposure, use of another user's tunnel, bypass of a rate limit, denial of
  service).
- The affected commit or version (`git rev-parse HEAD`), your operating system
  and version, and the YubiKey model and firmware version, if a card is
  involved.
- Steps to reproduce, a proof of concept, or a failing test. Logs help; please
  remove PINs, PUKs and management keys first. Never send us a PIN or any
  secret from a real card.
- Whether the problem needs the card to be plugged in, a local account, root, or
  network access to the machine.
- Whether you want to be credited, and by what name.

We will acknowledge your report, work with you to understand and fix it, and
agree a date for public disclosure with you. Please give us a reasonable time to
fix the problem before you publish details.

## Supported versions

Latchwire is pre-release software. There are no released versions yet, and
**only the `main` branch is supported**: fixes land there and nowhere else.
This section will list supported release lines once releases exist.

## What counts as a vulnerability

In scope, for example:

- Any way to make the private key, or an X25519 output, appear on disk, in a
  log, in a configuration file or in an IPC message other than the one
  documented.
- Any way the PIN is stored, logged, or sent anywhere except the card.
- Latchwire trying a factory default PIN, PUK or management key on a card in a
  way the [threat model](docs/threat-model.md) says it does not.
- A local user (or a fake agent or daemon) binding, rebinding, disconnecting,
  adding or removing a tunnel it should not be able to according to the
  [threat model](docs/threat-model.md), or posing as your card without access
  to it.
- A tunnel configuration that is accepted although it carries a private key, or
  that makes the daemon run commands.
- A bypass of the handshake rate limits and in-flight caps, or a way to make a
  remote party spend card operations beyond them.
- A tunnel that stays up after the card has been removed for longer than the
  threat model says.
- A mistake in the patches we carry in `third_party/` that weakens the
  upstream project.

Out of scope:

- The limits listed in "What Latchwire does NOT protect against" in the
  [threat model](docs/threat-model.md), for example malware running as you
  while the card is plugged in and the PIN has been entered, or other programs
  using a PIN-verified card, including other local users where the platform's
  PC/SC access policy lets them reach your card (they pass the proof of
  possession and can bind your unbound tunnels). These are known, documented
  behaviour. If you think the documentation understates them, that is worth a
  report.
- Problems in wireguard-go, piv-go, the Go standard library, the operating
  system, or YubiKey firmware that Latchwire does not make worse. Please report
  those to the upstream project. If a Latchwire change makes them reachable,
  tell us too.
- Reports that need root, or physical access to an unlocked machine with the
  card plugged in and the PIN entered, with no extra weakness.

Related documents: [threat model](docs/threat-model.md),
[contributing](CONTRIBUTING.md), [hardware checklist](docs/hardware-checklist.md).
