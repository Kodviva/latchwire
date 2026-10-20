# Contributing to Latchwire

Thanks for helping. Open an issue before large changes.

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by` line. It states that you wrote the
change or have the right to submit it under the project license
(Apache-2.0), as described by the Developer Certificate of Origin 1.1
(https://developercertificate.org/).

Add the line with `git commit -s`:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and a working email address. Commits without a sign-off
are not merged. To fix the last commit: `git commit --amend -s --no-edit`.

## Third-party code

`third_party/wireguard-go` is a patched copy of wireguard-go (MIT). Every change
to it must be listed in `third_party/wireguard-go/PATCHES.md`, and upstream's
`go test ./...` must still pass there.

## Rules for key material

The private key stays in the hardware token. Never write a private key, an
X25519 output or a PIN to disk, logs or IPC messages. Never try a default PIN.
