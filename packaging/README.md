# Packaging

| Path | What |
| --- | --- |
| `toolchain.env` | Build image and oldest supported macOS |
| `version.sh`, `build.sh` | The version stamp, one reproducible binary |
| `check-reproducible.sh` | Two builds, compared byte by byte |
| `third-party.sh`, `THIRD_PARTY.md` | Licence list and licence texts |
| `check-dco.sh` | `Signed-off-by` check of a git range |
| `linux/` | systemd units, deb, rpm, tarball |
| `linux/test/` | Real install, upgrade, tunnel and removal in systemd containers |
| `macos/` | launchd jobs, `.pkg`, signing, notarization, Homebrew cask |

## Build

Builds use the latest stable toolchain: the newest image of the tag in
`toolchain.env`, the newest nfpm and libpcsclite headers, and on macOS the
Go on your `PATH`. Each build records what it used in `BUILD-INFO`, next to its
output. Ship that file with the release.

Linux, on any machine with Docker (cgo needs libpcsclite, so the binary is
built in a container):

```bash
packaging/linux/build-in-container.sh --arch arm64
```

The output is in `dist/linux/`: `.deb`, `.rpm`, `.tar.gz`, `SHA256SUMS`.

macOS, unsigned:

```bash
packaging/macos/build-universal.sh --out dist/macos/latchwire
```

```bash
packaging/third-party.sh --licenses dist/macos/THIRD_PARTY_LICENSES.txt
```

```bash
packaging/macos/build-pkg.sh --binary dist/macos/latchwire --licenses dist/macos/THIRD_PARTY_LICENSES.txt --out dist/macos/latchwire.pkg
```

`build-pkg.sh --app PATH` adds a desktop application bundle to `/Applications`
when one exists. Nothing depends on it.

## Check that two builds match

```bash
packaging/check-reproducible.sh linux arm64
```

```bash
packaging/check-reproducible.sh macos
```

Each builds twice, from different paths and with empty build caches. To check
a published release, rebuild the tag with the versions in its `BUILD-INFO`:

```bash
git checkout vX.Y.Z
```

```bash
packaging/linux/build-in-container.sh --arch amd64 --build-info BUILD-INFO --out /tmp/rebuilt
```

```bash
diff /tmp/rebuilt/SHA256SUMS SHA256SUMS
```

What is covered:

- Linux: binary, tarball, deb and rpm are identical. `BUILD-INFO` holds the
  image digest (Go, C toolchain, glibc) and the nfpm and libpcsclite-dev
  versions. Debian may drop an old libpcsclite-dev version from its mirrors;
  the rebuild then stops and says so.
- macOS: the binary is identical given the same Go, compiler and SDK, which
  `BUILD-INFO` records. Set `GOTOOLCHAIN=` to the recorded Go to rebuild.
  `.pkg` files carry timestamps and are not compared.
- A Developer ID signature changes the bytes. To compare, remove the signature
  from a copy of the release binary and of your own build first:
  `codesign --remove-signature latchwire`.

## Test

```bash
packaging/linux/test/run.sh debian
```

Also `ubuntu`, `fedora` and `rocky`. Run it after any change to a unit or to
`lifecycle.sh`; it only touches the container's own network.

```bash
bash packaging/macos/test/lifecycle-test.sh
```

That runs against stubs in a scratch directory and needs no root. CI also
installs the real package on its throw-away macOS runner. Do not install it
on a machine you care about to test it.

## Release (macOS), by a person

Nothing in the repository holds a credential, and CI signs nothing. Every
script stops with the name of what is missing. The order matters: the binary
is signed before it goes into the package.

1. Build the universal binary.
2. `DEVELOPER_ID_APPLICATION=... packaging/macos/sign-binary.sh dist/macos/latchwire`
3. Build the package from that binary.
4. `DEVELOPER_ID_INSTALLER=... packaging/macos/sign-pkg.sh in.pkg latchwire-X.Y.Z.pkg`
5. Create a notarization profile once with `xcrun notarytool store-credentials`.
   Then run `NOTARY_KEYCHAIN_PROFILE=... packaging/macos/notarize.sh latchwire-X.Y.Z.pkg`.
   For CI use `APPLE_API_KEY_PATH`, `APPLE_API_KEY_ID` and `APPLE_API_ISSUER`.
6. `packaging/macos/render-cask.sh X.Y.Z latchwire-X.Y.Z.pkg` prints the cask.
   The URL in it expects the file on the GitHub release `vX.Y.Z`.

The Linux packages are not signed yet: there is no signing key and no
repository. Publish `SHA256SUMS` and `BUILD-INFO` with the release. Current
Fedora's plain `rpm -i` and `rpm -U` refuse an unsigned package ("does not
verify: no signature"); `dnf install ./latchwire-*.rpm` works.
