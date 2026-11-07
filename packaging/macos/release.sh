#!/bin/sh
# Builds, signs and notarizes the macOS release in one go, in the order the
# signatures need: the CLI and the application first, then the package that
# carries them, then notarization of that package.
#
#   DEVELOPER_ID_APPLICATION='Developer ID Application: NAME (TEAMID)' \
#   DEVELOPER_ID_INSTALLER='Developer ID Installer: NAME (TEAMID)' \
#   NOTARY_KEYCHAIN_PROFILE=latchwire \
#       packaging/macos/release.sh [--out dist/macos]
#
# Notarization also takes APPLE_API_KEY_PATH, APPLE_API_KEY_ID and
# APPLE_API_ISSUER instead of the profile (see notarize.sh). Every credential
# is checked before the build starts. Output: latchwire-VERSION.pkg, the cask,
# SHA256SUMS and BUILD-INFO.
set -eu

die() { echo "release.sh: $*" >&2; exit 1; }

out=dist/macos
while [ $# -gt 0 ]; do
	case $1 in
	--out) out=${2:?}; shift 2 ;;
	*) die "unknown argument: $1" ;;
	esac
done

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# Fail before a ten-minute build, not after it.
[ -n "${DEVELOPER_ID_APPLICATION:-}" ] || die "DEVELOPER_ID_APPLICATION is not set: the name of a 'Developer ID Application' identity; security find-identity -v -p codesigning lists them"
[ -n "${DEVELOPER_ID_INSTALLER:-}" ] || die "DEVELOPER_ID_INSTALLER is not set: the name of a 'Developer ID Installer' identity; security find-identity -v lists them"
if [ -z "${NOTARY_KEYCHAIN_PROFILE:-}" ]; then
	for var in APPLE_API_KEY_PATH APPLE_API_KEY_ID APPLE_API_ISSUER; do
		eval "value=\${$var:-}"
		[ -n "$value" ] || die "no notarization credentials: set NOTARY_KEYCHAIN_PROFILE, or all of APPLE_API_KEY_PATH APPLE_API_KEY_ID APPLE_API_ISSUER ($var is missing)"
	done
fi
identities=$(security find-identity -v ${LATCHWIRE_KEYCHAIN:+"$LATCHWIRE_KEYCHAIN"})
for id in "$DEVELOPER_ID_APPLICATION" "$DEVELOPER_ID_INSTALLER"; do
	printf '%s\n' "$identities" | grep -qF "\"$id\"" || die "no valid identity in the keychain: $id"
done

version=${LATCHWIRE_VERSION:-$(sh "$root/packaging/version.sh")}
case $version in
*-dev.*) echo "release.sh: WARNING: $version is a development build: HEAD carries no vX.Y.Z tag" >&2 ;;
esac
export LATCHWIRE_VERSION="$version"

mkdir -p "$out"
out=$(cd "$out" && pwd)
pkg=$out/latchwire-$version.pkg
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$here/build-universal.sh" --out "$work/latchwire"
"$here/sign-binary.sh" "$work/latchwire"
"$here/build-app.sh" --out "$work/Latchwire.app"
"$here/sign-app.sh" "$work/Latchwire.app"
"$root/packaging/third-party.sh" --licenses "$work/THIRD_PARTY_LICENSES.txt"
"$here/build-pkg.sh" --binary "$work/latchwire" --licenses "$work/THIRD_PARTY_LICENSES.txt" \
	--app "$work/Latchwire.app" --out "$work/unsigned.pkg"
"$here/sign-pkg.sh" "$work/unsigned.pkg" "$pkg"
"$here/notarize.sh" "$pkg"

# What a downloaded copy meets: Gatekeeper, with the stapled ticket.
spctl --assess --type install --verbose=2 "$pkg"

cp "$work/BUILD-INFO" "$out/BUILD-INFO"
"$here/render-cask.sh" "$version" "$pkg" >"$out/latchwire.rb"
(cd "$out" && shasum -a 256 "$(basename "$pkg")" BUILD-INFO >SHA256SUMS)
echo "$pkg"
