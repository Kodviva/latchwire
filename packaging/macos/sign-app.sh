#!/bin/sh
# Signs the desktop application with Developer ID and the hardened runtime,
# before it goes into the package:
#
#   DEVELOPER_ID_APPLICATION='Developer ID Application: NAME (TEAMID)' \
#       packaging/macos/sign-app.sh dist/macos/Latchwire.app
#
# Optional: LATCHWIRE_KEYCHAIN, the keychain that holds the identity. Nothing
# here creates or stores a credential.
set -eu

die() { echo "sign-app.sh: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: sign-app.sh <Latchwire.app>"
[ -n "${DEVELOPER_ID_APPLICATION:-}" ] || die "DEVELOPER_ID_APPLICATION is not set: the name of a 'Developer ID Application' identity; security find-identity -v -p codesigning lists them"
[ -d "$1/Contents/MacOS" ] || die "not an application bundle: $1"

# The bundle has one executable and no nested code, so signing the bundle
# signs it. --deep is not used: Apple advises against it for signing.
codesign --force --timestamp --options runtime \
	${LATCHWIRE_KEYCHAIN:+--keychain "$LATCHWIRE_KEYCHAIN"} \
	--sign "$DEVELOPER_ID_APPLICATION" "$1"
codesign --verify --strict --deep --verbose=2 "$1"
