#!/bin/sh
# Signs a binary with Developer ID and the hardened runtime, before it goes
# into the package:
#
#   DEVELOPER_ID_APPLICATION='Developer ID Application: NAME (TEAMID)' \
#       packaging/macos/sign-binary.sh dist/macos/latchwire
#
# Optional: LATCHWIRE_KEYCHAIN, the keychain that holds the identity. Nothing
# here creates or stores a credential.
set -eu

die() { echo "sign-binary.sh: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: sign-binary.sh <binary>"
[ -n "${DEVELOPER_ID_APPLICATION:-}" ] || die "DEVELOPER_ID_APPLICATION is not set: the name of a 'Developer ID Application' identity; security find-identity -v -p codesigning lists them"
[ -f "$1" ] || die "no such file: $1"

codesign --force --timestamp --options runtime --identifier com.latchwire.cli \
	${LATCHWIRE_KEYCHAIN:+--keychain "$LATCHWIRE_KEYCHAIN"} \
	--sign "$DEVELOPER_ID_APPLICATION" "$1"
codesign --verify --strict --verbose=2 "$1"
