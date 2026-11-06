#!/bin/sh
# Signs the installer with Developer ID Installer:
#
#   DEVELOPER_ID_INSTALLER='Developer ID Installer: NAME (TEAMID)' \
#       packaging/macos/sign-pkg.sh dist/macos/latchwire.pkg dist/macos/latchwire-signed.pkg
#
# Optional: LATCHWIRE_KEYCHAIN. Nothing here creates or stores a credential.
set -eu

die() { echo "sign-pkg.sh: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: sign-pkg.sh <input.pkg> <output.pkg>"
[ -n "${DEVELOPER_ID_INSTALLER:-}" ] || die "DEVELOPER_ID_INSTALLER is not set: the name of a 'Developer ID Installer' identity; security find-identity -v lists them"
[ -f "$1" ] || die "no such file: $1"

productsign --timestamp ${LATCHWIRE_KEYCHAIN:+--keychain "$LATCHWIRE_KEYCHAIN"} \
	--sign "$DEVELOPER_ID_INSTALLER" "$1" "$2"
pkgutil --check-signature "$2"
