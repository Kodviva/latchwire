#!/bin/sh
# Sends a signed installer to Apple's notary service, waits for the verdict
# and staples the ticket. Credentials come from the environment, one of:
#
#   NOTARY_KEYCHAIN_PROFILE   a profile made once by a person with
#                             xcrun notarytool store-credentials
#
#   APPLE_API_KEY_PATH, APPLE_API_KEY_ID, APPLE_API_ISSUER
#                             an App Store Connect API key, for CI
#
# An Apple ID password is not accepted: notarytool would need it on the
# command line, where other local processes can read it.
set -eu

die() { echo "notarize.sh: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: notarize.sh <signed.pkg>"
pkg=$1

if [ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]; then
	auth="profile"
else
	missing=
	for var in APPLE_API_KEY_PATH APPLE_API_KEY_ID APPLE_API_ISSUER; do
		eval "value=\${$var:-}"
		[ -n "$value" ] || missing="$missing $var"
	done
	[ -z "$missing" ] || die "no credentials: set NOTARY_KEYCHAIN_PROFILE, or all of APPLE_API_KEY_PATH APPLE_API_KEY_ID APPLE_API_ISSUER (missing:$missing)"
	[ -f "$APPLE_API_KEY_PATH" ] || die "APPLE_API_KEY_PATH: no such file: $APPLE_API_KEY_PATH"
	auth="key"
fi
[ -f "$pkg" ] || die "no such file: $pkg"
pkgutil --check-signature "$pkg" | grep -q 'Developer ID Installer' || die "$pkg is not signed with Developer ID Installer: run sign-pkg.sh first"

notary() {
	if [ "$auth" = profile ]; then
		xcrun notarytool "$@" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE"
	else
		xcrun notarytool "$@" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER"
	fi
}

result=$(mktemp)
trap 'rm -f "$result"' EXIT
notary submit "$pkg" --wait --output-format json >"$result" || :
status=$(plutil -extract status raw -o - "$result" 2>/dev/null) || status=unknown
if [ "$status" != Accepted ]; then
	id=$(plutil -extract id raw -o - "$result" 2>/dev/null) || id=
	cat "$result" >&2
	[ -z "$id" ] || notary log "$id" >&2 || :
	die "notarization failed: status $status"
fi
xcrun stapler staple "$pkg"
xcrun stapler validate "$pkg"
