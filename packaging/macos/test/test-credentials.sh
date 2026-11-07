#!/bin/sh
# Without credentials every signing script must stop before doing anything,
# and name what is missing. Safe anywhere: nothing signs or goes on the
# network.
set -u

here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
: >"$tmp/file"
failures=0

# expect NEEDLE COMMAND...: the command fails and its stderr has NEEDLE.
expect() {
	needle=$1
	shift
	if out=$(env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "$@" 2>&1); then
		echo "FAIL exit 0: $*"
		failures=$((failures + 1))
	elif printf '%s' "$out" | grep -q "$needle"; then
		echo "ok   $needle"
	else
		echo "FAIL no '$needle' in: $out"
		failures=$((failures + 1))
	fi
}

expect DEVELOPER_ID_APPLICATION "$here/sign-binary.sh" "$tmp/file"
expect DEVELOPER_ID_APPLICATION "$here/sign-app.sh" "$tmp"
expect DEVELOPER_ID_INSTALLER "$here/sign-pkg.sh" "$tmp/file" "$tmp/out"
expect NOTARY_KEYCHAIN_PROFILE "$here/notarize.sh" "$tmp/file"
expect APPLE_API_KEY_ID "$here/notarize.sh" "$tmp/file"
# A partial key says which part is missing.
expect 'missing: APPLE_API_KEY_ID' env APPLE_API_KEY_PATH=/x APPLE_API_ISSUER=y "$here/notarize.sh" "$tmp/file"
# Credentials set, unsigned package: stops before contacting Apple.
expect 'is not signed' env NOTARY_KEYCHAIN_PROFILE=x "$here/notarize.sh" "$tmp/file"

# The release stops before building, on the first thing missing.
expect DEVELOPER_ID_APPLICATION "$here/release.sh" --out "$tmp/dist"
expect DEVELOPER_ID_INSTALLER env DEVELOPER_ID_APPLICATION=x "$here/release.sh" --out "$tmp/dist"
expect NOTARY_KEYCHAIN_PROFILE env DEVELOPER_ID_APPLICATION=x DEVELOPER_ID_INSTALLER=y \
	"$here/release.sh" --out "$tmp/dist"
expect 'no valid identity' env DEVELOPER_ID_APPLICATION='Developer ID Application: Nobody (0000000000)' \
	DEVELOPER_ID_INSTALLER=y NOTARY_KEYCHAIN_PROFILE=z "$here/release.sh" --out "$tmp/dist"
[ ! -e "$tmp/dist" ] || { echo "FAIL release.sh created its output before the checks"; failures=$((failures + 1)); }

[ "$failures" -eq 0 ] || exit 1
