#!/bin/sh
# Prints the version to stamp: LATCHWIRE_VERSION when set, X.Y.Z when HEAD
# carries exactly the tag vX.Y.Z, else 0.0.0-dev.<commit time>.g<sha>, with
# .dirty added for uncommitted changes. Always a valid semantic version:
# nfpm maps it to deb and rpm version rules.
set -eu
cd "$(dirname "$0")/.."

if [ -n "${LATCHWIRE_VERSION:-}" ]; then
	printf '%s\n' "$LATCHWIRE_VERSION"
	exit 0
fi
dirty=
[ -z "$(git status --porcelain)" ] || dirty=.dirty
if tag=$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null) && [ -z "$dirty" ]; then
	printf '%s\n' "${tag#v}"
	exit 0
fi
stamp=$(TZ=UTC git show -s --date='format-local:%Y%m%d%H%M%S' --format=%cd HEAD)
printf '0.0.0-dev.%s.g%s%s\n' "$stamp" "$(git rev-parse --short=7 HEAD)" "$dirty"
