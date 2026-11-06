#!/bin/sh
# Builds everything reproducible twice, from different paths and with empty
# build caches, and fails if a byte differs:
#
#   packaging/check-reproducible.sh linux amd64|arm64    binary inside the
#                                                        tarball, deb, rpm
#   packaging/check-reproducible.sh macos                universal binary
#
# See packaging/README.md for checking a published release.
set -eu

die() { echo "check-reproducible.sh: $*" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
LATCHWIRE_VERSION=$(sh packaging/version.sh)
LATCHWIRE_COMMIT=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
export LATCHWIRE_VERSION LATCHWIRE_COMMIT SOURCE_DATE_EPOCH

work=$(mktemp -d)
volumes=
cleanup() {
	rm -rf "$work"
	for v in $volumes; do docker volume rm "$v" >/dev/null 2>&1 || :; done
}
trap cleanup EXIT

case ${1:-} in
linux)
	arch=${2:?usage: check-reproducible.sh linux amd64|arm64}
	# The second build takes its versions from the first one's BUILD-INFO,
	# as a rebuild of a release does.
	info=
	for n in 1 2; do
		v=latchwire-repro-$$-$n
		volumes="$volumes $v"
		LATCHWIRE_GO_CACHE_VOLUME=$v packaging/linux/build-in-container.sh \
			--arch "$arch" --out "$work/out$n" --mount "/build/path$n/src" ${info:+--build-info "$info"} >/dev/null
		info=$work/out1/BUILD-INFO
	done
	sums1=$work/out1/SHA256SUMS
	sums2=$work/out2/SHA256SUMS
	;;
macos)
	for n in 1 2; do
		src=$work/path$n/src
		mkdir -p "$src"
		git archive HEAD | tar -x -C "$src"
		(cd "$src" && GOCACHE=$work/cache$n sh packaging/macos/build-universal.sh --out out/latchwire)
		(cd "$src/out" && shasum -a 256 latchwire) >"$work/sums$n"
	done
	sums1=$work/sums1
	sums2=$work/sums2
	;;
*) die "usage: check-reproducible.sh linux <arch> | macos" ;;
esac

cat "$sums1"
if ! diff "$sums1" "$sums2"; then
	die "the two builds differ"
fi
echo "check-reproducible.sh: both builds are identical"
