#!/bin/sh
# Builds the Linux binary and packages in the pinned image of toolchain.env,
# for one architecture, on any host with Docker:
#
#   packaging/linux/build-in-container.sh --arch arm64 [--out dist/linux]
#       [--mount /src] [--test-binaries]
#
# --mount changes where the source is mounted, which a reproducibility check
# uses to prove that the path does not matter. --test-binaries also builds
# the e2e test agent and server into <out>/test: never ship those.
#
# Stamps: LATCHWIRE_VERSION, LATCHWIRE_COMMIT and SOURCE_DATE_EPOCH, taken
# from git when unset (the container sees no .git).
set -eu

arch=
out=dist/linux
mount=/src
test_binaries=
while [ $# -gt 0 ]; do
	case $1 in
	--arch) arch=${2:?}; shift 2 ;;
	--out) out=${2:?}; shift 2 ;;
	--mount) mount=${2:?}; shift 2 ;;
	--test-binaries) test_binaries=1; shift ;;
	*) echo "build-in-container.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ -n "$arch" ] || { echo "build-in-container.sh: --arch amd64|arm64 is required" >&2; exit 2; }

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
# shellcheck source=packaging/toolchain.env
. packaging/toolchain.env

version=${LATCHWIRE_VERSION:-$(sh packaging/version.sh)}
commit=${LATCHWIRE_COMMIT:-$(git rev-parse HEAD)}
epoch=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}

mkdir -p "$out"
outabs=$(cd "$out" && pwd)

# The go caches are named volumes: speed only, the output does not depend on
# them. check-reproducible.sh sets LATCHWIRE_GO_CACHE_VOLUME to its own empty
# volumes, because a shared cache would hide a difference between two builds.
# nfpm writes the hostname into the rpm header.
docker run --rm --platform "linux/$arch" --hostname latchwire-build \
	-v "$root:$mount:ro" -v "$outabs:/out" \
	-v "latchwire-go-mod:/go/pkg/mod" -v "${LATCHWIRE_GO_CACHE_VOLUME:-latchwire-go-cache-$arch}:/root/.cache/go-build" \
	-e LATCHWIRE_VERSION="$version" -e LATCHWIRE_COMMIT="$commit" -e SOURCE_DATE_EPOCH="$epoch" \
	-e TEST_BINARIES="$test_binaries" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
	"$GOLANG_IMAGE" sh "$mount/packaging/linux/container-entry.sh" "$arch"
