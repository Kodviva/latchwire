#!/bin/sh
# Builds the Linux binary and packages in the image of toolchain.env, for one
# architecture, on any host with Docker:
#
#   packaging/linux/build-in-container.sh --arch arm64 [--out dist/linux]
#       [--mount /src] [--build-info FILE] [--test-binaries]
#
# By default it pulls the newest image and tools, and writes what it used to
# <out>/BUILD-INFO. --build-info takes such a file and uses exactly those
# versions: that is how a release is rebuilt.
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
build_info=
while [ $# -gt 0 ]; do
	case $1 in
	--arch) arch=${2:?}; shift 2 ;;
	--out) out=${2:?}; shift 2 ;;
	--mount) mount=${2:?}; shift 2 ;;
	--build-info) build_info=${2:?}; shift 2 ;;
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

nfpm_version=latest
pcsc_version=
expect_go=
if [ -n "$build_info" ]; then
	# The file may come from a download, and its values reach docker run, so
	# it must hold exactly one strict value per key: an official Go image by
	# digest, a release tag, a Debian version.
	field() { # field KEY PATTERN
		value=$(sed -n "s/^$1=//p" "$build_info")
		if [ "$(printf '%s\n' "$value" | wc -l)" -ne 1 ] || ! printf '%s\n' "$value" | grep -Eq "^$2\$"; then
			echo "build-in-container.sh: $build_info: invalid or repeated $1" >&2
			exit 1
		fi
		printf '%s\n' "$value"
	}
	image=$(field image 'golang@sha256:[0-9a-f]{64}') || exit 1
	expect_go=$(field go 'go[0-9]+\.[0-9]+(\.[0-9]+)?') || exit 1
	nfpm_version=$(field nfpm 'v[0-9]+\.[0-9]+\.[0-9]+') || exit 1
	pcsc_version=$(field libpcsclite-dev '[0-9][0-9A-Za-z.+~:-]*') || exit 1
	echo "build-in-container.sh: using $image"
else
	docker pull --quiet --platform "linux/$arch" "$GOLANG_IMAGE" >/dev/null
	image=$(docker image inspect --format '{{index .RepoDigests 0}}' "$GOLANG_IMAGE")
fi

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
	-e TEST_BINARIES="$test_binaries" -e BUILD_IMAGE="$image" \
	-e NFPM_VERSION="$nfpm_version" -e PCSC_VERSION="$pcsc_version" -e EXPECT_GO="$expect_go" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
	"$image" sh "$mount/packaging/linux/container-entry.sh" "$arch"
