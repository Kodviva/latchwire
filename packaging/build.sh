#!/bin/sh
# Builds one reproducible latchwire binary:
#
#   packaging/build.sh --goos linux --goarch arm64 --out dist/latchwire
#
# The same source, Go and C toolchain give the same bytes, whatever the
# checkout path. Linux binaries link libpcsclite through cgo: build them
# with packaging/linux/build-in-container.sh, which fixes the C toolchain.
#
# Stamps: LATCHWIRE_VERSION (default: packaging/version.sh), LATCHWIRE_COMMIT
# (default: git HEAD). Both are explicit, so a build without .git works too.
set -eu

die() { echo "build.sh: $*" >&2; exit 1; }

goos=$(go env GOOS)
goarch=$(go env GOARCH)
out=
while [ $# -gt 0 ]; do
	case $1 in
	--goos) goos=${2:?}; shift 2 ;;
	--goarch) goarch=${2:?}; shift 2 ;;
	--out) out=${2:?}; shift 2 ;;
	*) die "unknown argument: $1" ;;
	esac
done
[ -n "$out" ] || die "--out is required"
case $out in /*) ;; *) out=$PWD/$out ;; esac

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
# shellcheck source=packaging/toolchain.env
. packaging/toolchain.env

ver=${LATCHWIRE_VERSION:-$(sh packaging/version.sh)}
rev=${LATCHWIRE_COMMIT:-$(git rev-parse HEAD)}

export GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=1
export GOFLAGS=-mod=readonly
if [ "$goos" = darwin ]; then
	# In the flags, not only in the environment: the Go build cache ignores
	# the environment variable and would reuse objects built for this Mac.
	export MACOSX_DEPLOYMENT_TARGET
	export CGO_CFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
	export CGO_LDFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
fi

# The shipped CLI must not contain the software key.
if go list -deps ./cmd/latchwire | grep -q '/keyprovider/softkey$'; then
	die "cmd/latchwire links the software key"
fi

mkdir -p "$(dirname "$out")"
go build -trimpath -buildvcs=false \
	-ldflags "-s -w -buildid= -X main.version=$ver -X main.commit=$rev" \
	-o "$out" ./cmd/latchwire
