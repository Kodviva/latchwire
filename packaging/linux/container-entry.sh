#!/bin/sh
# Inside the build container of build-in-container.sh.
set -eu

arch=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
# shellcheck source=packaging/toolchain.env
. packaging/toolchain.env

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends "libpcsclite-dev=$PCSC_DEV_VERSION" >/dev/null || {
	echo "container-entry.sh: libpcsclite-dev=$PCSC_DEV_VERSION is not available: update PCSC_DEV_VERSION in packaging/toolchain.env (a new version changes the binary)" >&2
	exit 1
}

# nfpm needs a newer Go than the release is built with. It is a tool here:
# GOTOOLCHAIN=auto fetches what it asks for, checked against the Go checksum
# database. Its version is pinned.
GOTOOLCHAIN=auto GOBIN=/usr/local/bin go install "github.com/goreleaser/nfpm/v2/cmd/nfpm@$NFPM_VERSION" 2>/dev/null

work=$(mktemp -d)
sh packaging/build.sh --goos linux --goarch "$arch" --out "$work/latchwire"
sh packaging/third-party.sh --licenses "$work/THIRD_PARTY_LICENSES.txt"
sh packaging/linux/build-packages.sh "$work/latchwire" "$work/THIRD_PARTY_LICENSES.txt" "$arch" "$LATCHWIRE_VERSION" /out

if [ -n "$TEST_BINARIES" ]; then
	mkdir -p /out/test
	export GOFLAGS=-buildvcs=false GOTOOLCHAIN="go$GO_VERSION"
	go build -tags e2e -o /out/test/testagent ./test/e2e/linux/testagent
	go build -tags e2e -o /out/test/testserver ./test/e2e/linux/testserver
fi
(cd /out && find . -maxdepth 1 -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum >SHA256SUMS)
chown -R "$HOST_UID:$HOST_GID" /out
