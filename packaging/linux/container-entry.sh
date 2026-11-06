#!/bin/sh
# Inside the build container of build-in-container.sh.
set -eu

arch=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
if [ -n "$EXPECT_GO" ] && [ "$(go env GOVERSION)" != "$EXPECT_GO" ]; then
	echo "container-entry.sh: BUILD-INFO says $EXPECT_GO, the image has $(go env GOVERSION)" >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends "libpcsclite-dev${PCSC_VERSION:+=$PCSC_VERSION}" >/dev/null || {
	echo "container-entry.sh: cannot install libpcsclite-dev ${PCSC_VERSION:-}: Debian may have replaced that version" >&2
	exit 1
}

# GOTOOLCHAIN=auto: a tool may ask for a newer Go than the image has. Go
# checks what it downloads against its checksum database.
GOTOOLCHAIN=auto GOBIN=/usr/local/bin go install "github.com/goreleaser/nfpm/v2/cmd/nfpm@$NFPM_VERSION" 2>/dev/null

work=$(mktemp -d)
sh packaging/build.sh --goos linux --goarch "$arch" --out "$work/latchwire"
sh packaging/third-party.sh --licenses "$work/THIRD_PARTY_LICENSES.txt"
sh packaging/linux/build-packages.sh "$work/latchwire" "$work/THIRD_PARTY_LICENSES.txt" "$arch" "$LATCHWIRE_VERSION" /out

if [ -n "$TEST_BINARIES" ]; then
	mkdir -p /out/test
	export GOFLAGS=-buildvcs=false
	go build -tags e2e -o /out/test/testagent ./test/e2e/linux/testagent
	go build -tags e2e -o /out/test/testserver ./test/e2e/linux/testserver
fi
# Everything a rebuild needs to get the same bytes.
cat >/out/BUILD-INFO <<INFO
image=$BUILD_IMAGE
go=$(go env GOVERSION)
nfpm=$(go version -m /usr/local/bin/nfpm | awk '$1 == "mod" { print $3 }')
libpcsclite-dev=$(dpkg-query -W -f='${Version}' libpcsclite-dev)
INFO

(cd /out && find . -maxdepth 1 -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum >SHA256SUMS)
chown -R "$HOST_UID:$HOST_GID" /out
