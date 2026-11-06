#!/bin/sh
# Builds the universal (arm64 and x86_64) macOS binary, not signed beyond the
# ad-hoc signature the Go linker adds:
#
#   packaging/macos/build-universal.sh --out dist/macos/latchwire
set -eu

out=
while [ $# -gt 0 ]; do
	case $1 in
	--out) out=${2:?}; shift 2 ;;
	*) echo "build-universal.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ -n "$out" ] || { echo "build-universal.sh: --out is required" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$(dirname "$out")"
"$here/../build.sh" --goos darwin --goarch arm64 --out "$out.arm64"
"$here/../build.sh" --goos darwin --goarch amd64 --out "$out.amd64"
lipo -create -output "$out" "$out.arm64" "$out.amd64"
rm -f "$out.arm64" "$out.amd64"

# Everything a rebuild needs to get the same bytes.
cat >"$(dirname "$out")/BUILD-INFO" <<INFO
go=$(go env GOVERSION)
cc=$(cc --version | head -1)
macos-sdk=$(xcrun --sdk macosx --show-sdk-version 2>/dev/null || echo unknown)
INFO
