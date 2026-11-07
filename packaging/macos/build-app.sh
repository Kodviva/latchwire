#!/bin/sh
# Builds the universal (arm64 and x86_64) desktop application, not signed
# beyond the ad-hoc signature the Go linker adds:
#
#   packaging/macos/build-app.sh --out dist/macos/Latchwire.app
#
# The version comes from packaging/version.sh, like the CLI. For a release,
# sign it with sign-app.sh and give it to build-pkg.sh --app.
set -eu

die() { echo "build-app.sh: $*" >&2; exit 1; }

out=
while [ $# -gt 0 ]; do
	case $1 in
	--out) out=${2:?}; shift 2 ;;
	*) die "unknown argument: $1" ;;
	esac
done
[ -n "$out" ] || die "--out is required"
case $out in *.app) ;; *) die "--out must end in .app: $out" ;; esac
case $out in /*) ;; *) out=$PWD/$out ;; esac

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/toolchain.env
. "$root/packaging/toolchain.env"
version=${LATCHWIRE_VERSION:-$(sh "$root/packaging/version.sh")}

# Both bundle versions take numbers only. A release X.Y.Z goes into both. A
# development build 0.0.0-dev.20261107120000.gabc1234 gets 0.0.0 and, as
# CFBundleVersion, the commit time, which grows with every commit.
short=${version%%-*}
case $short in
[0-9]*.[0-9]*.[0-9]*) ;;
*) die "version does not start with X.Y.Z: $version" ;;
esac
case $version in
*-dev.*) build=$(printf '%s' "$version" | sed -E 's/^[^-]*-dev\.([0-9]+)\..*/\1/') ;;
*) build=$short ;;
esac

export CGO_ENABLED=1 GOOS=darwin GOFLAGS=-mod=readonly MACOSX_DEPLOYMENT_TARGET
export CGO_CFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
export CGO_LDFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for arch in arm64 amd64; do
	(cd "$root/desktop" && GOARCH=$arch go build -trimpath -buildvcs=false \
		-ldflags "-s -w -buildid=" -o "$work/latchwire-desktop.$arch" .)
done

rm -rf "$out"
mkdir -p "$out/Contents/MacOS" "$out/Contents/Resources"
lipo -create -output "$out/Contents/MacOS/latchwire-desktop" \
	"$work/latchwire-desktop.arm64" "$work/latchwire-desktop.amd64"
sed -e "/<key>CFBundleShortVersionString<\/key>/{n;s|<string>.*</string>|<string>$short</string>|;}" \
	-e "/<key>CFBundleVersion<\/key>/{n;s|<string>.*</string>|<string>$build</string>|;}" \
	-e "/<key>LSMinimumSystemVersion<\/key>/{n;s|<string>.*</string>|<string>$MACOSX_DEPLOYMENT_TARGET</string>|;}" \
	"$root/desktop/Info.plist" >"$out/Contents/Info.plist"
plutil -lint -s "$out/Contents/Info.plist"
[ "$(plutil -extract CFBundleShortVersionString raw -o - "$out/Contents/Info.plist")" = "$short" ] ||
	die "could not stamp the version into Info.plist"
cp "$root/desktop/assets/icon.icns" "$out/Contents/Resources/icon.icns"
# The executable alone carries the linker's signature, which a bundle with
# resources does not accept. Ad hoc for a local run; sign-app.sh replaces it.
codesign --force --sign - "$out"
