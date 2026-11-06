#!/bin/sh
# Builds the deb, the rpm and the tarball from a finished binary. Runs inside
# the container of build-in-container.sh (GNU tar, nfpm).
#
#   build-packages.sh <binary> <licenses file> <goarch> <version> <outdir>
#
# SOURCE_DATE_EPOCH sets every timestamp, so the outputs are reproducible.
set -eu

binary=$1 licenses=$2 arch=$3 version=$4 out=$5
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
umask 022

# ---- deb and rpm: binary in /usr/bin ----
pkgstage=$stage/pkg
mkdir -p "$pkgstage"
cp -R "$here/deb" "$here/rpm" "$pkgstage/"
cp "$binary" "$pkgstage/latchwire"
cp "$here/lifecycle.sh" "$root/LICENSE" "$pkgstage/"
cp "$licenses" "$pkgstage/THIRD_PARTY_LICENSES.txt"
for unit in latchwire-daemon.service latchwire-agent.service; do
	sed 's|/usr/local/bin/latchwire|/usr/bin/latchwire|' "$here/$unit" >"$pkgstage/$unit"
done

mkdir -p "$out"
build_time=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
sed -e "s|@BUILD_TIME@|$build_time|" -e "s|@ARCH@|$arch|" -e "s|@VERSION@|$version|" \
	-e "s|@STAGE@|$pkgstage|g" "$here/nfpm.yaml" >"$stage/nfpm.yaml"
nfpm package --config "$stage/nfpm.yaml" --packager deb --target "$out/"
nfpm package --config "$stage/nfpm.yaml" --packager rpm --target "$out/"

# ---- tarball: binary in /usr/local/bin, as the units say ----
name=latchwire-$version-linux-$arch
tarstage=$stage/tar/$name
mkdir -p "$tarstage"
cp "$binary" "$tarstage/latchwire"
cp "$here/lifecycle.sh" "$here/install.sh" "$here/uninstall.sh" \
	"$here/latchwire-daemon.service" "$here/latchwire-agent.service" "$root/LICENSE" "$tarstage/"
cp "$licenses" "$tarstage/THIRD_PARTY_LICENSES.txt"
chmod 0755 "$tarstage/latchwire" "$tarstage/lifecycle.sh" "$tarstage/install.sh" "$tarstage/uninstall.sh"
chmod 0644 "$tarstage/"*.service "$tarstage/LICENSE" "$tarstage/THIRD_PARTY_LICENSES.txt"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
	-C "$stage/tar" -cf - "$name" | gzip -9n >"$out/$name.tar.gz"
