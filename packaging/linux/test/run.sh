#!/bin/sh
# Installs, upgrades and removes the real packages in a throw-away privileged
# container that boots systemd, with a real tunnel under the hardened units:
#
#   packaging/linux/test/run.sh debian|ubuntu|fedora|rocky [amd64|arm64]
#
# It changes only the container's own network. Do not add --network host.
# It builds two package versions, so it needs a few minutes the first time.
set -eu

distro=${1:?usage: run.sh debian|ubuntu|fedora|rocky [arch]}
arch=${2:-$(docker version --format '{{.Server.Arch}}')}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=$root/dist/install-test/$arch

if [ -z "${SKIP_BUILD:-}" ]; then
	rm -rf "$out"
	LATCHWIRE_VERSION=9.0.0 "$root/packaging/linux/build-in-container.sh" --arch "$arch" --out "$out/old"
	LATCHWIRE_VERSION=9.0.1 "$root/packaging/linux/build-in-container.sh" --arch "$arch" --out "$out/new" --test-binaries
fi

image=latchwire-install-test-$distro:$arch
docker build --quiet --platform "linux/$arch" -t "$image" -f "$here/Dockerfile.$distro" "$here" >/dev/null

name=latchwire-install-test-$distro-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || :' EXIT
docker run -d --name "$name" --platform "linux/$arch" --privileged --cgroupns=private \
	--tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
	-v "$out:/pkg:ro" -v "$here/inside.sh:/inside.sh:ro" \
	"$image" >/dev/null

docker exec -e "DISTRO=$distro" "$name" bash /inside.sh
