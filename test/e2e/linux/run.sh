#!/usr/bin/env bash
# Latchwire Linux end-to-end test. It changes real network state, so it runs
# ONLY as root inside a throw-away privileged container; on a host it stops
# at once with a non-zero exit. All changes happen in network namespaces the
# test creates inside the container (and in the container's own
# /etc/resolv.conf); the host network is never touched.
#
# Run it from the repository root on the host:
#
#   docker run --rm --privileged --cap-add NET_ADMIN -v "$PWD":/src -w /src \
#       golang:1.25 bash test/e2e/linux/run.sh
#
# Never add --network host, --pid host or other mounts: the test assumes
# that the container's network and mount namespaces are its own.
#
# What it does: installs nftables, iproute2, openresolv, ping and the PC/SC
# headers; builds the production CLI (cmd/latchwire) and two test-only
# binaries (test/e2e/linux/testagent: the agent with software keys;
# test/e2e/linux/testserver: a wireguard-go peer with a software key); then
# runs the scenarios in e2e_test.go (build tag e2e).
set -euo pipefail

die() { echo "run.sh: $*" >&2; exit 1; }

# ---- refuse to run outside a container, or as non-root ----
in_container() {
	[ -f /.dockerenv ] && return 0
	[ -f /run/.containerenv ] && return 0
	grep -qE '(docker|containerd|kubepods|libpod)' /proc/1/cgroup 2>/dev/null && return 0
	return 1
}
in_container || die "refusing to run: not inside a container (see the docker run line in this file)"
[ "$(id -u)" -eq 0 ] || die "refusing to run: must be root inside the container"
[ -c /dev/net/tun ] || die "no /dev/net/tun: run the container with --privileged"

cd "$(dirname "$0")/../../.."
[ -f go.mod ] && grep -q '^module github.com/Kodviva/latchwire' go.mod || die "not in the Latchwire repository"

export LATCHWIRE_E2E=1
export LATCHWIRE_E2E_WORK=/tmp/latchwire-e2e
rm -rf "$LATCHWIRE_E2E_WORK"
mkdir -p "$LATCHWIRE_E2E_WORK/bin"
BIN=$LATCHWIRE_E2E_WORK/bin

echo "== installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends \
	nftables iproute2 openresolv iputils-ping procps libpcsclite-dev >/dev/null
ip netns add lw-probe 2>/dev/null || die "cannot create network namespaces: run the container with --privileged --cap-add NET_ADMIN"
ip netns del lw-probe

echo "== building"
# The bind-mounted repository may belong to another uid; skip VCS stamping.
export GOFLAGS=-buildvcs=false
go build -o "$BIN/latchwire" ./cmd/latchwire
go build -o "$BIN/testagent" ./test/e2e/linux/testagent
go build -o "$BIN/testserver" ./test/e2e/linux/testserver
go test -c -tags e2e -o "$BIN/e2e.test" ./test/e2e/linux
# The shipped CLI must not contain the software key.
deps=$(go list -deps ./cmd/latchwire)
if grep -q '/keyprovider/softkey$' <<<"$deps"; then
	die "cmd/latchwire links the software key"
fi

echo "== preparing resolv.conf (container only)"
# Docker bind-mounts /etc/resolv.conf; openresolv replaces the file, which
# a bind-mount target does not allow. Make it a plain file of this
# container. From here on the container has no working DNS of its own,
# which is why everything is built first.
if mountpoint -q /etc/resolv.conf; then
	cp /etc/resolv.conf /tmp/resolv.conf.docker
	umount /etc/resolv.conf
	cp /tmp/resolv.conf.docker /etc/resolv.conf
fi
cat >/etc/resolvconf.conf <<'EOF'
resolv_conf=/etc/resolv.conf
resolv_conf_options="timeout:1 attempts:1"
EOF
# The "DHCP" DNS of the client's physical interface: the router, which
# serves no DNS (so a name resolves only through the tunnel).
printf 'nameserver 10.77.0.1\n' | resolvconf -a c0

echo "== running scenarios"
set +e
"$BIN/e2e.test" -test.v -test.count=1 -test.timeout=15m 2>&1 | tee "$LATCHWIRE_E2E_WORK/e2e.out"
rc=${PIPESTATUS[0]}
set -e
echo "== summary"
grep -E -- '^\s*--- (PASS|FAIL|SKIP)' "$LATCHWIRE_E2E_WORK/e2e.out" || true
exit "$rc"
