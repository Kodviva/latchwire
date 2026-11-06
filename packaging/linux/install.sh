#!/bin/sh
# Installs the Linux tarball under /usr/local, or upgrades it. Run as root
# from the unpacked directory. Same steps as the deb and rpm packages, except
# that the units go to /etc/systemd.
set -eu
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "install.sh: run as root" >&2; exit 1; }
if [ -e /usr/bin/latchwire ]; then
	echo "install.sh: /usr/bin/latchwire exists: a deb or rpm package is installed, remove it first" >&2
	exit 1
fi
for tool in nft ip sysctl; do
	command -v "$tool" >/dev/null 2>&1 || echo "install.sh: WARNING: $tool is not installed" >&2
done
ldconfig -p | grep -q libpcsclite || echo "install.sh: WARNING: libpcsclite is not installed: latchwire cannot start without it" >&2

action=post-install
[ ! -e /usr/local/bin/latchwire ] || action=post-upgrade

install -d -m 0755 /usr/local/bin /usr/local/lib/latchwire /usr/local/share/doc/latchwire /etc/systemd/user
# Write beside the target, then rename: a running daemon keeps its binary.
install -m 0755 latchwire /usr/local/bin/.latchwire.new
mv -f /usr/local/bin/.latchwire.new /usr/local/bin/latchwire
install -m 0644 latchwire-daemon.service /etc/systemd/system/latchwire-daemon.service
install -m 0644 latchwire-agent.service /etc/systemd/user/latchwire-agent.service
install -m 0755 lifecycle.sh uninstall.sh /usr/local/lib/latchwire/
install -m 0644 LICENSE THIRD_PARTY_LICENSES.txt /usr/local/share/doc/latchwire/

LATCHWIRE_TARBALL=1 sh /usr/local/lib/latchwire/lifecycle.sh "$action"
