#!/bin/sh
# Removes a tarball installation, /usr/local/lib/latchwire/uninstall.sh once
# installed. --purge also deletes the tunnels in /etc/latchwire.
set -eu

purge=
case ${1:-} in
'') ;;
--purge) purge=1 ;;
*) echo "usage: uninstall.sh [--purge]" >&2; exit 2 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo "uninstall.sh: run as root" >&2; exit 1; }

sh /usr/local/lib/latchwire/lifecycle.sh pre-remove
rm -f /usr/local/bin/latchwire /etc/systemd/system/latchwire-daemon.service /etc/systemd/user/latchwire-agent.service
rm -rf /usr/local/lib/latchwire /usr/local/share/doc/latchwire
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || :
fi
if [ -n "$purge" ]; then
	rm -rf /etc/latchwire
fi
