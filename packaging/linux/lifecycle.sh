#!/bin/sh
# What every Linux package does at install, upgrade and removal. deb and rpm
# scripts and the tarball's install.sh only call this file:
#
#   lifecycle.sh post-install   first installation, new files in place
#   lifecycle.sh post-upgrade   upgrade, new files in place
#   lifecycle.sh pre-remove     removal for good, files still in place
#
# Failures here must not leave the package half-installed, so problems are
# reported and the script still exits 0.
#
# A graceful stop takes every tunnel down and lifts the kill switch, so an
# upgrade restarts the daemon only when nothing is up: see post_upgrade.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

UNIT=latchwire-daemon.service
AGENT=latchwire-agent.service
RUNDIR=/run/latchwire
JOURNAL=$RUNDIR/journal.json
SOCKET=/run/latchwire.sock
STOREDIR=/etc/latchwire/tunnels

say() { echo "latchwire: $*"; }

have_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

# journal_has_steps: the daemon has something applied (a tunnel up, a kill
# switch) or left behind. Every journaled step has a "name" field.
journal_has_steps() { [ -f "$JOURNAL" ] && grep -q '"name"' "$JOURNAL"; }

# each_user_agent VERB: runs systemctl VERB for the agent of every user who
# has a running user manager. Best effort, a stuck manager is skipped.
each_user_agent() {
	for dir in /run/user/*; do
		uid=${dir##*/}
		case $uid in '' | *[!0-9]*) continue ;; esac
		name=$(id -nu "$uid" 2>/dev/null) || continue
		# Not --machine: that needs systemd-container on some distributions.
		timeout 10 runuser -u "$name" -- env XDG_RUNTIME_DIR="$dir" systemctl --user "$1" "$AGENT" >/dev/null 2>&1 || :
	done
}

warn_shadowing_units() {
	# The tarball installs its units there itself.
	[ -z "${LATCHWIRE_TARBALL:-}" ] || return 0
	for f in /etc/systemd/system/$UNIT /etc/systemd/user/$AGENT; do
		[ -e "$f" ] && say "WARNING: $f overrides the packaged unit (a manual installation?): remove it, then run systemctl daemon-reload"
	done
}

post_install() {
	have_systemd || { say "systemd is not running: enable $UNIT yourself"; return 0; }
	systemctl daemon-reload || :
	warn_shadowing_units
	systemctl enable --now "$UNIT" || say "WARNING: could not start $UNIT"
	systemctl --global enable "$AGENT" >/dev/null 2>&1 || say "WARNING: could not enable $AGENT for all users"
	say "the agent starts at the next login; to start it now, as your user: systemctl --user start $AGENT"
}

# post_upgrade leaves a daemon that has anything up alone: restarting it
# would disconnect the tunnels and lift the kill switch without the user
# asking, and connecting again needs the PIN. The new binary takes over at
# the next start of the service. The agent follows the daemon.
post_upgrade() {
	have_systemd || return 0
	systemctl daemon-reload || :
	warn_shadowing_units
	if systemctl is-active --quiet "$UNIT" && journal_has_steps; then
		say "a tunnel or the kill switch is active: the daemon keeps running the old version"
		say "take the tunnels down, then run: systemctl restart $UNIT"
		return 0
	fi
	systemctl try-restart "$UNIT" || say "WARNING: could not restart $UNIT"
	each_user_agent try-restart
}

# clean_leftovers runs with the daemon stopped. Steps still in the journal
# mean a crash or a stop that timed out. The daemon knows how to undo them,
# so it starts once: its startup undoes what it can, and its graceful stop
# takes down a kill switch held over from the crash.
clean_leftovers() {
	if journal_has_steps; then
		say "the journal holds leftovers of an earlier run: cleaning up"
		rm -f "$SOCKET"
		systemctl reset-failed "$UNIT" >/dev/null 2>&1
		if systemctl start "$UNIT"; then
			i=0
			while [ ! -S "$SOCKET" ] && [ "$i" -lt 30 ]; do
				sleep 0.5
				i=$((i + 1))
			done
			systemctl stop "$UNIT" || :
		fi
	fi
	# Whatever happened above, no kill switch may survive the package.
	if command -v nft >/dev/null 2>&1 && nft list table inet latchwire >/dev/null 2>&1; then
		printf 'delete table inet latchwire\n' | nft -f - || say "WARNING: could not delete the nft table inet latchwire: nft delete table inet latchwire"
	fi
	rm -f "$SOCKET" "$STOREDIR/killswitch.state"
	if journal_has_steps; then
		say "WARNING: some changes could not be undone, see $JOURNAL; a reboot clears them"
	else
		rm -rf "$RUNDIR"
	fi
}

pre_remove() {
	if have_systemd; then
		systemctl --global disable "$AGENT" >/dev/null 2>&1 || :
		each_user_agent stop
		systemctl disable --now "$UNIT" || :
		systemctl reset-failed "$UNIT" >/dev/null 2>&1
		clean_leftovers
	fi
}

case ${1:-} in
post-install) post_install ;;
post-upgrade) post_upgrade ;;
pre-remove) pre_remove ;;
*)
	echo "usage: lifecycle.sh post-install|post-upgrade|pre-remove" >&2
	exit 2
	;;
esac
exit 0
