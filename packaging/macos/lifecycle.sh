#!/bin/sh
# What the macOS package does at installation, upgrade and removal:
#
#   lifecycle.sh post-install         from the .pkg, new files in place
#   lifecycle.sh uninstall [--purge]  run by hand or by the Homebrew cask;
#                                     --purge also deletes the tunnels
#
# A graceful stop takes every tunnel down and lifts the kill switch, so an
# upgrade replaces the daemon only when nothing is up: see post_install.
#
# LW_ROOT prefixes every path and every system command, so that
# packaging/macos/test/lifecycle-test.sh runs this against stubs in a scratch
# directory and never touches the machine. Leave it unset otherwise.
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT=${LW_ROOT:-}
if [ "$(id -u)" -ne 0 ] && [ -z "$ROOT" ]; then
	echo "lifecycle.sh: run as root" >&2
	exit 1
fi

LAUNCHCTL=$ROOT/bin/launchctl
PFCTL=$ROOT/sbin/pfctl
PKGUTIL=$ROOT/usr/sbin/pkgutil
DAEMON_LABEL=com.latchwire.daemon
AGENT_LABEL=com.latchwire.agent
DAEMON_PLIST=$ROOT/Library/LaunchDaemons/$DAEMON_LABEL.plist
AGENT_PLIST=$ROOT/Library/LaunchAgents/$AGENT_LABEL.plist
PREFIX=$ROOT/usr/local/latchwire
CLI_LINK=$ROOT/usr/local/bin/latchwire
LOGFILE=$ROOT/var/log/latchwire-daemon.log
NEWSYSLOG=$ROOT/etc/newsyslog.d/com.latchwire.daemon.conf
RUNDIR=$ROOT/var/run/latchwire
JOURNAL=$RUNDIR/journal.json
SOCKET=$ROOT/var/run/latchwire.sock
SUPPORTDIR="$ROOT/Library/Application Support/Latchwire"
PF_ANCHOR=com.apple/250.latchwire
PKG_ID=com.latchwire.pkg

say() { echo "latchwire: $*"; }

# journal_has_steps: the daemon has something applied (a tunnel up, a kill
# switch) or left behind. Every journaled step has a "name" field.
journal_has_steps() { [ -f "$JOURNAL" ] && grep -q '"name"' "$JOURNAL"; }

daemon_loaded() { "$LAUNCHCTL" print "system/$DAEMON_LABEL" >/dev/null 2>&1; }

# gui_uids prints the uids that have a GUI login session: the console user,
# and everyone else with an agent running (fast user switching).
gui_uids() {
	console=$(stat -f %u "$ROOT/dev/console" 2>/dev/null) || console=0
	[ "$console" = 0 ] || echo "$console"
	ps -axo uid=,args= | awk '$2 ~ /latchwire$/ && $3 == "agent" { print $1 }'
}

post_install() {
	# launchd keeps the mode of an existing file; one it creates itself would
	# be readable by every user.
	if [ ! -e "$LOGFILE" ]; then
		(umask 077 && : >"$LOGFILE") && chown root:admin "$LOGFILE" && chmod 0640 "$LOGFILE" ||
			say "WARNING: could not prepare $LOGFILE"
	fi
	mkdir -p "$(dirname "$CLI_LINK")"
	# Only for the shell's PATH: launchd never goes through this link, which
	# may sit in a directory a user owns (Intel Homebrew).
	ln -sfn "/usr/local/latchwire/bin/latchwire" "$CLI_LINK" || say "WARNING: could not create $CLI_LINK"

	if daemon_loaded; then
		if journal_has_steps; then
			# Restarting would disconnect the tunnels and lift the kill
			# switch without the user asking; connecting again needs the PIN.
			say "a tunnel or the kill switch is active: the daemon keeps running the old version"
			say "take the tunnels down, then run: sudo launchctl kickstart -k system/$DAEMON_LABEL"
			return 0
		fi
		"$LAUNCHCTL" bootout "system/$DAEMON_LABEL" || :
	fi
	"$LAUNCHCTL" bootstrap system "$DAEMON_PLIST" || say "WARNING: could not start the daemon"
	for uid in $(gui_uids | sort -u); do
		"$LAUNCHCTL" bootout "gui/$uid/$AGENT_LABEL" >/dev/null 2>&1
		"$LAUNCHCTL" bootstrap "gui/$uid" "$AGENT_PLIST" || say "WARNING: could not start the agent of uid $uid"
	done
}

# clean_leftovers runs with the daemon stopped. Steps still in the journal
# mean a crash or a stop that timed out. The daemon knows how to undo them,
# so it starts once: its startup undoes what it can, and its graceful stop
# takes down a kill switch held over from the crash.
clean_leftovers() {
	if journal_has_steps; then
		say "the journal holds leftovers of an earlier run: cleaning up"
		rm -f "$SOCKET"
		if "$LAUNCHCTL" bootstrap system "$DAEMON_PLIST"; then
			i=0
			while [ ! -S "$SOCKET" ] && [ "$i" -lt 30 ]; do
				sleep 0.5
				i=$((i + 1))
			done
			"$LAUNCHCTL" bootout "system/$DAEMON_LABEL" || :
		fi
	fi
	# Whatever happened above, no kill switch may survive the package. The
	# pf reference token is only in the journal.
	"$PFCTL" -a "$PF_ANCHOR" -F all >/dev/null 2>&1 || :
	if [ -f "$JOURNAL" ]; then
		for tok in $(tr -d ' \n\t' <"$JOURNAL" | grep -o '"-X","[0-9]*"' | tr -dc '0-9\n'); do
			"$PFCTL" -X "$tok" >/dev/null 2>&1 || :
		done
	fi
	rm -f "$SOCKET" "$SUPPORTDIR/tunnels/killswitch.state"
	if journal_has_steps; then
		say "WARNING: some changes could not be undone, see $JOURNAL; a restart clears them"
	else
		rm -rf "$RUNDIR"
	fi
}

uninstall() {
	purge=
	case ${1:-} in
	'') ;;
	--purge) purge=1 ;;
	*) echo "usage: lifecycle.sh uninstall [--purge]" >&2; return 2 ;;
	esac

	for uid in $(gui_uids | sort -u); do
		"$LAUNCHCTL" bootout "gui/$uid/$AGENT_LABEL" >/dev/null 2>&1
	done
	if daemon_loaded; then
		"$LAUNCHCTL" bootout "system/$DAEMON_LABEL" || :
	fi
	clean_leftovers

	rm -f "$DAEMON_PLIST" "$AGENT_PLIST" "$NEWSYSLOG" "$LOGFILE"
	# Leave the link alone if someone replaced it with something else.
	if [ "$(readlink "$CLI_LINK" 2>/dev/null)" = /usr/local/latchwire/bin/latchwire ]; then
		rm -f "$CLI_LINK"
	fi
	if [ -n "$purge" ]; then
		rm -rf "$SUPPORTDIR"
	fi
	"$PKGUTIL" --forget "$PKG_ID" >/dev/null 2>&1
	# Last: this script lives there. The shell has read the whole function.
	rm -rf "$PREFIX"
}

main() {
	cmd=${1:-}
	[ $# -eq 0 ] || shift
	case $cmd in
	post-install) post_install ;;
	uninstall) uninstall "$@" ;;
	*)
		echo "usage: lifecycle.sh post-install | uninstall [--purge]" >&2
		return 2
		;;
	esac
}

main "$@"
exit $?
