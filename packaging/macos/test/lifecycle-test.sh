#!/bin/bash
# Runs lifecycle.sh against stub launchctl, pfctl and pkgutil in a scratch
# directory. LW_ROOT sends every path and command there: it never touches
# launchd, pf or the installed system, and needs no root.
set -u

here=$(cd "$(dirname "$0")/.." && pwd)
failures=0
pass() { echo "  ok   $*"; }
fail() {
	echo "  FAIL $*"
	failures=$((failures + 1))
}
check() {
	local d=$1
	shift
	if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}
refute() {
	local d=$1
	shift
	if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi
}
called() { grep -q -- "$1" "$root/calls"; }

# fresh [BEHAVIOUR]: a new fake machine with the package's files in place.
# Stub state: $root/loaded exists while the daemon is loaded; a bootstrap
# creates the socket, and undoes the journal (like the real startup and
# stop), unless $root/stuck exists.
fresh() {
	root=$(mktemp -d)
	mkdir -p "$root/bin" "$root/sbin" "$root/usr/sbin" "$root/usr/local/latchwire/bin" "$root/var/run" "$root/var/log" \
		"$root/Library/LaunchDaemons" "$root/Library/LaunchAgents" "$root/etc/newsyslog.d" \
		"$root/Library/Application Support/Latchwire/tunnels"
	touch "$root/Library/LaunchDaemons/com.latchwire.daemon.plist" "$root/Library/LaunchAgents/com.latchwire.agent.plist" \
		"$root/etc/newsyslog.d/com.latchwire.daemon.conf" "$root/usr/local/latchwire/bin/latchwire" \
		"$root/Library/Application Support/Latchwire/tunnels/wg0.conf"
	cp "$here/lifecycle.sh" "$root/usr/local/latchwire/lifecycle.sh"
	cat >"$root/bin/launchctl" <<STUB
#!/bin/bash
root="$root"
echo "launchctl \$*" >>"\$root/calls"
case \$1 in
print) [ -e "\$root/loaded" ]; exit \$? ;;
bootstrap)
	if [ "\$2" = system ]; then
		touch "\$root/loaded"
		[ -e "\$root/stuck" ] || printf '{"version":1,"owners":{}}\n' >"\$root/var/run/latchwire/journal.json" 2>/dev/null
		/usr/bin/python3 -I -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "\$root/var/run/latchwire.sock"
	fi
	;;
bootout) case \$2 in system/*) rm -f "\$root/loaded" ;; esac ;;
esac
exit 0
STUB
	printf '#!/bin/bash\necho "pfctl $*" >>"%s/calls"\n' "$root" >"$root/sbin/pfctl"
	printf '#!/bin/bash\necho "pkgutil $*" >>"%s/calls"\n' "$root" >"$root/usr/sbin/pkgutil"
	chmod +x "$root/bin/launchctl" "$root/sbin/pfctl" "$root/usr/sbin/pkgutil"
	: >"$root/calls"
}
journal_with_steps() {
	mkdir -p "$root/var/run/latchwire"
	cat >"$root/var/run/latchwire/journal.json" <<'JSON'
{
  "version": 1,
  "owners": {
    "latchwire:killswitch": [
      {"name": "pfctl", "args": ["-a", "com.apple/250.latchwire", "-F", "all"]},
      {"name": "pfctl", "args": ["-X", "12345"]}
    ]
  }
}
JSON
}
run() { LW_ROOT=$root sh "$root/usr/local/latchwire/lifecycle.sh" "$@" >"$root/out" 2>&1; }

echo "== first installation"
fresh
run post-install
check "starts the daemon" called 'bootstrap system .*com.latchwire.daemon.plist'
refute "does not boot out anything of the daemon" called 'bootout system'
check "log file exists" test -e "$root/var/log/latchwire-daemon.log"
check "CLI link" test "$(readlink "$root/usr/local/bin/latchwire")" = /usr/local/latchwire/bin/latchwire
rm -rf "$root"

echo "== upgrade with nothing up"
fresh
touch "$root/loaded"
: >"$root/var/log/latchwire-daemon.log"
run post-install
check "replaces the daemon" called 'bootout system/com.latchwire.daemon'
check "starts it again" called 'bootstrap system'
rm -rf "$root"

echo "== upgrade with the kill switch on"
fresh
touch "$root/loaded"
journal_with_steps
run post-install
refute "leaves the daemon alone" called 'bootout system'
refute "starts nothing" called 'bootstrap'
check "says so" grep -q 'keeps running the old version' "$root/out"
check "says how to finish" grep -q 'launchctl kickstart -k' "$root/out"
rm -rf "$root"

echo "== uninstall, clean"
fresh
touch "$root/loaded"
mkdir -p "$root/usr/local/bin"
ln -sf /usr/local/latchwire/bin/latchwire "$root/usr/local/bin/latchwire"
touch "$root/var/log/latchwire-daemon.log"
run uninstall
check "stops the daemon" called 'bootout system/com.latchwire.daemon'
check "flushes the pf anchor" called 'pfctl -a com.apple/250.latchwire -F all'
check "forgets the receipt" called 'pkgutil --forget com.latchwire.pkg'
refute "program removed" test -e "$root/usr/local/latchwire"
refute "plists removed" test -e "$root/Library/LaunchDaemons/com.latchwire.daemon.plist"
refute "CLI link removed" test -L "$root/usr/local/bin/latchwire"
refute "log removed" test -e "$root/var/log/latchwire-daemon.log"
refute "rotation removed" test -e "$root/etc/newsyslog.d/com.latchwire.daemon.conf"
check "tunnels kept" test -e "$root/Library/Application Support/Latchwire/tunnels/wg0.conf"
rm -rf "$root"

echo "== uninstall --purge"
fresh
run uninstall --purge
refute "tunnels deleted" test -e "$root/Library/Application Support/Latchwire"
rm -rf "$root"

echo "== uninstall, daemon dead, leftovers in the journal"
fresh
journal_with_steps
touch "$root/Library/Application Support/Latchwire/tunnels/killswitch.state"
run uninstall
check "reports the cleanup" grep -q leftovers "$root/out"
check "starts the daemon once" called 'bootstrap system'
check "stops it again" called 'bootout system/com.latchwire.daemon'
refute "no journal left" test -e "$root/var/run/latchwire"
refute "no socket left" test -e "$root/var/run/latchwire.sock"
refute "no kill switch record" test -e "$root/Library/Application Support/Latchwire/tunnels/killswitch.state"
rm -rf "$root"

echo "== uninstall, cleanup fails"
fresh
journal_with_steps
touch "$root/stuck"
run uninstall
check "releases the pf reference from the journal" called 'pfctl -X 12345'
check "warns" grep -q 'could not be undone' "$root/out"
check "keeps the journal for the record" test -e "$root/var/run/latchwire/journal.json"
rm -rf "$root"

echo "== refuses a link that is not ours"
fresh
mkdir -p "$root/usr/local/bin"
ln -s /somewhere/else "$root/usr/local/bin/latchwire"
run uninstall
check "foreign link kept" test -L "$root/usr/local/bin/latchwire"
rm -rf "$root"

echo
[ "$failures" -eq 0 ] && echo "== ALL PASSED" || { echo "== $failures FAILED"; exit 1; }
