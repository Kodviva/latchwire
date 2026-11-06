#!/usr/bin/env bash
# The scenarios of run.sh, inside the booted container. It changes real
# network state, so it refuses to run anywhere else.
#
#   lws (netns): s0 10.77.0.1/24, wgs 10.66.0.1/24, testserver :51820, DNS :53
#                dummy 203.0.113.1 is the "outside" host
#   main       : c0 10.77.0.2/24; route to 203.0.113.1 via 10.77.0.1
set -uo pipefail

[ -f /.dockerenv ] || { echo "inside.sh: not in a container, refusing" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "inside.sh: not root, refusing" >&2; exit 1; }

UNIT=latchwire-daemon.service
AGENT=latchwire-agent.service
OUTSIDE=203.0.113.1
TUN_PEER=10.66.0.1
WORK=/root/lw # /tmp is mounted noexec
USERNAME=lwuser
LOG=/tmp/step.log
failures=0

step() { printf '\n=== %s\n' "$*"; }
pass() { printf '  ok   %s\n' "$*"; }
fail() {
	printf '  FAIL %s\n' "$*"
	failures=$((failures + 1))
}
check() { # check DESCRIPTION COMMAND...
	local d=$1
	shift
	if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}
refute() { # refute DESCRIPTION COMMAND...
	local d=$1
	shift
	if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi
}
wait_for() { # wait_for SECONDS COMMAND...
	local n=$(($1 * 5))
	shift
	while [ "$n" -gt 0 ]; do
		"$@" >/dev/null 2>&1 && return 0
		sleep 0.2
		n=$((n - 1))
	done
	return 1
}
contains() { grep -q -- "$1" "$2"; }

if command -v dpkg >/dev/null 2>&1; then
	PKG=deb
	OLD=$(echo /pkg/old/*.deb)
	NEW=$(echo /pkg/new/*.deb)
	pkg_first() { apt-get install -y -qq "$1"; }
	pkg_again() { dpkg -i "$1"; }
	pkg_upgrade() { dpkg -i "$1"; }
	pkg_remove() { dpkg -r latchwire; }
	pkg_purge() { dpkg -P latchwire; }
	pkg_installed() { dpkg-query -W -f='${Status}' latchwire 2>/dev/null | grep -q 'ok installed'; }
else
	PKG=rpm
	OLD=$(echo /pkg/old/*.rpm)
	NEW=$(echo /pkg/new/*.rpm)
	pkg_first() { dnf install -y -q "$1"; }
	# The packages are unsigned, which current rpm refuses by default.
	pkg_again() { rpm -i --nosignature "$1"; }
	pkg_upgrade() { rpm -Uvh --oldpackage --nosignature "$1"; }
	pkg_remove() { rpm -e latchwire; }
	pkg_purge() { rpm -e latchwire; }
	pkg_installed() { rpm -q latchwire; }
fi

journal_steps() { [ -f /run/latchwire/journal.json ] && grep -q '"name"' /run/latchwire/journal.json; }
nft_table() { nft list table inet latchwire; }
outside_reachable() { ping -c1 -W1 "$OUTSIDE"; }
daemon_pid() { systemctl show -p MainPID --value "$UNIT"; }
tunnel_state() { latchwire status lwfull | grep -qiw "$1"; }
daemon_active() { systemctl is-active --quiet "$UNIT"; }
as_user() { runuser -u "$USERNAME" -- env XDG_RUNTIME_DIR="/run/user/$(id -u "$USERNAME")" "$@"; }
user_ctl() { as_user systemctl --user "$@"; }
agent_show() { user_ctl show -p "$1" --value "$AGENT"; }
agent_active() { [ "$(agent_show ActiveState)" = active ]; }

# Why the user manager did not come up. The agent scenarios depend on it.
user_manager_report() {
	local uid
	uid=$(id -u "$USERNAME")
	loginctl show-user "$USERNAME" --no-pager 2>&1 | grep -E '^(Linger|State)='
	systemctl status "user@$uid.service" "user-runtime-dir@$uid.service" systemd-logind.service --no-pager -l 2>&1 | tail -40
	journalctl -u "user@$uid.service" -u "user-runtime-dir@$uid.service" -u systemd-logind.service --no-pager 2>&1 | tail -40
	ls -la "/run/user/$uid" 2>&1
	stat -c '%A %U %n' /etc/passwd /etc/shadow /usr/sbin/unix_chkpwd 2>&1
	grep -E '^(passwd|shadow):' /etc/nsswitch.conf
	echo "shadow entry: $(getent shadow "$USERNAME" | cut -d: -f1)"
	grep -E '^Cap(Eff|Bnd)' /proc/self/status
}

# ---- the network and the fake card; survives all package changes ----
prepare_network() {
	mkdir -p "$WORK/keys"
	cp /pkg/new/test/testagent /pkg/new/test/testserver "$WORK/"
	chmod 0755 "$WORK/testagent" "$WORK/testserver"

	ip netns add lws
	ip link add name c0 type veth peer name s0 netns lws
	ip addr add 10.77.0.2/24 dev c0
	ip link set c0 up
	ip route add "$OUTSIDE/32" via 10.77.0.1
	ip -n lws link set lo up
	ip -n lws addr add 10.77.0.1/24 dev s0
	ip -n lws link set s0 up
	ip -n lws link add inet0 type dummy
	ip -n lws addr add "$OUTSIDE/32" dev inet0
	ip -n lws link set inet0 up
	ip -n lws route add default via 10.77.0.2
	ip netns exec lws sysctl -qw net.ipv4.ip_forward=1

	# Keys: a 32-byte scalar, clamped by the tools that read it.
	local serverpub clientpub
	head -c32 /dev/urandom | base64 >"$WORK/server.key"
	head -c32 /dev/urandom | base64 >"$WORK/keys/82.key"
	chmod 0600 "$WORK/server.key" "$WORK/keys/82.key"
	serverpub=$("$WORK/testagent" -pub "$WORK/server.key")
	clientpub=$("$WORK/testagent" -pub "$WORK/keys/82.key")

	ip netns exec lws "$WORK/testserver" -iface wgs -key "$WORK/server.key" -port 51820 \
		-peer "$clientpub@10.66.0.2/32" -dns 0.0.0.0:53 -answer probe.test=10.66.0.42 \
		>"$WORK/server.log" 2>&1 &
	wait_for 10 ip -n lws link show wgs || fail "testserver interface"
	ip -n lws addr add "$TUN_PEER/24" dev wgs
	ip -n lws link set wgs up

	local dnsline="DNS = $TUN_PEER"
	command -v resolvconf >/dev/null || command -v resolvectl >/dev/null || dnsline=
	cat >"$WORK/lwfull.conf" <<CONF
[Interface]
KeyRef = piv://4242/82
PublicKey = $clientpub
Address = 10.66.0.2/32
$dnsline

[Peer]
PublicKey = $serverpub
Endpoint = 10.77.0.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5
CONF
	touch "$WORK/card"
}

# prepare_dns cuts the container off from Docker's DNS, so it runs after the
# one installation that downloads dependencies.
prepare_dns() {
	# openresolv replaces resolv.conf, which Docker bind-mounts.
	if mountpoint -q /etc/resolv.conf; then
		cp /etc/resolv.conf /tmp/resolv.docker
		umount /etc/resolv.conf
		cp /tmp/resolv.docker /etc/resolv.conf
	fi
	if command -v resolvconf >/dev/null && ! systemctl is-active --quiet systemd-resolved; then
		printf 'resolv_conf=/etc/resolv.conf\n' >/etc/resolvconf.conf
		printf 'nameserver 10.77.0.1\n' | resolvconf -a c0
	fi
}

start_card() {
	"$WORK/testagent" -serial 4242 -card "$WORK/card" -keys "$WORK/keys" -poll 200ms >"$WORK/agent.log" 2>&1 &
	CARD_PID=$!
	wait_for 10 latchwire status
}
stop_card() {
	kill "$CARD_PID" 2>/dev/null
	wait "$CARD_PID" 2>/dev/null
}
tunnel_up() {
	latchwire status lwfull >/dev/null 2>&1 || latchwire add lwfull "$WORK/lwfull.conf"
	start_card
	# The test agent registers shortly after the daemon answers.
	wait_for 15 latchwire up lwfull
	wait_for 15 tunnel_state connected
}
assert_network_clean() { # assert_network_clean WHEN
	refute "$1: no nft table" nft_table
	refute "$1: no lwfull interface" ip link show lwfull
	refute "$1: no policy rule" sh -c 'ip rule | grep -q fwmark'
	refute "$1: journal has no steps" journal_steps
	check "$1: outside host reachable directly" outside_reachable
	refute "$1: tunnel DNS gone from resolv.conf" grep -q "nameserver $TUN_PEER" /etc/resolv.conf
}
assert_files_gone() { # assert_files_gone WHEN
	refute "$1: binary removed" test -e /usr/bin/latchwire
	refute "$1: lifecycle removed" test -e /usr/lib/latchwire
	refute "$1: daemon unit removed" test -e /usr/lib/systemd/system/$UNIT
	refute "$1: agent unit removed" test -e /usr/lib/systemd/user/$AGENT
	refute "$1: no enable link for the daemon" test -e /etc/systemd/system/multi-user.target.wants/$UNIT
	refute "$1: no global enable link for the agent" test -e /etc/systemd/user/default.target.wants/$AGENT
	refute "$1: no run directory" test -e /run/latchwire
	refute "$1: no socket" test -e /run/latchwire.sock
	refute "$1: no daemon process" pgrep -f 'latchwire daemon'
	refute "$1: no agent process" pgrep -f 'latchwire agent'
	refute "$1: no kill switch record" test -e /etc/latchwire/tunnels/killswitch.state
}

# ---- scenarios ----

scenario_install_starts() {
	step "install: units enabled and running under the sandbox"
	# A user with a running manager, like a logged-in desktop user.
	useradd -m "$USERNAME" 2>/dev/null
	loginctl enable-linger "$USERNAME"
	if ! wait_for 15 user_ctl show-environment; then
		user_manager_report
		fail "user manager running"
		return 1
	fi

	pkg_first "$OLD" >"$LOG" 2>&1 || { cat "$LOG"; fail "package installs"; return 1; }
	pass "package installs"
	prepare_dns
	check "daemon enabled" systemctl is-enabled "$UNIT"
	wait_for 10 daemon_active || { journalctl -u "$UNIT" --no-pager | tail -30; }
	check "daemon active" daemon_active
	check "CLI reaches the daemon" wait_for 10 latchwire status
	contains "9.0.0" <(latchwire version) && pass "version stamp 9.0.0" || fail "version stamp"
	check "agent enabled globally" test -e /etc/systemd/user/default.target.wants/$AGENT
	user_ctl daemon-reload
	user_ctl start "$AGENT"
	check "agent active" wait_for 10 agent_active
	journalctl -u "$UNIT" --no-pager | grep -iE 'denied|not permitted|read-only' && fail "daemon log has sandbox errors" || pass "daemon log clean"
	check "journal directory survives a stop" sh -c "systemctl stop $UNIT && test -d /run/latchwire && test \"\$(stat -c %a /run/latchwire)\" = 700 && systemctl start $UNIT"
	wait_for 10 latchwire status
	systemd-analyze security --no-pager "$UNIT" 2>/dev/null | tail -1
}

scenario_agent_reaches_pcsc() {
	step "agent sandbox: PC/SC is reachable"
	# pcscd asks polkit, which a container lacks. A desktop has it; the
	# hardware checklist covers that side.
	if /usr/sbin/pcscd --help 2>&1 | grep -q disable-polkit; then
		mkdir -p /run/systemd/system/pcscd.service.d
		printf '[Service]\nExecStart=\nExecStart=/usr/sbin/pcscd --foreground --auto-exit --disable-polkit\n' \
			>/run/systemd/system/pcscd.service.d/test.conf
	fi
	systemctl stop pcscd.service pcscd.socket 2>/dev/null
	systemctl daemon-reload
	systemctl start pcscd.socket
	# The same sandbox as the agent's unit, running "devices" once.
	local dir=/home/$USERNAME/.config/systemd/user
	install -d -o "$USERNAME" -g "$USERNAME" /home/$USERNAME/.config /home/$USERNAME/.config/systemd "$dir"
	sed -e 's|^ExecStart=.*|ExecStart=/usr/bin/latchwire devices|' -e 's|^Type=.*|Type=oneshot|' -e '/^Restart/d' \
		/usr/lib/systemd/user/$AGENT >"$dir/lw-devices.service"
	chown "$USERNAME:$USERNAME" "$dir/lw-devices.service"
	user_ctl daemon-reload
	if user_ctl start lw-devices.service; then
		pass "latchwire devices ran under the agent sandbox"
	else
		fail "latchwire devices failed under the agent sandbox"
		journalctl --no-pager -n 20 | grep -i latchwire
	fi
	rm -f "$dir/lw-devices.service"
	user_ctl daemon-reload
}

scenario_upgrade_restarts_when_idle() {
	step "upgrade with nothing up: daemon and agent move to the new version"
	local pid agentpid
	pid=$(daemon_pid)
	agentpid=$(agent_show MainPID)
	pkg_upgrade "$NEW" >"$LOG" 2>&1 || { cat "$LOG"; fail "upgrade"; return 1; }
	pass "upgrade"
	wait_for 10 latchwire status
	[ "$(daemon_pid)" != "$pid" ] && pass "daemon restarted" || fail "daemon not restarted"
	contains "9.0.1" <(latchwire version) && pass "version stamp 9.0.1" || fail "version stamp"
	check "daemon still enabled" systemctl is-enabled "$UNIT"
	wait_for 10 agent_active
	[ "$(agent_show MainPID)" != "$agentpid" ] && pass "agent restarted" || fail "agent not restarted"
}

scenario_tunnel_under_hardened_unit() {
	step "full tunnel with kill switch under the hardened unit"
	local resolvmode
	resolvmode=$(stat -c %a /etc/resolv.conf)
	tunnel_up && pass "tunnel connected" || {
		fail "tunnel connected"
		latchwire status lwfull
		journalctl -u "$UNIT" --no-pager | tail -30
		cat "$WORK/agent.log"
		return 1
	}
	check "TUN interface exists" ip link show lwfull
	check "ping through the tunnel" ping -c1 -W2 "$TUN_PEER"
	check "policy rule" sh -c 'ip rule | grep -q fwmark'
	check "src_valid_mark set through /proc/sys/net" test "$(sysctl -n net.ipv4.conf.all.src_valid_mark)" = 1
	check "nft kill switch table" nft_table
	check "journal holds steps" journal_steps
	check "journal mode 0600" test "$(stat -c %a /run/latchwire/journal.json)" = 600
	if grep -q '^DNS' "$WORK/lwfull.conf"; then
		if systemctl is-active --quiet systemd-resolved; then
			check "systemd-resolved got the tunnel DNS" sh -c "resolvectl dns lwfull | grep -q $TUN_PEER"
		else
			check "resolvconf got the tunnel DNS" grep -q "nameserver $TUN_PEER" /etc/resolv.conf
			check "resolv.conf keeps its mode" test "$(stat -c %a /etc/resolv.conf)" = "$resolvmode"
		fi
	fi
	latchwire down lwfull
	wait_for 10 sh -c '! ip link show lwfull' || :
	stop_card
	assert_network_clean "after down"
}

scenario_upgrade_keeps_kill_switch() {
	step "upgrade with the kill switch on: the daemon is left alone"
	pkg_upgrade "$OLD" >"$LOG" 2>&1 || { cat "$LOG"; fail "downgrade to prepare"; return 1; }
	wait_for 10 latchwire status
	tunnel_up || { fail "tunnel connected"; return 1; }
	local pid
	pid=$(daemon_pid)
	pkg_upgrade "$NEW" >"$LOG" 2>&1 || { cat "$LOG"; fail "upgrade"; return 1; }
	[ "$(daemon_pid)" = "$pid" ] && pass "daemon PID unchanged" || fail "daemon restarted"
	contains 'keeps running the old version' "$LOG" && pass "the upgrade says so" || { cat "$LOG"; fail "no notice"; }
	check "kill switch table still there" nft_table
	check "tunnel still carries traffic" ping -c1 -W2 "$TUN_PEER"
	check "tunnel still connected" tunnel_state connected
	latchwire down lwfull
	wait_for 10 sh -c '! ip link show lwfull' || :
	stop_card
	assert_network_clean "after down"
	systemctl restart "$UNIT"
	wait_for 10 latchwire status
	check "restart by hand starts the new version" sh -c 'readlink /proc/$(systemctl show -p MainPID --value latchwire-daemon.service)/exe | grep -q "^/usr/bin/latchwire$"'
}

# crash leaves what kill -9 leaves: the kill switch and DNS in place, the
# journal full, the tunnel gone.
crash() {
	tunnel_up || { fail "tunnel connected"; return 1; }
	stop_card
	systemctl kill --kill-whom=main --signal=KILL "$UNIT"
}

scenario_remove_after_crash_restarted() {
	step "remove after a crash, daemon restarted by systemd and holding the kill switch"
	crash || return 1
	wait_for 10 latchwire status
	check "kill switch held after the crash" nft_table
	refute "outside host blocked (fail closed)" outside_reachable
	pkg_remove >"$LOG" 2>&1 || { cat "$LOG"; fail "remove"; }
	assert_network_clean "after remove"
	assert_files_gone "after remove"
	check "tunnels kept on remove" test -f /etc/latchwire/tunnels/lwfull.conf
}

scenario_remove_after_crash_dead() {
	step "remove with the daemon dead and leftovers in the journal"
	pkg_again "$NEW" >"$LOG" 2>&1 || { cat "$LOG"; fail "reinstall"; return 1; }
	pass "reinstall"
	check "reinstall enables the daemon again" systemctl is-enabled "$UNIT"
	check "reinstall starts the daemon again" wait_for 10 latchwire status
	check "reinstall keeps the tunnels" test -f /etc/latchwire/tunnels/lwfull.conf
	mkdir -p /etc/systemd/system/$UNIT.d
	printf '[Service]\nRestart=no\n' >/etc/systemd/system/$UNIT.d/test.conf
	systemctl daemon-reload
	systemctl restart "$UNIT"
	wait_for 10 latchwire status
	crash || return 1
	wait_for 5 sh -c '! systemctl is-active --quiet latchwire-daemon.service'
	refute "daemon is dead" daemon_active
	check "journal holds leftovers" journal_steps
	check "kill switch left behind" nft_table
	rm -rf /etc/systemd/system/$UNIT.d
	pkg_remove >"$LOG" 2>&1 || { cat "$LOG"; fail "remove"; }
	contains 'leftovers' "$LOG" && pass "cleanup reported" || { cat "$LOG"; fail "cleanup not reported"; }
	assert_network_clean "after remove"
	assert_files_gone "after remove"
}

scenario_purge() {
	step "purge"
	if [ "$PKG" = deb ]; then
		pkg_again "$NEW" >"$LOG" 2>&1 || { cat "$LOG"; fail "reinstall"; return 1; }
		pkg_purge >"$LOG" 2>&1 || { cat "$LOG"; fail "purge"; }
		refute "purge deletes /etc/latchwire" test -e /etc/latchwire
		refute "package fully gone" pkg_installed
	else
		check "rpm has no purge: /etc/latchwire is documented to stay" test -d /etc/latchwire
		rm -rf /etc/latchwire
	fi
}

scenario_manual_unit_warns() {
	step "a manually installed unit is reported"
	printf '[Service]\nExecStart=/usr/local/bin/latchwire daemon\n' >/etc/systemd/system/$UNIT
	pkg_again "$NEW" >"$LOG" 2>&1 || { cat "$LOG"; fail "install"; }
	contains "overrides the packaged unit" "$LOG" && pass "warned" || { cat "$LOG"; fail "no warning"; }
	rm -f /etc/systemd/system/$UNIT
	pkg_remove >"$LOG" 2>&1 || { cat "$LOG"; fail "remove"; }
	systemctl daemon-reload
}

scenario_tarball() {
	step "tarball: install, upgrade in place, uninstall"
	mkdir -p /root/tar-old /root/tar-new
	tar -xzf /pkg/old/*.tar.gz -C /root/tar-old --strip-components=1
	tar -xzf /pkg/new/*.tar.gz -C /root/tar-new --strip-components=1
	/root/tar-old/install.sh >"$LOG" 2>&1 || { cat "$LOG"; fail "install.sh"; return 1; }
	check "daemon active" wait_for 10 daemon_active
	check "CLI reaches the daemon" wait_for 10 /usr/local/bin/latchwire status
	contains 'ExecStart=/usr/local/bin/latchwire daemon' /etc/systemd/system/$UNIT && pass "unit points to /usr/local/bin" || fail "unit path"
	local pid
	pid=$(daemon_pid)
	/root/tar-new/install.sh >"$LOG" 2>&1 || { cat "$LOG"; fail "upgrade"; }
	wait_for 10 /usr/local/bin/latchwire status
	[ "$(daemon_pid)" != "$pid" ] && pass "daemon restarted on upgrade" || fail "daemon not restarted"
	contains "9.0.1" <(/usr/local/bin/latchwire version) && pass "new version" || fail "version"
	refute "no override warning" contains "overrides the packaged unit" "$LOG"
	/usr/local/lib/latchwire/uninstall.sh --purge >"$LOG" 2>&1 || { cat "$LOG"; fail "uninstall.sh"; }
	refute "binary removed" test -e /usr/local/bin/latchwire
	refute "units removed" test -e /etc/systemd/system/$UNIT
	refute "lib removed" test -e /usr/local/lib/latchwire
	refute "/etc/latchwire purged" test -e /etc/latchwire
	refute "daemon gone" pgrep -f 'latchwire daemon'
}

wait_for 30 sh -c 'systemctl is-system-running | grep -qE "running|degraded"' || echo "systemd is slow: $(systemctl is-system-running)"
echo "== $DISTRO ($PKG), systemd $(systemctl --version | sed -n '1s/systemd \([0-9]*\).*/\1/p'), kernel $(uname -r)"
prepare_network

# A scenario that stops early is a failure, not a silent end of the run. The
# later ones depend on the state it leaves.
for scenario in scenario_install_starts scenario_agent_reaches_pcsc scenario_upgrade_restarts_when_idle \
	scenario_tunnel_under_hardened_unit scenario_upgrade_keeps_kill_switch \
	scenario_remove_after_crash_restarted scenario_remove_after_crash_dead \
	scenario_purge scenario_manual_unit_warns scenario_tarball; do
	if ! "$scenario"; then
		fail "$scenario stopped early; the rest did not run"
		break
	fi
done

echo
if [ "$failures" -eq 0 ]; then
	echo "== $DISTRO: ALL PASSED"
	exit 0
fi
echo "== $DISTRO: $failures FAILED"
exit 1
