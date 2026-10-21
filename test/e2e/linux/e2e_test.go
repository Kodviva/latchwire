//go:build e2e && linux

// Package e2e is Latchwire's Linux end-to-end test. It changes real network
// state (namespaces, veth pairs, routes, rules, nftables, resolv.conf), so it
// runs only inside a privileged, throw-away container through run.sh, which
// sets LATCHWIRE_E2E=1. Everything happens in the container's own network
// namespaces; the daemon runs in the client namespace "lwc".
//
// Topology:
//
//	lwc (client)            lwr (router, "internet")          lws (server)
//	c0 10.77.0.2/24  ---  r0 10.77.0.1/24                 s0 10.88.0.2/24
//	default via .1        r1 10.88.0.1/24  -------------  default via .1
//	latchwire daemon      inet0 203.0.113.1/32            wgs 10.66.0.1/24,
//	                      10.66.0.0/16 via 10.88.0.2          10.66.1.1/24
//	                                                      testserver :51820
//	                                                      DNS on :53
//
// 203.0.113.1 is the "outside" host: reachable directly from lwc, or through
// the tunnel (server forwards) when the full tunnel is up.
//
// The key comes from testagent (software keys, card present while a file
// exists): the production CLI never links a software key. Two agents run:
// root's, and one of the unprivileged user lwuser (uid 1500) for the
// allowed-users scenario. The scenarios run in order and share state; after
// a failure the rest are skipped.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

const (
	serial    = 4242
	outside   = "203.0.113.1"
	gateway   = "10.77.0.1"
	inTunnel  = "10.66.0.1"
	inMulti   = "10.66.1.1"
	tunnelDNS = "10.66.0.1"
	probeName = "probe.e2e.test"
	probeAddr = "10.66.0.42"
	userName  = "lwuser" // unprivileged test user with its own agent
	userUID   = "1500"
)

var (
	work    string // scratch directory (keys, configs, logs)
	bin     string // directory with latchwire, testagent, testserver
	card    string // the simulated card is present while this file exists
	daemonP *exec.Cmd
	bg      []*exec.Cmd // server and agent, stopped at the end
)

func TestMain(m *testing.M) {
	if reason := refuse(); reason != "" {
		fmt.Fprintln(os.Stderr, "e2e: refusing to run:", reason)
		os.Exit(1)
	}
	work = os.Getenv("LATCHWIRE_E2E_WORK")
	bin = filepath.Join(work, "bin")
	card = filepath.Join(work, "card")
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: setup:", err)
		dumpLogs()
		os.Exit(1)
	}
	code := m.Run()
	if code != 0 {
		dumpLogs()
	}
	stopDaemon()
	for _, c := range bg {
		c.Process.Signal(syscall.SIGTERM)
		c.Wait()
	}
	os.Exit(code)
}

// refuse returns why this process must not change network state, or "".
func refuse() string {
	if os.Getenv("LATCHWIRE_E2E") != "1" || os.Getenv("LATCHWIRE_E2E_WORK") == "" {
		return "LATCHWIRE_E2E=1 and LATCHWIRE_E2E_WORK are set only by test/e2e/linux/run.sh"
	}
	if os.Geteuid() != 0 {
		return "not root"
	}
	if !inContainer() {
		return "not inside a container"
	}
	return ""
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	return false
}

// ---- setup ----

type keyPair struct{ priv, pub string }

func newKey(path string) (keyPair, error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return keyPair{}, err
	}
	sk[0] &= 248
	sk[31] = sk[31]&127 | 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return keyPair{}, err
	}
	kp := keyPair{base64.StdEncoding.EncodeToString(sk[:]), base64.StdEncoding.EncodeToString(pk)}
	return kp, os.WriteFile(path, []byte(kp.priv+"\n"), 0o600)
}

func setup() error {
	keys := filepath.Join(work, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		return err
	}
	ka, err := newKey(filepath.Join(keys, "82.key"))
	if err != nil {
		return err
	}
	kb, err := newKey(filepath.Join(keys, "83.key"))
	if err != nil {
		return err
	}
	ks, err := newKey(filepath.Join(work, "server.key"))
	if err != nil {
		return err
	}

	for _, c := range [][]string{
		{"netns", "add", "lwc"}, {"netns", "add", "lwr"}, {"netns", "add", "lws"},
		{"link", "add", "name", "c0", "netns", "lwc", "type", "veth", "peer", "name", "r0", "netns", "lwr"},
		{"link", "add", "name", "r1", "netns", "lwr", "type", "veth", "peer", "name", "s0", "netns", "lws"},
		{"-n", "lwc", "link", "set", "lo", "up"},
		{"-n", "lwc", "addr", "add", "10.77.0.2/24", "dev", "c0"},
		{"-n", "lwc", "link", "set", "c0", "up"},
		{"-n", "lwc", "route", "add", "default", "via", gateway},
		{"-n", "lwr", "link", "set", "lo", "up"},
		{"-n", "lwr", "addr", "add", "10.77.0.1/24", "dev", "r0"},
		{"-n", "lwr", "addr", "add", "10.88.0.1/24", "dev", "r1"},
		{"-n", "lwr", "link", "set", "r0", "up"},
		{"-n", "lwr", "link", "set", "r1", "up"},
		{"-n", "lwr", "link", "add", "inet0", "type", "dummy"},
		{"-n", "lwr", "addr", "add", outside + "/32", "dev", "inet0"},
		{"-n", "lwr", "link", "set", "inet0", "up"},
		{"-n", "lwr", "route", "add", "10.66.0.0/16", "via", "10.88.0.2"},
		{"-n", "lws", "link", "set", "lo", "up"},
		{"-n", "lws", "addr", "add", "10.88.0.2/24", "dev", "s0"},
		{"-n", "lws", "link", "set", "s0", "up"},
		{"-n", "lws", "route", "add", "default", "via", "10.88.0.1"},
	} {
		if _, err := run("ip", c...); err != nil {
			return err
		}
	}
	for _, ns := range []string{"lwr", "lws"} {
		if _, err := run("ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv4.ip_forward=1"); err != nil {
			return err
		}
	}

	// The WireGuard server, with a software key (test binary only).
	srv, err := startBG("server", "ip", "netns", "exec", "lws", filepath.Join(bin, "testserver"),
		"-iface", "wgs", "-key", filepath.Join(work, "server.key"), "-port", "51820",
		"-peer", ka.pub+"@10.66.0.2/32", "-peer", kb.pub+"@10.66.1.2/32",
		"-dns", "0.0.0.0:53", "-answer", probeName+"="+probeAddr)
	if err != nil {
		return err
	}
	bg = append(bg, srv)
	if err := waitFor(10*time.Second, func() bool {
		_, err := run("ip", "-n", "lws", "link", "show", "wgs")
		return err == nil
	}); err != nil {
		return fmt.Errorf("server interface: %w", err)
	}
	for _, c := range [][]string{
		{"-n", "lws", "addr", "add", "10.66.0.1/24", "dev", "wgs"},
		{"-n", "lws", "addr", "add", "10.66.1.1/24", "dev", "wgs"},
		{"-n", "lws", "link", "set", "wgs", "up"},
	} {
		if _, err := run("ip", c...); err != nil {
			return err
		}
	}

	// Tunnel configurations. lwsplit and lwfull share identity 82 (never up
	// together); lwmulti uses 83 on the same card.
	confs := map[string]string{
		"lwsplit": tunnelConf("82", ka.pub, "10.66.0.2/32", "DNS = "+tunnelDNS, ks.pub, "10.66.0.0/24"),
		"lwfull":  tunnelConf("82", ka.pub, "10.66.0.2/32", "DNS = "+tunnelDNS, ks.pub, "0.0.0.0/0"),
		"lwmulti": tunnelConf("83", kb.pub, "10.66.1.2/32", "", ks.pub, "10.66.1.0/24"),
	}
	for name, text := range confs {
		if err := os.WriteFile(filepath.Join(work, name+".conf"), []byte(text), 0o600); err != nil {
			return err
		}
	}

	if err := os.WriteFile(card, nil, 0o600); err != nil {
		return err
	}
	if err := startDaemon(); err != nil {
		return err
	}
	ag, err := startBG("agent", filepath.Join(bin, "testagent"), "-serial", strconv.Itoa(serial),
		"-card", card, "-keys", keys, "-poll", "200ms")
	if err != nil {
		return err
	}
	bg = append(bg, ag)

	// A second, unprivileged user with an agent for the same card.
	if _, err := run("useradd", "-M", "-u", userUID, "-s", "/usr/sbin/nologin", userName); err != nil {
		return err
	}
	ukeys := filepath.Join(work, "userkeys")
	if _, err := run("cp", "-r", keys, ukeys); err != nil {
		return err
	}
	if _, err := run("chown", "-R", userUID+":"+userUID, ukeys); err != nil {
		return err
	}
	uag, err := startBG("useragent", "setpriv", "--reuid="+userUID, "--regid="+userUID, "--clear-groups",
		filepath.Join(bin, "testagent"), "-serial", strconv.Itoa(serial), "-card", card, "-keys", ukeys, "-poll", "200ms")
	if err != nil {
		return err
	}
	bg = append(bg, uag)
	for name := range confs {
		if _, err := run(filepath.Join(bin, "latchwire"), "add", name, filepath.Join(work, name+".conf")); err != nil {
			return err
		}
	}
	return nil
}

func tunnelConf(slot string, pub, addr, dnsLine, serverPub, allowed string) string {
	return fmt.Sprintf(`[Interface]
KeyRef = piv://%d/%s
PublicKey = %s
Address = %s
%s

[Peer]
PublicKey = %s
Endpoint = 10.88.0.2:51820
AllowedIPs = %s
PersistentKeepalive = 5
`, serial, slot, pub, addr, dnsLine, serverPub, allowed)
}

// ---- processes ----

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func startBG(logName, name string, args ...string) (*exec.Cmd, error) {
	f, err := os.OpenFile(filepath.Join(work, logName+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = f, f
	if err := c.Start(); err != nil {
		f.Close()
		return nil, err
	}
	return c, nil
}

// startDaemon runs the production daemon in the client namespace and waits
// until it answers. "ip netns exec" execs the daemon, so the PID is the
// daemon's.
func startDaemon() error {
	c, err := startBG("daemon", "ip", "netns", "exec", "lwc", filepath.Join(bin, "latchwire"), "daemon")
	if err != nil {
		return err
	}
	daemonP = c
	return waitFor(15*time.Second, func() bool {
		_, err := run(filepath.Join(bin, "latchwire"), "status")
		return err == nil
	})
}

func killDaemon(t *testing.T) {
	t.Helper()
	if err := daemonP.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill -9 daemon: %v", err)
	}
	daemonP.Wait()
	daemonP = nil
}

func stopDaemon() {
	if daemonP == nil {
		return
	}
	daemonP.Process.Signal(syscall.SIGTERM)
	daemonP.Wait()
	daemonP = nil
}

func dumpLogs() {
	for _, n := range []string{"daemon", "agent", "useragent", "server"} {
		b, err := os.ReadFile(filepath.Join(work, n+".log"))
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "----- %s.log -----\n%s\n", n, b)
	}
}

func waitFor(d time.Duration, ok func() bool) error {
	end := time.Now().Add(d)
	for {
		if ok() {
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("not reached within %s", d)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- probes ----

func lw(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run(filepath.Join(bin, "latchwire"), args...)
	if err != nil {
		t.Fatalf("latchwire: %v", err)
	}
	return out
}

func status(t *testing.T, name string) ipc.TunnelStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := ipc.Dial(daemon.DefaultSocket)
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer c.Close()
	go c.Serve(ctx)
	var sts []ipc.TunnelStatus
	if err := c.Call(ctx, ipc.MethodTunnelStatus, ipc.TunnelName{Name: name}, &sts); err != nil {
		t.Fatalf("tunnel.status %s: %v", name, err)
	}
	for _, st := range sts {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("tunnel.status: no %s in %+v", name, sts)
	return ipc.TunnelStatus{}
}

func waitState(t *testing.T, name, state, ks string) ipc.TunnelStatus {
	t.Helper()
	var st ipc.TunnelStatus
	if err := waitFor(15*time.Second, func() bool {
		st = status(t, name)
		return st.State == state && (ks == "" || st.KillSwitch == ks)
	}); err != nil {
		t.Fatalf("%s: want state %s kill switch %q, have %+v", name, state, ks, st)
	}
	return st
}

// ping reports whether lwc reaches addr (one echo, 1 s).
func ping(addr string) bool {
	_, err := run("ip", "netns", "exec", "lwc", "ping", "-n", "-q", "-c", "1", "-W", "1", addr)
	return err == nil
}

// reach waits until addr answers from lwc.
func reach(t *testing.T, addr string) {
	t.Helper()
	if err := waitFor(15*time.Second, func() bool { return ping(addr) }); err != nil {
		t.Fatalf("ping %s from lwc: %v", addr, err)
	}
}

// blocked checks that addr does not answer from lwc, three times.
func blocked(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 3; i++ {
		if ping(addr) {
			t.Fatalf("ping %s from lwc passed, want it blocked", addr)
		}
	}
}

var devRE = regexp.MustCompile(`\bdev (\S+)`)

// routeDev is the interface lwc's kernel picks for addr.
func routeDev(t *testing.T, addr string, extra ...string) string {
	t.Helper()
	out, err := run("ip", append([]string{"-n", "lwc", "route", "get", addr}, extra...)...)
	if err != nil {
		t.Fatalf("route get: %v", err)
	}
	m := devRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("route get %s: no dev in %q", addr, out)
	}
	return m[1]
}

func txPackets(t *testing.T, iface string) uint64 {
	t.Helper()
	out, err := run("ip", "netns", "exec", "lwc", "cat", "/sys/class/net/"+iface+"/statistics/tx_packets")
	if err != nil {
		t.Fatalf("tx_packets %s: %v", iface, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	if err != nil {
		t.Fatalf("tx_packets %s: %v", iface, err)
	}
	return n
}

// viaTunnel pings addr and checks that the packets left through iface.
func viaTunnel(t *testing.T, addr, iface string) {
	t.Helper()
	if dev := routeDev(t, addr); dev != iface {
		t.Fatalf("route to %s uses %s, want %s", addr, dev, iface)
	}
	before := txPackets(t, iface)
	reach(t, addr)
	if after := txPackets(t, iface); after <= before {
		t.Fatalf("ping %s answered but %s sent nothing (tx %d -> %d)", addr, iface, before, after)
	}
}

func linkExists(iface string) bool {
	_, err := run("ip", "-n", "lwc", "link", "show", "dev", iface)
	return err == nil
}

func nftTable() bool {
	_, err := run("ip", "netns", "exec", "lwc", "nft", "list", "table", "inet", "latchwire")
	return err == nil
}

func ipRules(t *testing.T) string {
	t.Helper()
	out, err := run("ip", "-n", "lwc", "-4", "rule", "show")
	if err != nil {
		t.Fatalf("ip rule: %v", err)
	}
	return out
}

// ourRules are the full tunnel's policy rules: anything but the three
// default rules.
func ourRules(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(ipRules(t)), "\n") {
		switch {
		case l == "", strings.HasPrefix(l, "0:\tfrom all lookup local"),
			strings.HasPrefix(l, "32766:\tfrom all lookup main"),
			strings.HasPrefix(l, "32767:\tfrom all lookup default"):
			continue
		}
		out = append(out, l)
	}
	return out
}

func resolvConf(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func nameservers(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(resolvConf(t), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// resolve looks the probe name up from lwc through the system resolver.
func resolve() (string, error) {
	out, err := run("ip", "netns", "exec", "lwc", "timeout", "10", "getent", "ahostsv4", probeName)
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return "", fmt.Errorf("getent: empty answer")
	}
	return f[0], nil
}

func journalOwners(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(netcfg.DefaultJournalPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var j struct {
		Owners map[string]json.RawMessage `json:"owners"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatalf("journal: %v", err)
	}
	var out []string
	for o := range j.Owners {
		out = append(out, o)
	}
	return out
}

// assertClean checks that no tunnel left anything behind in lwc.
func assertClean(t *testing.T) {
	t.Helper()
	for _, n := range []string{"lwsplit", "lwfull", "lwmulti"} {
		if linkExists(n) {
			t.Errorf("interface %s still exists", n)
		}
	}
	if r := ourRules(t); len(r) > 0 {
		t.Errorf("policy rules left: %q", r)
	}
	if nftTable() {
		t.Errorf("nft table inet latchwire still present")
	}
	for _, ns := range nameservers(t) {
		if ns == tunnelDNS {
			t.Errorf("resolv.conf still lists the tunnel's DNS:\n%s", resolvConf(t))
		}
	}
	if o := journalOwners(t); len(o) > 0 {
		t.Errorf("journal still has owners %q", o)
	}
	if dev := routeDev(t, outside); dev != "c0" {
		t.Errorf("route to %s uses %s, want c0", outside, dev)
	}
	reach(t, outside)
}

func setCard(t *testing.T, present bool) {
	t.Helper()
	var err error
	if present {
		err = os.WriteFile(card, nil, 0o600)
	} else {
		err = os.Remove(card)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// ---- scenarios ----

func TestLinuxNetworkParity(t *testing.T) {
	steps := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"baseline", func(t *testing.T) { assertClean(t) }},
		{"split_tunnel", testSplit},
		{"dns_resolvconf", testDNS},
		{"full_tunnel", testFull},
		{"kill_switch_card_removed", testKillSwitchCard},
		{"daemon_kill9_restart", testCrash},
		{"daemon_sigterm_releases", testShutdown},
		{"multi_tunnel", testMulti},
		{"allowed_users", testAllowedUsers},
		{"on_demand", testOnDemand},
	}
	failed := false
	for _, s := range steps {
		if failed {
			t.Run(s.name, func(t *testing.T) { t.Skip("SKIP: an earlier scenario failed; state unknown") })
			continue
		}
		if !t.Run(s.name, s.fn) {
			failed = true
		}
	}
}

func testSplit(t *testing.T) {
	lw(t, "up", "lwsplit")
	st := waitState(t, "lwsplit", daemon.StateConnected, ipc.KillSwitchStatusOff)
	if st.FullTunnel || st.Interface != "lwsplit" {
		t.Fatalf("status %+v", st)
	}
	viaTunnel(t, inTunnel, "lwsplit")
	// Outside the AllowedIPs: the physical interface, not the tunnel.
	if dev := routeDev(t, outside); dev != "c0" {
		t.Fatalf("split tunnel: route to %s uses %s", outside, dev)
	}
	reach(t, outside)
	if r := ourRules(t); len(r) > 0 {
		t.Fatalf("split tunnel added policy rules %q", r)
	}
	if nftTable() {
		t.Fatalf("split tunnel (kill switch auto = off) created the nft table")
	}
	if st := status(t, "lwsplit"); st.LastHandshake == "" {
		t.Fatalf("no handshake reported: %+v", st)
	}
	// Left up for the DNS scenario.
}

func testDNS(t *testing.T) {
	st := status(t, "lwsplit")
	if st.State != daemon.StateConnected {
		t.Fatalf("split tunnel not connected: %+v", st)
	}
	if st.DNS != ipc.DNSStatusPrimary {
		t.Fatalf("DNS status %q, want %q (openresolv, exclusive)", st.DNS, ipc.DNSStatusPrimary)
	}
	if ns := nameservers(t); len(ns) != 1 || ns[0] != tunnelDNS {
		t.Fatalf("resolv.conf nameservers %q, want only %s:\n%s", ns, tunnelDNS, resolvConf(t))
	}
	addr, err := resolve()
	if err != nil || addr != probeAddr {
		t.Fatalf("resolve %s through the tunnel: %q, %v", probeName, addr, err)
	}
	lw(t, "down", "lwsplit")
	waitState(t, "lwsplit", daemon.StateDisconnected, "")
	if ns := nameservers(t); len(ns) != 1 || ns[0] != gateway {
		t.Fatalf("after down: nameservers %q, want the original %s:\n%s", ns, gateway, resolvConf(t))
	}
	if _, err := resolve(); err == nil {
		t.Fatalf("after down %s still resolves (the original server %s has no DNS)", probeName, gateway)
	}
	assertClean(t)
}

func testFull(t *testing.T) {
	lw(t, "up", "lwfull")
	st := waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	if !st.FullTunnel {
		t.Fatalf("status %+v: not a full tunnel", st)
	}
	// Everything goes through the tunnel ...
	viaTunnel(t, outside, "lwfull")
	// ... except the local subnet (main table, suppress_prefixlength 0),
	// which the armed kill switch blocks: only tunnel traffic passes ...
	if dev := routeDev(t, gateway); dev != "c0" {
		t.Fatalf("local subnet routed via %s, want c0", dev)
	}
	blocked(t, gateway)
	// ... and the device's own (fwmark) traffic to the endpoint.
	mark := "51820"
	if dev := routeDev(t, "10.88.0.2", "mark", mark); dev != "c0" {
		t.Fatalf("endpoint with fwmark %s routed via %s, want c0", mark, dev)
	}
	rules := strings.Join(ourRules(t), "\n")
	if !strings.Contains(rules, "lookup "+mark) || !strings.Contains(rules, "suppress_prefixlength 0") {
		t.Fatalf("full tunnel rules missing:\n%s", rules)
	}
	if !nftTable() {
		t.Fatalf("kill switch armed but no nft table")
	}
	if st.DNS != ipc.DNSStatusPrimary {
		t.Fatalf("DNS status %q", st.DNS)
	}
	if addr, err := resolve(); err != nil || addr != probeAddr {
		t.Fatalf("resolve through full tunnel: %q, %v", addr, err)
	}
	lw(t, "down", "lwfull")
	waitState(t, "lwfull", daemon.StateDisconnected, ipc.KillSwitchStatusOff)
	assertClean(t)
}

func testKillSwitchCard(t *testing.T) {
	lw(t, "up", "lwfull")
	waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	viaTunnel(t, outside, "lwfull")

	setCard(t, false)
	waitState(t, "lwfull", daemon.StateCardRemoved, ipc.KillSwitchStatusBlocking)
	if linkExists("lwfull") {
		t.Fatalf("card removed but the tunnel interface is still there")
	}
	// The routes point at the physical interface again: only the kill
	// switch stops the leak.
	if dev := routeDev(t, outside); dev != "c0" {
		t.Fatalf("card removed: route to %s uses %s, want c0", outside, dev)
	}
	if !nftTable() {
		t.Fatalf("card removed: no nft table")
	}
	blocked(t, outside)
	blocked(t, gateway)
	if _, err := resolve(); err == nil {
		t.Fatalf("names resolve while the kill switch blocks")
	}

	// The card comes back: the tunnel reconnects, traffic flows again.
	setCard(t, true)
	waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	viaTunnel(t, outside, "lwfull")

	// Pulled again, then taken down: down lifts the block.
	setCard(t, false)
	waitState(t, "lwfull", daemon.StateCardRemoved, ipc.KillSwitchStatusBlocking)
	blocked(t, outside)
	lw(t, "down", "lwfull")
	waitState(t, "lwfull", daemon.StateDisconnected, ipc.KillSwitchStatusOff)
	assertClean(t)
	setCard(t, true)
	time.Sleep(time.Second)
	if st := status(t, "lwfull"); st.State != daemon.StateDisconnected {
		t.Fatalf("after down, the card's return reconnected the tunnel: %+v", st)
	}
}

func testCrash(t *testing.T) {
	lw(t, "up", "lwfull")
	waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	viaTunnel(t, outside, "lwfull")

	killDaemon(t)
	// Fail closed while no daemon runs: the rules stay, nothing passes.
	if !nftTable() {
		t.Fatalf("kill -9: the nft table is gone")
	}
	if dev := routeDev(t, outside); dev != "c0" {
		t.Fatalf("kill -9: route to %s uses %s, want c0 (the device died with the process)", outside, dev)
	}
	blocked(t, outside)
	leftRules := ourRules(t)
	leftDNS := slices.Contains(nameservers(t), tunnelDNS)
	t.Logf("left behind by the crash: rules %q, tunnel DNS in resolv.conf %v", leftRules, leftDNS)

	// Restart without the card, so the restored tunnel stays card_removed.
	setCard(t, false)
	if err := startDaemon(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	waitState(t, "lwfull", daemon.StateCardRemoved, ipc.KillSwitchStatusBlocking)
	if r := ourRules(t); len(r) > 0 {
		t.Fatalf("after restart: policy rules not cleaned: %q", r)
	}
	if slices.Contains(nameservers(t), tunnelDNS) {
		t.Fatalf("after restart: tunnel DNS not cleaned:\n%s", resolvConf(t))
	}
	if out, _ := run("ip", "-n", "lwc", "route", "show", "table", "51820"); strings.TrimSpace(out) != "" &&
		!strings.Contains(out, "does not exist") {
		t.Fatalf("after restart: table 51820 not empty: %q", out)
	}
	if !nftTable() {
		t.Fatalf("after restart: the kill switch was lifted")
	}
	blocked(t, outside)

	// The card returns: the restored tunnel reconnects (P17).
	setCard(t, true)
	waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	viaTunnel(t, outside, "lwfull")
	lw(t, "down", "lwfull")
	waitState(t, "lwfull", daemon.StateDisconnected, ipc.KillSwitchStatusOff)
	assertClean(t)
}

func testMulti(t *testing.T) {
	lw(t, "up", "lwfull")
	waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	lw(t, "up", "lwmulti")
	waitState(t, "lwmulti", daemon.StateConnected, "")
	viaTunnel(t, inMulti, "lwmulti")
	viaTunnel(t, outside, "lwfull")
	lw(t, "down", "lwmulti")
	waitState(t, "lwmulti", daemon.StateDisconnected, "")
	viaTunnel(t, outside, "lwfull")
	lw(t, "down", "lwfull")
	waitState(t, "lwfull", daemon.StateDisconnected, ipc.KillSwitchStatusOff)
	assertClean(t)
}

func testOnDemand(t *testing.T) {
	id := strings.TrimSpace(lw(t, "network"))
	t.Logf("network: %s", id)
	lw(t, "policy", "lwsplit", "--on-demand=true")
	// Untrusted network: on-demand connects without anyone running up.
	waitStateLong(t, "lwsplit", daemon.StateConnected, 45*time.Second)
	viaTunnel(t, inTunnel, "lwsplit")
	// Trusting this network takes it down at the next evaluation (a
	// network change or the 30 s check).
	lw(t, "policy", "lwsplit", "--trust-current-network")
	waitStateLong(t, "lwsplit", daemon.StateDisconnected, 45*time.Second)
	lw(t, "policy", "lwsplit", "--on-demand=false")
	assertClean(t)
}

func testShutdown(t *testing.T) {
	lw(t, "up", "lwfull")
	waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	setCard(t, false)
	waitState(t, "lwfull", daemon.StateCardRemoved, ipc.KillSwitchStatusBlocking)
	blocked(t, outside)
	// A clean stop of the service lifts the kill switch and undoes
	// everything (fail-closed covers crashes, not an orderly stop).
	stopDaemon()
	if nftTable() {
		t.Fatalf("SIGTERM: the nft table is still there")
	}
	if r := ourRules(t); len(r) > 0 {
		t.Fatalf("SIGTERM: policy rules left: %q", r)
	}
	reach(t, outside)
	setCard(t, true)
	if err := startDaemon(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	// Nothing is restored after an orderly stop.
	time.Sleep(time.Second)
	if st := status(t, "lwfull"); st.State != daemon.StateDisconnected || st.KillSwitch == ipc.KillSwitchStatusBlocking {
		t.Fatalf("after SIGTERM and restart: %+v", st)
	}
	assertClean(t)
}

// asUser runs the CLI as the unprivileged test user.
func asUser(args ...string) (string, error) {
	return run("setpriv", append([]string{"--reuid=" + userUID, "--regid=" + userUID, "--clear-groups",
		filepath.Join(bin, "latchwire")}, args...)...)
}

func testAllowedUsers(t *testing.T) {
	// lwuser is not an administrator and not an allowed user: refused
	// before any key operation.
	if out, err := asUser("up", "lwsplit"); err == nil || !strings.Contains(out, "not one of the allowed users") {
		t.Fatalf("non-allowed user up: err %v, output %q", err, out)
	}
	if st := status(t, "lwsplit"); st.State != daemon.StateDisconnected {
		t.Fatalf("refused up changed the tunnel: %+v", st)
	}
	lw(t, "policy", "lwsplit", "--allow-user", userName)
	if out, err := asUser("up", "lwsplit"); err != nil {
		t.Fatalf("allowed user up: %v %s", err, out)
	}
	waitState(t, "lwsplit", daemon.StateConnected, "")
	viaTunnel(t, inTunnel, "lwsplit")
	// Deny revokes the running binding (P20): an unarmed tunnel goes down.
	lw(t, "policy", "lwsplit", "--deny-user", userName)
	waitState(t, "lwsplit", daemon.StateDisconnected, ipc.KillSwitchStatusOff)

	// An armed tunnel taken from a denied user keeps blocking, unbound,
	// until an administrator takes it down (P21).
	lw(t, "policy", "lwfull", "--allow-user", userName)
	if out, err := asUser("up", "lwfull"); err != nil {
		t.Fatalf("allowed user up lwfull: %v %s", err, out)
	}
	waitState(t, "lwfull", daemon.StateConnected, ipc.KillSwitchStatusArmed)
	viaTunnel(t, outside, "lwfull")
	out := lw(t, "policy", "lwfull", "--deny-user", userName)
	if !strings.Contains(out, "stays blocked by its kill switch") {
		t.Fatalf("deny of an armed tunnel's user printed no kill switch note: %q", out)
	}
	waitState(t, "lwfull", daemon.StateCardRemoved, ipc.KillSwitchStatusBlocking)
	blocked(t, outside)
	if out, err := asUser("down", "lwfull"); err == nil {
		if st := status(t, "lwfull"); st.KillSwitch != ipc.KillSwitchStatusBlocking {
			t.Fatalf("the denied user lifted the kill switch: %q %+v", out, st)
		}
	}
	blocked(t, outside)
	lw(t, "down", "lwfull")
	waitState(t, "lwfull", daemon.StateDisconnected, ipc.KillSwitchStatusOff)
	assertClean(t)
}

func waitStateLong(t *testing.T, name, state string, d time.Duration) {
	t.Helper()
	var st ipc.TunnelStatus
	if err := waitFor(d, func() bool {
		st = status(t, name)
		return st.State == state
	}); err != nil {
		t.Fatalf("%s: want state %s within %s, have %+v", name, state, d, st)
	}
}
