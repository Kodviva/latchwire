package daemon

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/killswitch"
	"github.com/Kodviva/latchwire/internal/netcfg"
	"github.com/Kodviva/latchwire/internal/netmon"
)

// chanSource is a netmon.Source fed by the test: each string sent is one
// notification for that interface.
type chanSource chan string

func (s chanSource) Next(ctx context.Context) (string, error) {
	select {
	case n := <-s:
		return n, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// netEnv is a connected tunnel whose daemon watches notes.
func netEnv(t *testing.T) (*env, chanSource, *recCfg) {
	t.Helper()
	notes := make(chanSource)
	hook := func(m *Manager) {
		m.netSource = func() (netmon.Source, error) { return notes, nil }
	}
	e, _ := connected(t, envOpts{hook: hook})
	_, cfg := e.f.last()
	return e, notes, cfg
}

func (c *recCfg) refreshCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshes
}

func waitRefreshes(t *testing.T, c *recCfg, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.refreshCount() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d refreshes, want %d", c.refreshCount(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A network change refreshes every connected tunnel's configuration, without
// Manager.mu held (Refresh runs commands; status requests must not wait).
func TestNetworkChangeRefreshesConnectedTunnels(t *testing.T) {
	e, notes, cfg := netEnv(t)
	locked := make(chan bool, 1)
	cfg.mu.Lock()
	cfg.onRefresh = func() {
		done := make(chan struct{})
		go func() { e.m.matching(func(*tunnel) bool { return true }); close(done) }()
		select {
		case <-done:
			locked <- false
		case <-time.After(2 * time.Second):
			locked <- true
		}
	}
	cfg.mu.Unlock()
	notes <- "en0"
	waitRefreshes(t, cfg, 1)
	if <-locked {
		t.Fatal("Refresh ran with Manager.mu held")
	}
}

// Notifications about the tunnel's own interface are not network changes;
// a failing Refresh is logged and leaves the tunnel up.
func TestNetworkChangeIgnoresOwnInterfaceAndKeepsTunnelOnError(t *testing.T) {
	e, notes, cfg := netEnv(t)
	cfg.mu.Lock()
	own := cfg.iface
	cfg.refreshErr = errors.New("route: writing to routing socket: Network is unreachable")
	cfg.mu.Unlock()
	if own == "" {
		t.Fatal("configurer got no interface name")
	}
	notes <- own
	time.Sleep(200 * time.Millisecond)
	if n := cfg.refreshCount(); n != 0 {
		t.Fatalf("own interface caused %d refreshes", n)
	}
	notes <- "en0"
	waitRefreshes(t, cfg, 1)
	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q after a failed refresh, want connected", st.State)
	}
	cfg.mu.Lock()
	removed := cfg.removed
	cfg.mu.Unlock()
	if removed != 0 {
		t.Fatalf("configuration removed %d times after a failed refresh", removed)
	}
}

// A disconnected tunnel is not refreshed.
func TestNetworkChangeSkipsDisconnected(t *testing.T) {
	e, notes, cfg := netEnv(t)
	if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
	notes <- "en0"
	time.Sleep(200 * time.Millisecond)
	if n := cfg.refreshCount(); n != 0 {
		t.Fatalf("disconnected tunnel refreshed %d times", n)
	}
}

// macOS and Windows route full tunnels too, without a routing table or
// fwmark; Linux keeps its table.
func TestFullTunnelPlatforms(t *testing.T) {
	m := NewManager(Options{})
	if want := runtime.GOOS == "darwin" || runtime.GOOS == "linux" || runtime.GOOS == "windows"; m.fullTunnel != want {
		t.Errorf("fullTunnel = %v on %s, want %v", m.fullTunnel, runtime.GOOS, want)
	}
	if got, want := m.pickTable != nil, runtime.GOOS == "linux"; got != want {
		t.Errorf("pickTable set = %v on %s, want %v", got, runtime.GOOS, want)
	}
}

// A full tunnel without a routing table (macOS): no fwmark in the UAPI,
// none for the resolver, none in the plan. (The test configuration sets
// its MTU, so it is not automatic; see TestConnectAutoMTU.)
func TestFullTunnelWithoutTable(t *testing.T) {
	fe := newFullTunnelEnvTable(t, false)
	if st := fe.connect(); st.State != StateConnected {
		t.Fatalf("connect state %q, want connected", st.State)
	}
	tnet, cfg := fe.f.last()
	if err := get(tnet, 5*time.Second); err != nil {
		t.Fatalf("GET over the full tunnel: %v", err)
	}
	fe.mu.Lock()
	uapis, marks := fe.uapis, fe.marks
	fe.mu.Unlock()
	if len(uapis) != 1 || strings.Contains(uapis[0], "fwmark") {
		t.Fatalf("ipcSet %q, want one without fwmark", uapis)
	}
	if len(marks) != 1 || marks[0] != 0 {
		t.Errorf("resolver marks %v, want [0]", marks)
	}
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	if cfg.fwmark != 0 || len(cfg.routes) != 1 || cfg.routes[0].Bits() != 0 || cfg.mtuAuto {
		t.Errorf("plan FwMark %d routes %v MTUAuto %v, want 0, 0.0.0.0/0, false", cfg.fwmark, cfg.routes, cfg.mtuAuto)
	}
}

type failingSource struct{}

func (failingSource) Next(context.Context) (string, error) {
	return "", errors.New("route socket closed")
}

// When the notifications stop for good the daemon says so, and the
// periodic check goes on until the daemon stops.
func TestWatchNetworkLogsSourceFailure(t *testing.T) {
	logs := &syncBuffer{}
	log.SetOutput(logs)
	defer log.SetOutput(os.Stderr)
	m := NewManager(Options{VerifyEvery: time.Hour})
	m.netSource = func() (netmon.Source, error) { return failingSource{}, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.watchNetwork(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "network change notifications stopped") {
		if time.Now().After(deadline) {
			t.Fatalf("log %q does not report the stop", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("watchNetwork returned: the periodic check stopped with the notifications")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchNetwork did not return after ctx ended")
	}
}

// syncBuffer is a bytes.Buffer safe for the log's writes from other
// goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Without any network notification, the connected tunnels are refreshed
// every VerifyEvery (P12): a DHCP renewal that rewrote the DNS is noticed
// by the next tick (netcfg's Refresh puts the tunnel's DNS back, see
// TestDarwinDNSRefreshPrimaryServiceChange and TestDarwinDNSFightLogsOnce).
func TestVerifyTickRefreshesWithoutNetworkChange(t *testing.T) {
	e, _ := connected(t, envOpts{verifyEvery: 20 * time.Millisecond})
	_, cfg := e.f.last()
	waitRefreshes(t, cfg, 2)
	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q, want connected", st.State)
	}
}

// The verification tick retries what tunnels that went down left in the
// journal (whatever interface it names; the records of tunnels that are up
// and the kill switch's stay), and a DNSPrimary tunnel that got
// primary-busy meanwhile gets its DNS once netcfg lets it have it.
func TestVerifyTickRetriesLeftoversAndRetakesDNS(t *testing.T) {
	r := &cmdRunner{}
	e := newEnv(t, envOpts{present: []uint32{serialA}, verifyEvery: 20 * time.Millisecond, hook: func(m *Manager) { m.runner = r }})
	e.waitCard(serialA, true)
	e.f.mu.Lock()
	e.f.outcome = netcfg.DNSOutcomePrimaryBusy
	e.f.mu.Unlock()
	e.addTunnel("split", "10.1.0.0/16", "DNS = 10.1.0.53\n")
	e.mustConnect("split")
	if st := e.statusOf("split"); st.DNS != ipc.DNSStatusBusy {
		t.Fatalf("status %+v, want busy", st)
	}
	e.m.mu.Lock()
	j := e.m.journal
	e.m.mu.Unlock()
	left := netcfg.Step{Name: "ip", Args: []string{"rule", "del", "left", "over"}, Persistent: true}
	ks := netcfg.Step{Name: "nft", Args: []string{"delete", "table", "inet", "latchwire"}, Persistent: true}
	if err := j.Record("utun5", []netcfg.Step{left}); err != nil {
		t.Fatal(err)
	}
	if err := j.Record(killswitch.JournalOwner, []netcfg.Step{ks}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := j.Entries()["utun5"]; !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the leftover was not retried: journal %v", j.Entries())
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.mu.Lock()
	cmds := slices.Clone(r.cmds)
	r.mu.Unlock()
	if !slices.Contains(cmds, "ip rule del left over") || slices.Contains(cmds, "nft delete table inet latchwire") {
		t.Errorf("commands %q: want the leftover undone and the kill switch left alone", cmds)
	}
	if _, ok := j.Entries()[killswitch.JournalOwner]; !ok {
		t.Error("the kill switch's record went")
	}

	// The DNS undo the ownership waited for ran: the busy tunnel takes it.
	c := e.f.cfgFor("split")
	c.mu.Lock()
	c.outcome = ""
	c.mu.Unlock()
	deadline = time.Now().Add(5 * time.Second)
	for e.statusOf("split").DNS != ipc.DNSStatusPrimary {
		if time.Now().After(deadline) {
			t.Fatalf("still %+v", e.statusOf("split"))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if role, sets := e.roleOf("split"); role != netcfg.DNSPrimary || len(sets) == 0 || sets[len(sets)-1] != netcfg.DNSPrimary {
		t.Errorf("role %v, SetDNSRole %v", role, sets)
	}
}
