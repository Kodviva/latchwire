package killswitch

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/netcfg"
)

func wfpTestState() State {
	return State{Block: true, Tunnels: []TunnelRule{
		{Iface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820")}, ListenPort: 40000},
		{Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::9]:51820")}},
	}}
}

func mustFilters(t *testing.T, s State) []wfpFilter {
	t.Helper()
	fs, err := wfpFilters(s)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func filtersNamed(fs []wfpFilter, name string) []wfpFilter {
	var out []wfpFilter
	for _, f := range fs {
		if strings.HasPrefix(f.name, name) {
			out = append(out, f)
		}
	}
	return out
}

func TestWFPBlockAllPresentOnEveryLayer(t *testing.T) {
	for _, s := range []State{{Block: true}, wfpTestState()} {
		fs := mustFilters(t, s)
		var got []wfpLayer
		for _, f := range fs {
			if !f.permit {
				if len(f.conds) != 0 {
					t.Fatalf("a block filter with conditions: %+v", f)
				}
				got = append(got, f.layer)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, wfpLayers) {
			t.Fatalf("block filters on %v", got)
		}
		for _, l := range wfpLayers {
			if !slices.ContainsFunc(fs, func(f wfpFilter) bool {
				return f.layer == l && f.permit && len(f.conds) == 1 && f.conds[0].field == fieldLoopback
			}) {
				t.Fatalf("no loopback on layer %d", l)
			}
		}
	}
}

func TestWFPNoDNSRule(t *testing.T) {
	for _, f := range mustFilters(t, wfpTestState()) {
		for _, c := range f.conds {
			if (c.field == fieldRemotePort || c.field == fieldLocalPort) && c.value == 53 {
				t.Fatalf("DNS rule: %+v", f)
			}
		}
	}
}

func TestWFPTunnelInterfacePermitted(t *testing.T) {
	fs := filtersNamed(mustFilters(t, wfpTestState()), "tunnel ")
	if len(fs) != len(wfpLayers) {
		t.Fatalf("%+v", fs)
	}
	for _, f := range fs {
		if !f.permit || f.hard || len(f.conds) != 1 || f.conds[0].field != fieldInterface || f.conds[0].iface != "wg0" {
			t.Fatalf("%+v", f)
		}
	}
}

func TestWFPEndpointOutboundAndListenPort(t *testing.T) {
	fs := filtersNamed(mustFilters(t, wfpTestState()), "endpoint 198.51.100.7:51820")
	if len(fs) != 2 {
		t.Fatalf("%+v", fs)
	}
	out, in := fs[0], fs[1]
	if out.layer != layerConnect4 || in.layer != layerRecv4 || !out.hard || !in.hard {
		t.Fatalf("%+v", fs)
	}
	want := netip.MustParsePrefix("198.51.100.7/32")
	if !slices.ContainsFunc(out.conds, func(c wfpCond) bool { return c.field == fieldRemoteAddr && c.prefix == want }) ||
		!slices.ContainsFunc(out.conds, func(c wfpCond) bool { return c.field == fieldRemotePort && c.value == 51820 }) ||
		!slices.ContainsFunc(out.conds, func(c wfpCond) bool { return c.field == fieldProtocol && c.value == protoUDP }) {
		t.Fatalf("outbound: %+v", out)
	}
	if !slices.ContainsFunc(in.conds, func(c wfpCond) bool { return c.field == fieldLocalPort && c.value == 40000 }) {
		t.Fatalf("inbound is not limited to the listen port: %+v", in)
	}
}

func TestWFPConnectingTunnelOutboundOnly(t *testing.T) {
	fs := filtersNamed(mustFilters(t, wfpTestState()), "endpoint [2001:db8::9]:51820")
	if len(fs) != 1 || fs[0].layer != layerConnect6 {
		t.Fatalf("%+v", fs)
	}
}

func TestWFPDHCPScoped(t *testing.T) {
	fs := mustFilters(t, State{Block: true})
	out := filtersNamed(fs, "dhcp out")
	if len(out) != 1 || out[0].layer != layerConnect4 {
		t.Fatalf("%+v", out)
	}
	var nets []string
	for _, c := range out[0].conds {
		if c.field == fieldRemoteAddr {
			nets = append(nets, c.prefix.String())
		}
	}
	if !slices.Equal(nets, []string{"255.255.255.255/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}) {
		t.Fatalf("%v", nets)
	}
	v6 := filtersNamed(fs, "dhcpv6 out")
	if len(v6) != 1 || !slices.ContainsFunc(v6[0].conds, func(c wfpCond) bool {
		return c.field == fieldRemoteAddr && c.prefix == netip.MustParsePrefix("ff02::1:2/128")
	}) {
		t.Fatalf("%+v", v6)
	}
}

func TestWFPNDPScoped(t *testing.T) {
	fs := filtersNamed(mustFilters(t, State{Block: true}), "nd ")
	if len(fs) != 4 {
		t.Fatalf("%+v", fs)
	}
	for _, f := range fs {
		if f.layer != layerConnect6 && f.layer != layerRecv6 {
			t.Fatalf("%+v", f)
		}
		var types []uint16
		scoped := false
		for _, c := range f.conds {
			if c.field == fieldLocalPort {
				types = append(types, c.value)
			}
			scoped = scoped || c.field == fieldRemoteAddr || c.field == fieldLocalAddr
		}
		if !slices.Equal(types, []uint16{133, 134, 135, 136}) || !scoped {
			t.Fatalf("%+v", f)
		}
	}
}

func TestWFPMLD(t *testing.T) {
	fs := mustFilters(t, State{Block: true})
	if r := filtersNamed(fs, "mld reports"); len(r) != 1 || r[0].layer != layerConnect6 {
		t.Fatalf("%+v", r)
	}
	if q := filtersNamed(fs, "mld queries"); len(q) != 1 || q[0].layer != layerRecv6 {
		t.Fatalf("%+v", q)
	}
}

func TestWFPRejectsBadState(t *testing.T) {
	for _, s := range []State{
		{Block: true, Tunnels: []TunnelRule{{Iface: "bad name"}}},
		{Block: true, Tunnels: []TunnelRule{{Iface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[fe80::1%eth0]:1")}}}},
		{Block: true, Tunnels: []TunnelRule{{Iface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:0")}}}},
	} {
		if _, err := wfpFilters(s); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
}

type fakeEngine struct {
	calls    []string
	onApply  func() error
	applyErr error
	clearErr error
	n        int
	countErr error
}

func (e *fakeEngine) apply(fs []wfpFilter) error {
	e.calls = append(e.calls, "apply")
	if e.onApply != nil {
		if err := e.onApply(); err != nil {
			return err
		}
	}
	if e.applyErr != nil {
		return e.applyErr
	}
	e.n = len(fs)
	return nil
}

func (e *fakeEngine) clear() error {
	e.calls = append(e.calls, "clear")
	if e.clearErr != nil {
		return e.clearErr
	}
	e.n = 0
	return nil
}

func (e *fakeEngine) count() (int, error) { return e.n, e.countErr }

func wfpJournal(t *testing.T) *netcfg.Journal {
	t.Helper()
	j, err := netcfg.OpenJournal(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestSetJournalsBeforeApply(t *testing.T) {
	j := wfpJournal(t)
	e := &fakeEngine{}
	e.onApply = func() error {
		if len(j.Entries()[JournalOwner]) != 1 || j.Entries()[JournalOwner][0].Name != wfpClearCmd {
			t.Fatal("filters went in before the undo was journaled")
		}
		return nil
	}
	if err := newWFP(e, j).Set(context.Background(), wfpTestState()); err != nil {
		t.Fatal(err)
	}
	if !j.Entries()[JournalOwner][0].Persistent {
		t.Fatal("the undo must survive a failure")
	}
}

func TestSetFalseClears(t *testing.T) {
	j := wfpJournal(t)
	e := &fakeEngine{}
	f := newWFP(e, j)
	f.Set(context.Background(), wfpTestState())
	if err := f.Set(context.Background(), State{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.calls, []string{"apply", "clear"}) {
		t.Fatal(e.calls)
	}
	if len(j.Entries()) != 0 {
		t.Fatal("journal not forgotten")
	}
}

func TestFailedApplyKeepsJournal(t *testing.T) {
	j := wfpJournal(t)
	e := &fakeEngine{applyErr: errors.New("boom")}
	if err := newWFP(e, j).Set(context.Background(), wfpTestState()); err == nil {
		t.Fatal("no error")
	}
	if len(j.Entries()[JournalOwner]) != 1 {
		t.Fatal("an earlier Set's filters may still be there: the undo must stay")
	}
}

func TestFailedClearKeepsJournal(t *testing.T) {
	j := wfpJournal(t)
	e := &fakeEngine{}
	f := newWFP(e, j)
	f.Set(context.Background(), wfpTestState())
	e.clearErr = errors.New("boom")
	if err := f.Set(context.Background(), State{}); err == nil {
		t.Fatal("no error")
	}
	if len(j.Entries()[JournalOwner]) != 1 {
		t.Fatal("undo forgotten")
	}
}

func TestVerifyNoticesMissingFilters(t *testing.T) {
	e := &fakeEngine{}
	f := newWFP(e, nil)
	var _ Verifier = f
	f.Set(context.Background(), wfpTestState())
	if ok, err := f.Verify(context.Background()); !ok || err != nil {
		t.Fatal(ok, err)
	}
	e.n = 0 // the filtering engine restarted
	if ok, _ := f.Verify(context.Background()); ok {
		t.Fatal("missing filters not noticed")
	}
	e.countErr = errors.New("boom")
	if ok, err := f.Verify(context.Background()); ok || err == nil {
		t.Fatal(ok, err)
	}
}

func TestSetRejectsBadStateBeforeJournal(t *testing.T) {
	j := wfpJournal(t)
	e := &fakeEngine{}
	if err := newWFP(e, j).Set(context.Background(), State{Block: true, Tunnels: []TunnelRule{{Iface: "bad name"}}}); err == nil {
		t.Fatal("no error")
	}
	if len(e.calls) != 0 || len(j.Entries()) != 0 {
		t.Fatal("touched something")
	}
}
