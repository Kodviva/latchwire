package killswitch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/netcfg"
)

// recorder is a netcfg.Runner that records each command line and its stdin.
// missing makes every command fail as not installed; fail fails the ones
// whose line starts with it.
type recorder struct {
	cmds    []string
	stdin   []string
	missing bool
	fail    string
}

func (r *recorder) Run(_ context.Context, name string, args []string, in []byte) ([]byte, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	r.cmds = append(r.cmds, c)
	r.stdin = append(r.stdin, string(in))
	if r.missing {
		return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
	}
	if r.fail != "" && strings.HasPrefix(c, r.fail) {
		return nil, errors.New("exit status 1: Error: syntax error")
	}
	return nil, nil
}

func newJournal(t *testing.T) *netcfg.Journal {
	t.Helper()
	j, err := netcfg.OpenJournal(filepath.Join(t.TempDir(), "run", "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func blockState() State {
	return State{
		Block:  true,
		FwMark: 51820,
		Tunnels: []TunnelRule{
			{
				Iface: "wg0",
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("203.0.113.5:51820"),
					netip.MustParseAddrPort("[2001:db8::5]:51820"),
				},
				DNS: []netip.Addr{netip.MustParseAddr("10.64.0.1"), netip.MustParseAddr("fd00::1")},
			},
			{
				Iface:     "office",
				Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[::ffff:198.51.100.7]:4500")},
			},
		},
	}
}

const wantBlockScript = `table inet latchwire {}
delete table inet latchwire
table inet latchwire {
	chain output {
		type filter hook output priority filter; policy accept;
		oifname "lo" accept
		oifname "wg0" accept
		oifname "office" accept
		meta mark 51820 ct mark set meta mark accept
		meta nfproto ipv4 udp sport 68 udp dport 67 accept
		meta nfproto ipv6 udp sport 546 udp dport 547 accept
		icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
		ip daddr 10.64.0.1 meta l4proto { tcp, udp } th dport 53 accept
		ip6 daddr fd00::1 meta l4proto { tcp, udp } th dport 53 accept
		ip daddr 203.0.113.5 udp dport 51820 accept
		ip6 daddr 2001:db8::5 udp dport 51820 accept
		ip daddr 198.51.100.7 udp dport 4500 accept
		reject with icmpx type admin-prohibited
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "lo" accept
		iifname "wg0" accept
		iifname "office" accept
		ct mark 51820 ct state established,related accept
		meta nfproto ipv4 udp sport 67 udp dport 68 accept
		meta nfproto ipv6 udp sport 547 udp dport 546 accept
		icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
		ip saddr 10.64.0.1 meta l4proto { tcp, udp } th sport 53 ct state established accept
		ip6 saddr fd00::1 meta l4proto { tcp, udp } th sport 53 ct state established accept
		ip saddr 203.0.113.5 udp sport 51820 accept
		ct state related ct original ip daddr 203.0.113.5 accept
		ip6 saddr 2001:db8::5 udp sport 51820 accept
		ct state related ct original ip6 daddr 2001:db8::5 accept
		ip saddr 198.51.100.7 udp sport 4500 accept
		ct state related ct original ip daddr 198.51.100.7 accept
		drop
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		oifname "wg0" accept
		iifname "wg0" ct state established,related accept
		oifname "office" accept
		iifname "office" ct state established,related accept
		drop
	}
}
`

const wantRemoveScript = "table inet latchwire {}\ndelete table inet latchwire\n"

func TestNftRulesBlockState(t *testing.T) {
	got, err := nftScript(blockState())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantBlockScript {
		t.Fatalf("script:\n%s\nwant:\n%s", got, wantBlockScript)
	}
	// DNS passes only to the tunnels' servers: every rule naming port 53
	// names one of them.
	for line := range strings.Lines(string(got)) {
		if strings.Contains(line, " 53 ") && !strings.Contains(line, "10.64.0.1") && !strings.Contains(line, "fd00::1") {
			t.Errorf("DNS rule not limited to the tunnel servers: %q", line)
		}
	}

	// Without a mark (no full tunnel) no mark rule is written.
	s := blockState()
	s.FwMark = 0
	got, err = nftScript(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "mark") {
		t.Errorf("mark rule without FwMark:\n%s", got)
	}

	// Blocking with no tunnel (the interface is gone) still lets the link
	// come up and rejects everything else.
	got, err = nftScript(State{Block: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`oifname "lo" accept`, "udp sport 68 udp dport 67 accept", "reject with icmpx type admin-prohibited", "\t\tdrop\n"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("empty block state lacks %q:\n%s", want, got)
		}
	}
}

func TestNftScriptRejectsBadInput(t *testing.T) {
	for name, s := range map[string]State{
		"quote in iface":   {Block: true, Tunnels: []TunnelRule{{Iface: `wg0" accept`}}},
		"empty iface":      {Block: true, Tunnels: []TunnelRule{{Iface: ""}}},
		"long iface":       {Block: true, Tunnels: []TunnelRule{{Iface: "abcdefghijklmnop"}}},
		"invalid endpoint": {Block: true, Tunnels: []TunnelRule{{Iface: "wg0", Endpoints: []netip.AddrPort{{}}}}},
		"port 0":           {Block: true, Tunnels: []TunnelRule{{Iface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:0")}}}},
		"zoned endpoint":   {Block: true, Tunnels: []TunnelRule{{Iface: "wg0", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[fe80::1%eth0]:51820")}}}},
		"invalid dns":      {Block: true, Tunnels: []TunnelRule{{Iface: "wg0", DNS: []netip.Addr{{}}}}},
		"zoned dns":        {Block: true, Tunnels: []TunnelRule{{Iface: "wg0", DNS: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}}}},
	} {
		if _, err := nftScript(s); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestNftRemoveWhenNotBlocking(t *testing.T) {
	got, err := nftScript(State{Tunnels: blockState().Tunnels, FwMark: 51820})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantRemoveScript {
		t.Fatalf("script %q, want %q", got, wantRemoveScript)
	}

	r := &recorder{}
	j := newJournal(t)
	f, err := newNft(context.Background(), r, j)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	// The table's removal is journaled (persistent) before it is created.
	want := []netcfg.Step{{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(wantRemoveScript), Persistent: true}}
	if got := j.Entries()[JournalOwner]; !reflect.DeepEqual(got, want) {
		t.Fatalf("journal %+v, want %+v", got, want)
	}
	if err := f.Set(context.Background(), State{}); err != nil {
		t.Fatal(err)
	}
	wantCmds := []string{"nft --version", "nft -f -", "nft -f -"}
	if !reflect.DeepEqual(r.cmds, wantCmds) {
		t.Fatalf("commands %q, want %q", r.cmds, wantCmds)
	}
	if r.stdin[1] != wantBlockScript || r.stdin[2] != wantRemoveScript {
		t.Errorf("stdin %q", r.stdin)
	}
	if _, ok := j.Entries()[JournalOwner]; ok {
		t.Error("journal still holds the kill switch after its removal")
	}
}

// A failed nft run leaves the removal journaled: a table from an earlier
// Set may still be in place.
func TestNftFailureKeepsJournal(t *testing.T) {
	r := &recorder{}
	j := newJournal(t)
	f, err := newNft(context.Background(), r, j)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	r.fail = "nft -f -"
	if err := f.Set(context.Background(), blockState()); err == nil {
		t.Fatal("no error from a failing nft")
	}
	if err := f.Set(context.Background(), State{}); err == nil {
		t.Fatal("no error from a failing nft")
	}
	if _, ok := j.Entries()[JournalOwner]; !ok {
		t.Fatal("journal lost the kill switch after a failed removal")
	}
	// A bad state runs nothing.
	n := len(r.cmds)
	if err := f.Set(context.Background(), State{Block: true, Tunnels: []TunnelRule{{Iface: "a b"}}}); err == nil {
		t.Fatal("no error for a bad interface name")
	}
	if len(r.cmds) != n {
		t.Errorf("a bad state ran %q", r.cmds[n:])
	}
}

// The journaled removal is what netcfg.Cleanup runs after a crash.
func TestNftJournalCleanup(t *testing.T) {
	r := &recorder{}
	j := newJournal(t)
	f, err := newNft(context.Background(), r, j)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	r.cmds, r.stdin = nil, nil
	if err := netcfg.Cleanup(context.Background(), r, j, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.cmds) != 1 || r.cmds[0] != "nft -f -" || r.stdin[0] != wantRemoveScript {
		t.Fatalf("cleanup ran %q %q", r.cmds, r.stdin)
	}
}

func TestNftUnsupported(t *testing.T) {
	r := &recorder{missing: true}
	if _, err := newNft(context.Background(), r, newJournal(t)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("newNft without nft: %v, want ErrUnsupported", err)
	}
	// nft removed after New: Set reports the same.
	r.missing = false
	f, err := newNft(context.Background(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.missing = true
	if err := f.Set(context.Background(), blockState()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Set without nft: %v, want ErrUnsupported", err)
	}
}
