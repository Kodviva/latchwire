package killswitch

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

// pfRecorder is a netcfg.Runner and netcfg.CombinedRunner that records each
// command line and its stdin and answers with out[line] (default: nothing).
// errs[line] fails that line; missing fails every command as not installed.
type pfRecorder struct {
	cmds     []string
	stdin    []string
	combined []bool
	out      map[string]string
	errs     map[string]error
	missing  bool
}

func newPfRecorder() *pfRecorder {
	return &pfRecorder{
		out: map[string]string{
			"pfctl -sr": appleRuleset,
			"pfctl -E":  "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 18446742523466346583\n",
		},
		errs: map[string]error{},
	}
}

func (r *pfRecorder) run(name string, args []string, in []byte, combined bool) ([]byte, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	r.cmds = append(r.cmds, c)
	r.stdin = append(r.stdin, string(in))
	r.combined = append(r.combined, combined)
	if r.missing {
		return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
	}
	if err := r.errs[c]; err != nil {
		return nil, err
	}
	return []byte(r.out[c]), nil
}

func (r *pfRecorder) Run(_ context.Context, name string, args []string, in []byte) ([]byte, error) {
	return r.run(name, args, in, false)
}

func (r *pfRecorder) RunCombined(_ context.Context, name string, args []string, in []byte) ([]byte, error) {
	return r.run(name, args, in, true)
}

// appleRuleset is pfctl -sr on a stock macOS (/etc/pf.conf loaded at boot).
const appleRuleset = `scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
`

const wantPfRules = `pass quick on lo0 all no state
pass quick on wg0 all no state
pass quick on office all no state
pass out quick inet proto udp from any port 68 to { 255.255.255.255, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } port 67 user root no state
pass in quick inet proto udp from { 0.0.0.0, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } port 67 to any port 68 no state
pass out quick inet6 proto udp from fe80::/10 port 546 to ff02::1:2 port 547 user root no state
pass in quick inet6 proto udp from fe80::/10 port 547 to any port 546 no state
pass quick inet6 proto icmp6 from fe80::/10 to any icmp6-type { 133, 134, 135, 136 } no state
pass quick inet6 proto icmp6 from any to { fe80::/10, ff02::/16 } icmp6-type { 133, 134, 135, 136 } no state
pass out quick inet6 proto icmp6 from { fe80::/10, ::/128 } to any icmp6-type { 131, 143 } no state
pass in quick inet6 proto icmp6 from { fe80::/10, ::/128 } to any icmp6-type 130 no state
pass out quick inet proto udp from any to 203.0.113.5 port 51820 keep state
pass in quick inet proto udp from 203.0.113.5 port 51820 to any port 41641 keep state
pass out quick inet6 proto udp from any to 2001:db8::5 port 51820 keep state
pass in quick inet6 proto udp from 2001:db8::5 port 51820 to any port 41641 keep state
pass out quick inet proto udp from any to 198.51.100.7 port 4500 keep state
pass in quick inet proto udp from 198.51.100.7 port 4500 to any port 51820 keep state
block return out quick all
block drop in quick all
`

const (
	pfLoad   = "pfctl -a com.apple/250.latchwire -f -"
	pfFlush  = "pfctl -a com.apple/250.latchwire -F all"
	pfToken  = "18446742523466346583"
	pfRelTok = "pfctl -X " + pfToken
)

func TestPfRulesAndToken(t *testing.T) {
	got, err := pfRules(blockState())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantPfRules {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, wantPfRules)
	}

	r := newPfRecorder()
	j := newJournal(t)
	f := newPf(r, j)
	if err := f.Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	// The main ruleset is checked, the rules go into the anchor (stdin),
	// then pf is enabled with a reference (-E, whose token is on stderr).
	wantCmds := []string{"pfctl -sr", pfLoad, "pfctl -E"}
	if !reflect.DeepEqual(r.cmds, wantCmds) {
		t.Fatalf("commands %q, want %q", r.cmds, wantCmds)
	}
	if r.stdin[1] != wantPfRules {
		t.Errorf("rules on stdin:\n%s", r.stdin[1])
	}
	if !r.combined[2] {
		t.Error("pfctl -E did not read stderr")
	}
	// The token reaches the journal, with the anchor's flush: both
	// persistent, the release undone first.
	want := []netcfg.Step{
		{Name: "pfctl", Args: []string{"-a", "com.apple/250.latchwire", "-F", "all"}, Persistent: true},
		{Name: "pfctl", Args: []string{"-X", pfToken}, Persistent: true},
	}
	if got := j.Entries()[JournalOwner]; !reflect.DeepEqual(got, want) {
		t.Fatalf("journal %+v, want %+v", got, want)
	}

	// The next Set takes a new reference before it releases the old one,
	// so pf stays enabled even if someone ran pfctl -d meanwhile.
	r.cmds = nil
	r.out["pfctl -E"] = "Token : 7\n"
	if err := f.Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	wantCmds = []string{"pfctl -sr", pfLoad, "pfctl -E", pfRelTok}
	if !reflect.DeepEqual(r.cmds, wantCmds) {
		t.Fatalf("commands %q, want %q", r.cmds, wantCmds)
	}
	want[1].Args[1] = "7"
	if got := j.Entries()[JournalOwner]; !reflect.DeepEqual(got, want) {
		t.Fatalf("journal %+v, want %+v", got, want)
	}

	// Release: flush the anchor, release the token, forget the journal.
	r.cmds = nil
	if err := f.Set(context.Background(), State{}); err != nil {
		t.Fatal(err)
	}
	wantCmds = []string{pfFlush, "pfctl -X 7"}
	if !reflect.DeepEqual(r.cmds, wantCmds) {
		t.Fatalf("commands %q, want %q", r.cmds, wantCmds)
	}
	if _, ok := j.Entries()[JournalOwner]; ok {
		t.Error("journal still holds the kill switch after its release")
	}
}

// DNS passes only through the tunnel interfaces (P14); endpoint packets
// reach only the tunnel's listen port (P15); MLD is allowed from
// link-local or unspecified sources only (pf cannot match the hop limit).
func TestPfRulesNoDNSAndListenPortOnly(t *testing.T) {
	got, err := pfRules(blockState())
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Contains(s, "port 53") || strings.Contains(s, "domain") {
		t.Errorf("rules accept DNS outside the tunnels:\n%s", s)
	}
	for line := range strings.Lines(s) {
		if strings.HasPrefix(line, "pass in") && strings.Contains(line, "proto udp") && !strings.Contains(line, "from any") &&
			!strings.Contains(line, "to any port ") {
			t.Errorf("inbound endpoint rule open to every local port: %q", line)
		}
	}
	for line := range strings.Lines(s) {
		if strings.Contains(line, "icmp6-type { 131") || strings.Contains(line, "icmp6-type 130") {
			if !strings.Contains(line, "from { fe80::/10, ::/128 }") {
				t.Errorf("MLD rule not limited to link-local sources: %q", line)
			}
		}
	}
	// With no tunnel, only loopback and link setup pass.
	got, err = pfRules(State{Block: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pass quick on lo0 all no state\n", "port 67 user root no state\n", "block return out quick all\n", "block drop in quick all\n"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("empty block state lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "keep state") {
		t.Errorf("empty block state passes an endpoint:\n%s", got)
	}
}

func TestPfRulesRejectBadInput(t *testing.T) {
	for name, s := range map[string]State{
		"quote in iface": {Block: true, Tunnels: []TunnelRule{{Iface: `utun3 all`}}},
		"zoned endpoint": {Block: true, Tunnels: []TunnelRule{{Iface: "utun3", ListenPort: 1, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[fe80::1%en0]:51820")}}}},
	} {
		if _, err := pfRules(s); err == nil {
			t.Errorf("%s: no error", name)
		}
		r := newPfRecorder()
		if err := newPf(r, nil).Set(context.Background(), s); err == nil || len(r.cmds) != 0 {
			t.Errorf("%s: Set = %v, ran %q", name, err, r.cmds)
		}
	}
}

func TestPfHasAppleAnchor(t *testing.T) {
	for out, want := range map[string]bool{
		appleRuleset:                       true,
		"anchor \"com.apple/*\"\n":         true,
		"  anchor \"com.apple/*\" all  \n": true,
		"scrub-anchor \"com.apple/*\" all\nnat-anchor \"com.apple/*\" all\n": false,
		"anchor \"com.apple.other/*\" all\n":                                 false,
		"anchor \"custom\" all\nblock drop all\n":                            false,
		"": false,
	} {
		if got := pfHasAppleAnchor(out); got != want {
			t.Errorf("pfHasAppleAnchor(%q) = %v, want %v", out, got, want)
		}
	}
}

func TestParsePfToken(t *testing.T) {
	for out, want := range map[string]uint64{
		"pf enabled\nToken : 18446742523466346583\n": 18446742523466346583,
		"Token : 1":                    1,
		"pf enabled\n":                 0,
		"Token : 0\n":                  0,
		"Token : x\n":                  0,
		"Token : 99999999999999999999": 0,
	} {
		got, ok := parsePfToken(out)
		if got != want || ok != (want != 0) {
			t.Errorf("parsePfToken(%q) = %d, %v; want %d", out, got, ok, want)
		}
	}
}

// A custom main ruleset without the com.apple anchor point (or no pfctl)
// is not supported: nothing is changed and the error is ErrUnsupported.
func TestPfRefusesWithoutAppleAnchor(t *testing.T) {
	r := newPfRecorder()
	r.out["pfctl -sr"] = "block drop all\n"
	j := newJournal(t)
	err := newPf(r, j).Set(context.Background(), blockState())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Set = %v, want ErrUnsupported", err)
	}
	if err.Error() == ErrUnsupported.Error() || !strings.Contains(err.Error(), "com.apple") {
		t.Errorf("error %q does not explain the missing anchor", err)
	}
	if !reflect.DeepEqual(r.cmds, []string{"pfctl -sr"}) {
		t.Errorf("commands %q, want only the check", r.cmds)
	}
	if len(j.Entries()) != 0 {
		t.Errorf("journal %v, want empty", j.Entries())
	}

	r = newPfRecorder()
	r.missing = true
	if err := newPf(r, nil).Set(context.Background(), blockState()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Set without pfctl = %v, want ErrUnsupported", err)
	}
	// Releasing needs no anchor point and succeeds without pfctl.
	if err := newPf(r, nil).Set(context.Background(), State{}); err != nil {
		t.Fatalf("release without pfctl: %v", err)
	}
}

// Undo is idempotent: a release of an anchor already flushed and a token
// pf no longer holds succeeds and forgets the journal; a real failure keeps
// it.
func TestPfReleaseIdempotent(t *testing.T) {
	r := newPfRecorder()
	j := newJournal(t)
	f := newPf(r, j)
	if err := f.Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	r.errs[pfFlush] = errors.New("exit status 1: pfctl: /dev/pf: Permission denied")
	if err := f.Set(context.Background(), State{}); err == nil {
		t.Fatal("no error from a failing flush")
	}
	if _, ok := j.Entries()[JournalOwner]; !ok {
		t.Fatal("journal lost the kill switch after a failed release")
	}
	r.errs[pfFlush] = errors.New("exit status 1: pfctl: Anchor does not exist.")
	r.errs[pfRelTok] = errors.New("exit status 1: pfctl: DIOCSTOPREF: Invalid argument")
	if err := f.Set(context.Background(), State{}); err != nil {
		t.Fatalf("release of what is gone: %v", err)
	}
	if _, ok := j.Entries()[JournalOwner]; ok {
		t.Error("journal still holds the kill switch")
	}
	// A release with nothing held only flushes the anchor.
	r.cmds = nil
	if err := newPf(r, nil).Set(context.Background(), State{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.cmds, []string{pfFlush}) {
		t.Errorf("commands %q", r.cmds)
	}
}

// A daemon that restarts with the kill switch journaled knows its token:
// the next Set rotates it and the release releases it.
func TestPfRecoversTokenFromJournal(t *testing.T) {
	r := newPfRecorder()
	j := newJournal(t)
	if err := newPf(r, j).Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	f := newPf(r, j)
	if err := f.Set(context.Background(), State{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.cmds, []string{pfFlush, pfRelTok}) {
		t.Fatalf("commands %q", r.cmds)
	}
}

// pfctl -E without a token in its output leaves the rules journaled for
// removal and fails: nothing would release pf's reference.
func TestPfEnableWithoutToken(t *testing.T) {
	r := newPfRecorder()
	r.out["pfctl -E"] = "pf enabled\n"
	j := newJournal(t)
	if err := newPf(r, j).Set(context.Background(), blockState()); err == nil {
		t.Fatal("no error without a token")
	}
	want := []netcfg.Step{{Name: "pfctl", Args: []string{"-a", "com.apple/250.latchwire", "-F", "all"}, Persistent: true}}
	if got := j.Entries()[JournalOwner]; !reflect.DeepEqual(got, want) {
		t.Fatalf("journal %+v, want %+v", got, want)
	}
}

// The journaled steps are what netcfg.Cleanup runs after a crash.
func TestPfJournalCleanup(t *testing.T) {
	r := newPfRecorder()
	j := newJournal(t)
	if err := newPf(r, j).Set(context.Background(), blockState()); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	r.errs[pfRelTok] = errors.New("exit status 1: pfctl: DIOCSTOPREF: Invalid argument")
	if err := netcfg.Cleanup(context.Background(), r, j, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.cmds, []string{pfRelTok, pfFlush}) {
		t.Fatalf("cleanup ran %q", r.cmds)
	}
}

// A tunnel still connecting gets the outbound endpoint rule only; its
// state lets the replies in (P17).
func TestPfConnectingTunnelOutboundOnly(t *testing.T) {
	got, err := pfRules(State{Block: true, Tunnels: []TunnelRule{{Endpoints: []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::5]:51820")}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "pass out quick inet6 proto udp from any to 2001:db8::5 port 51820 keep state\n") {
		t.Errorf("no outbound endpoint rule:\n%s", got)
	}
	for _, bad := range []string{"from 2001:db8::5", "pass quick on  ", "port 0"} {
		if strings.Contains(string(got), bad) {
			t.Errorf("rules have %q:\n%s", bad, got)
		}
	}
}

// DHCP passes only from root's sockets to where a DHCP server can be, and
// back (P16); neighbour discovery only with a link-local or link-scope
// multicast address on one side (P17).
func TestPfLinkRulesNarrow(t *testing.T) {
	got, err := pfRules(State{Block: true})
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(got)) {
		switch {
		case strings.Contains(line, "port 67 user") || strings.Contains(line, "port 547 user"):
		case strings.Contains(line, "port 67") || strings.Contains(line, "port 547"):
			if strings.HasPrefix(line, "pass out") {
				t.Errorf("DHCP request rule without user root: %q", line)
			}
		}
		if strings.Contains(line, "from any port 67") || strings.Contains(line, "from any port 547") ||
			strings.Contains(line, "to any port 67") || strings.Contains(line, "to any port 547") {
			t.Errorf("DHCP rule open to any address: %q", line)
		}
		if strings.Contains(line, "icmp6-type { 133") && !strings.Contains(line, "from fe80::/10 to any") &&
			!strings.Contains(line, "from any to { fe80::/10, ff02::/16 }") {
			t.Errorf("neighbour discovery rule too wide: %q", line)
		}
	}
}

func TestPfVerify(t *testing.T) {
	r := newPfRecorder()
	f := newPf(r, nil)
	const info = "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n\nState Table                          Total             Rate\n"
	for _, tc := range []struct {
		info, anchor string
		want         bool
	}{
		{info, "block drop in quick all\n", true},
		{strings.Replace(info, "Enabled", "Disabled", 1), "block drop in quick all\n", false},
		{info, "", false},
		{"", "block drop in quick all\n", false},
	} {
		r.out["pfctl -s info"], r.out["pfctl -a com.apple/250.latchwire -sr"] = tc.info, tc.anchor
		if ok, err := f.Verify(context.Background()); ok != tc.want || err != nil {
			t.Errorf("Verify(%.20q, %q) = %v, %v; want %v", tc.info, tc.anchor, ok, err, tc.want)
		}
	}
	// A main ruleset that no longer evaluates com.apple/* (pfctl -f with
	// a custom pf.conf): the anchor's rules are there but never used, and
	// setting them again cannot help.
	r.out["pfctl -s info"], r.out["pfctl -a com.apple/250.latchwire -sr"] = info, "block drop in quick all\n"
	r.out["pfctl -sr"] = "pass all\n"
	ok, err := f.Verify(context.Background())
	if ok || !errors.Is(err, ErrUnsupported) || err.Error() != msg.KillSwitchPfNoAnchor {
		t.Errorf("Verify without the anchor point = %v, %v; want false, ErrUnsupported", ok, err)
	}
	r.errs["pfctl -sr"] = errors.New("exit status 1")
	if ok, err := f.Verify(context.Background()); ok || err == nil || errors.Is(err, ErrUnsupported) {
		t.Errorf("Verify that cannot read the main ruleset = %v, %v", ok, err)
	}
	delete(r.errs, "pfctl -sr")
	r.out["pfctl -sr"] = appleRuleset
	if ok, err := f.Verify(context.Background()); !ok || err != nil {
		t.Errorf("Verify with the anchor point back = %v, %v", ok, err)
	}
	r.errs["pfctl -s info"] = errors.New("exit status 1: pfctl: /dev/pf: Permission denied")
	if ok, err := f.Verify(context.Background()); ok || err == nil {
		t.Errorf("Verify that cannot read = %v, %v", ok, err)
	}
	var _ Verifier = f
}
