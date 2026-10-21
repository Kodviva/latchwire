package netcfg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// fval is one value of a fake dynamic-store dictionary.
type fval struct {
	kind string // "" string, "*" array, "#" number
	vals []string
}

type fdict map[string]fval

// fakeStore stands in for configd's dynamic store: it runs the scutil
// scripts it gets on stdin (d.init, d.add, set, remove, show, comments)
// and prints what scutil prints. Other commands go to rec.
type fakeStore struct {
	keys    map[string]fdict
	scripts []string // every scutil stdin, in order
	cmds    []string // every command line; scutil ones as "scutil"
	rec     recorder
	// setErr, when set, is printed by every "set" instead of storing.
	setErr string
}

// newFakeStore also frees the process-wide DNSPrimary ownership (P12), now
// and when the test ends, so tests do not see each other's tunnels.
func newFakeStore(t *testing.T) *fakeStore {
	freshPrimaryDNS(t)
	return &fakeStore{keys: map[string]fdict{}}
}

func freshPrimaryDNS(t *testing.T) {
	reset := func() {
		primaryDNS.mu.Lock()
		primaryDNS.owner, primaryDNS.iface = nil, ""
		primaryDNS.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func (f *fakeStore) Run(c2 context.Context, name string, args []string, in []byte) ([]byte, error) {
	if name != "scutil" {
		f.cmds = append(f.cmds, strings.Join(append([]string{name}, args...), " "))
		return f.rec.Run(c2, name, args, in)
	}
	f.cmds = append(f.cmds, "scutil")
	if len(args) != 0 {
		return nil, fmt.Errorf("scutil with arguments %q", args)
	}
	f.scripts = append(f.scripts, string(in))
	var out strings.Builder
	var cur fdict
	for line := range strings.Lines(string(in)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tok := fakeTokens(line)
		switch tok[0] {
		case "d.init":
			cur = fdict{}
		case "d.add":
			v := fval{}
			rest := tok[2:]
			if len(rest) > 0 && (rest[0] == "*" || rest[0] == "#") {
				v.kind, rest = rest[0], rest[1:]
			}
			if len(rest) == 0 {
				out.WriteString("d.add: no values.\n")
				continue
			}
			v.vals = rest
			cur[tok[1]] = v
		case "set":
			if f.setErr != "" {
				out.WriteString(f.setErr + "\n")
				continue
			}
			f.keys[tok[1]] = maps2(cur)
		case "remove":
			if _, ok := f.keys[tok[1]]; !ok {
				out.WriteString("  No such key\n")
			}
			delete(f.keys, tok[1])
		case "show":
			d, ok := f.keys[tok[1]]
			if !ok {
				out.WriteString("  No such key\n")
				continue
			}
			out.WriteString(dumpFake(d))
		default:
			fmt.Fprintf(&out, "%s: unknown, type \"help\" for command info\n", tok[0])
		}
	}
	return []byte(out.String()), nil
}

// fakeTokens splits a scutil line into words; double quotes group words.
func fakeTokens(line string) []string {
	var out []string
	var b strings.Builder
	quoted, in := false, false
	for _, c := range line {
		switch {
		case c == '"':
			quoted, in = !quoted, true
		case c == ' ' && !quoted:
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteRune(c)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

func maps2(d fdict) fdict {
	out := fdict{}
	for k, v := range d {
		out[k] = fval{kind: v.kind, vals: slices.Clone(v.vals)}
	}
	return out
}

// dumpFake prints d the way scutil's show does (keys sorted).
func dumpFake(d fdict) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("<dictionary> {\n")
	for _, k := range keys {
		v := d[k]
		if v.kind == "*" {
			fmt.Fprintf(&b, "  %s : <array> {\n", k)
			for i, s := range v.vals {
				fmt.Fprintf(&b, "    %d : %s\n", i, s)
			}
			b.WriteString("  }\n")
			continue
		}
		fmt.Fprintf(&b, "  %s : %s\n", k, strings.Join(v.vals, " "))
	}
	b.WriteString("}\n")
	return b.String()
}

func arr(v ...string) fval { return fval{kind: "*", vals: v} }
func str(v string) fval    { return fval{vals: []string{v}} }
func num(v string) fval    { return fval{kind: "#", vals: []string{v}} }

const (
	svc1 = "95CB9790-6B29-4AA5-9B9E-2910B5FD8CCD"
	svc2 = "0F3A1C2E-1111-4222-8333-444455556666"
)

func (f *fakeStore) setPrimary(id string) {
	f.keys["State:/Network/Global/IPv4"] = fdict{
		"PrimaryInterface": str("en0"), "PrimaryService": str(id), "Router": str("192.168.1.1"),
	}
}

func dnsKey(id string) string { return "State:/Network/Service/" + id + "/DNS" }

func darwinDNSPlan(role DNSRole, search ...string) Plan {
	return Plan{
		Iface: "utun7", Addresses: pfx("10.0.0.2/32"), DNSRole: role, DNSSearch: search,
		DNS: []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")},
	}
}

// scutilUndos returns the journaled scutil undo steps, persistent ones
// marked with "P ", followed by their stdin.
func scutilUndos(j *Journal, owner string) []string {
	var out []string
	for _, s := range j.Entries()[owner] {
		if s.Name == "scutil" {
			p := "  "
			if s.Persistent {
				p = "P "
			}
			out = append(out, p+string(s.Stdin))
		}
	}
	return out
}

// writes returns the scutil scripts that change the store.
func (f *fakeStore) writes() []string {
	var out []string
	for _, s := range f.scripts {
		if strings.Contains(s, "\nset ") || strings.HasPrefix(s, "remove ") || strings.Contains(s, "\nremove ") {
			out = append(out, s)
		}
	}
	return out
}

func TestDarwinDNSPrimaryWritesAndRestores(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	orig := fdict{
		"ServerAddresses": arr("192.168.1.1", "fe80::1%en0"),
		"SearchDomains":   arr("home.lan"),
		"DomainName":      str("home.lan"),
		"SearchOrder":     num("1"),
		"Options":         str("ndots:2 timeout:3"),
	}
	f.keys[dnsKey(svc1)] = maps2(orig)
	j, _ := newJournal(t)
	c := newDarwin(f, j)
	res, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary, "corp.example"))
	if err != nil {
		t.Fatal(err)
	}
	if res.DNS != DNSOutcomeScutilPrimary {
		t.Errorf("Applied.DNS = %q, want %q", res.DNS, DNSOutcomeScutilPrimary)
	}
	// The reads come before any change; DNS goes after the addresses.
	wantCmds := []string{"scutil", "scutil", "scutil", "ifconfig utun7 inet 10.0.0.2 10.0.0.2 alias", "scutil"}
	if !reflect.DeepEqual(f.cmds, wantCmds) {
		t.Errorf("commands %q, want %q", f.cmds, wantCmds)
	}
	wantReads := []string{
		"show State:/Network/Global/IPv4\n",
		"show " + dnsKey(svc1) + "\n",
		"show Setup:/Network/Service/" + svc1 + "/DNS\n",
	}
	if !reflect.DeepEqual(f.scripts[:3], wantReads) {
		t.Errorf("reads %q, want %q", f.scripts[:3], wantReads)
	}
	wantSet := "d.init\n" +
		"d.add ServerAddresses * 10.0.0.1 fd00::1\n" +
		"d.add SearchDomains * corp.example\n" +
		"set " + dnsKey(svc1) + "\n"
	if f.scripts[3] != wantSet {
		t.Errorf("set script:\n%s\nwant:\n%s", f.scripts[3], wantSet)
	}
	want := fdict{"ServerAddresses": arr("10.0.0.1", "fd00::1"), "SearchDomains": arr("corp.example")}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], want) {
		t.Errorf("store %v, want %v", f.keys[dnsKey(svc1)], want)
	}
	// The original dictionary is journaled (persistent, P7) before the
	// change, behind what Latchwire set: the undo restores it only while
	// the key still holds that.
	wantUndo := "P # expect d.add ServerAddresses * 10.0.0.1 fd00::1\n" +
		"# expect d.add SearchDomains * corp.example\n" +
		"d.init\n" +
		"d.add DomainName home.lan\n" +
		"d.add Options \"ndots:2 timeout:3\"\n" +
		"d.add SearchDomains * home.lan\n" +
		"d.add SearchOrder # 1\n" +
		"d.add ServerAddresses * 192.168.1.1 fe80::1%en0\n" +
		"set " + dnsKey(svc1) + "\n"
	if got := scutilUndos(j, "utun7"); !reflect.DeepEqual(got, []string{wantUndo}) {
		t.Fatalf("journal:\n%q\nwant:\n%q", got, []string{wantUndo})
	}
	undo := j.Entries()["utun7"]

	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig) {
		t.Errorf("restored %v, want %v", f.keys[dnsKey(svc1)], orig)
	}
	if e := j.Entries()["utun7"]; len(e) != 0 {
		t.Errorf("journal after Remove: %v", e)
	}
	// Idempotent: running the undo again (a crash before the journal was
	// updated) finds the original, not Latchwire's, and writes nothing.
	n := len(f.writes())
	for i := len(undo) - 1; i >= 0; i-- {
		if err := runUndo(ctx, f, undo[i]); err != nil {
			t.Fatalf("second undo: %v", err)
		}
	}
	if len(f.writes()) != n || !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig) {
		t.Errorf("second undo wrote %q", f.writes()[n:])
	}
}

// Leak, not clobber: a dictionary somebody wrote after Latchwire is left
// alone, and so is a key that is gone (the service went down).
func TestDarwinDNSPrimaryUndoLeavesForeignDict(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	f.keys[dnsKey(svc1)] = fdict{"ServerAddresses": arr("192.168.1.1")}
	j, _ := newJournal(t)
	c := newDarwin(f, j)
	if _, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil {
		t.Fatal(err)
	}
	foreign := fdict{"ServerAddresses": arr("9.9.9.9")}
	f.keys[dnsKey(svc1)] = maps2(foreign)
	n := len(f.writes())
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.writes()) != n || !reflect.DeepEqual(f.keys[dnsKey(svc1)], foreign) {
		t.Errorf("foreign dictionary clobbered: %v (writes %q)", f.keys[dnsKey(svc1)], f.writes()[n:])
	}
	if e := j.Entries()["utun7"]; len(e) != 0 {
		t.Errorf("journal after Remove: %v", e)
	}

	// Gone: nothing restored, no stale key created.
	if _, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil {
		t.Fatal(err)
	}
	delete(f.keys, dnsKey(svc1))
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys[dnsKey(svc1)]; ok {
		t.Errorf("restored a key that was gone: %v", f.keys[dnsKey(svc1)])
	}
}

func TestDarwinDNSPrimaryNoOriginalRemoves(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	j, _ := newJournal(t)
	c := newDarwin(f, j)
	if _, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil {
		t.Fatal(err)
	}
	// No search domains: only the servers are set.
	want := fdict{"ServerAddresses": arr("10.0.0.1", "fd00::1")}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], want) {
		t.Errorf("store %v, want %v", f.keys[dnsKey(svc1)], want)
	}
	wantUndo := "P # expect d.add ServerAddresses * 10.0.0.1 fd00::1\n" +
		"remove " + dnsKey(svc1) + "\n"
	if got := scutilUndos(j, "utun7"); !reflect.DeepEqual(got, []string{wantUndo}) {
		t.Fatalf("journal:\n%q\nwant:\n%q", got, []string{wantUndo})
	}
	// A crash: the next start's Cleanup removes the key.
	if err := Cleanup(ctx, f, j, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys[dnsKey(svc1)]; ok {
		t.Errorf("key left after Cleanup: %v", f.keys[dnsKey(svc1)])
	}
	if e := j.Entries(); len(e) != 0 {
		t.Errorf("journal after Cleanup: %v", e)
	}
}

func TestDarwinDNSScopedSupplemental(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	primary := fdict{"ServerAddresses": arr("192.168.1.1")}
	f.keys[dnsKey(svc1)] = maps2(primary)
	j, _ := newJournal(t)
	c := newDarwin(f, j)
	res, err := c.Apply(ctx, darwinDNSPlan(DNSScoped, "corp.example", "lab.example"))
	if err != nil {
		t.Fatal(err)
	}
	if res.DNS != DNSOutcomeScutilScoped {
		t.Errorf("Applied.DNS = %q, want %q", res.DNS, DNSOutcomeScutilScoped)
	}
	key := "State:/Network/Service/latchwire-utun7/DNS"
	wantSet := "d.init\n" +
		"d.add ServerAddresses * 10.0.0.1 fd00::1\n" +
		"d.add SupplementalMatchDomains * corp.example lab.example\n" +
		"set " + key + "\n"
	// The primary service is neither read nor touched.
	if !reflect.DeepEqual(f.scripts, []string{wantSet}) {
		t.Errorf("scripts:\n%q\nwant:\n%q", f.scripts, []string{wantSet})
	}
	if got, want := scutilUndos(j, "utun7"), []string{"P remove " + key + "\n"}; !reflect.DeepEqual(got, want) {
		t.Errorf("journal %q, want %q", got, want)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys[key]; ok {
		t.Error("scoped key left after Remove")
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], primary) {
		t.Errorf("primary changed: %v", f.keys[dnsKey(svc1)])
	}
	// Removing a key that is gone already succeeds (idempotent).
	if err := runUndo(ctx, f, Step{Name: "scutil", Stdin: []byte("remove " + key + "\n"), Persistent: true}); err != nil {
		t.Errorf("undo of a gone key: %v", err)
	}

	// Scoped without search domains has nothing to answer: no change.
	f2 := newFakeStore(t)
	res, err = newDarwin(f2, nil).Apply(ctx, darwinDNSPlan(DNSScoped))
	if err != nil || res.DNS != DNSOutcomeScutilScoped || len(f2.scripts) != 0 {
		t.Errorf("scoped without domains: %+v %v %q", res, err, f2.scripts)
	}
}

func TestDarwinDNSRefreshPrimaryServiceChange(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	orig1 := fdict{"ServerAddresses": arr("192.168.1.1")}
	orig2 := fdict{"ServerAddresses": arr("172.20.10.1"), "SearchDomains": arr("mobile.lan")}
	f.keys[dnsKey(svc1)] = maps2(orig1)
	f.keys[dnsKey(svc2)] = maps2(orig2)
	j, _ := newJournal(t)
	c := newDarwin(f, j)
	if _, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary, "corp.example")); err != nil {
		t.Fatal(err)
	}
	ours := fdict{"ServerAddresses": arr("10.0.0.1", "fd00::1"), "SearchDomains": arr("corp.example")}

	// Unchanged: Refresh only reads (P9).
	n := len(f.writes())
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.writes()) != n {
		t.Fatalf("unchanged Refresh wrote %q", f.writes()[n:])
	}

	// The primary service changes: the old one gets its DNS back, the new
	// one gets the tunnel's, and the journal follows.
	f.setPrimary(svc2)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig1) {
		t.Errorf("old service %v, want %v", f.keys[dnsKey(svc1)], orig1)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc2)], ours) {
		t.Errorf("new service %v, want %v", f.keys[dnsKey(svc2)], ours)
	}
	got := scutilUndos(j, "utun7")
	if len(got) != 1 || !strings.HasSuffix(got[0], "d.add SearchDomains * mobile.lan\nd.add ServerAddresses * 172.20.10.1\nset "+dnsKey(svc2)+"\n") {
		t.Fatalf("journal after the move: %q", got)
	}
	n = len(f.writes())
	if err := c.Refresh(ctx); err != nil || len(f.writes()) != n {
		t.Fatalf("second Refresh: %v, wrote %q", err, f.writes()[n:])
	}

	// Offline (no primary service): nothing changes.
	delete(f.keys, "State:/Network/Global/IPv4")
	if err := c.Refresh(ctx); err != nil || len(f.writes()) != n {
		t.Fatalf("offline Refresh: %v, wrote %q", err, f.writes()[n:])
	}

	// Same service, but DHCP rewrote its DNS (a lease renewal, the
	// network coming back): the tunnel's DNS is put back and the new
	// dictionary becomes the one to restore.
	f.setPrimary(svc2)
	renewed := fdict{"ServerAddresses": arr("172.20.10.254")}
	f.keys[dnsKey(svc2)] = maps2(renewed)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc2)], ours) {
		t.Errorf("after the rewrite %v, want %v", f.keys[dnsKey(svc2)], ours)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc2)], renewed) {
		t.Errorf("restored %v, want %v", f.keys[dnsKey(svc2)], renewed)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig1) {
		t.Errorf("svc1 %v, want %v", f.keys[dnsKey(svc1)], orig1)
	}
}

// A move that fails is not retried on every network event (P9).
func TestDarwinDNSRefreshBacksOff(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	c := newDarwin(f, nil).(*configurer)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil {
		t.Fatal(err)
	}
	f.setPrimary(svc2)
	f.setErr = "set: Permission denied"
	if err := c.Refresh(ctx); err == nil {
		t.Fatal("failed move: no error")
	}
	n := len(f.scripts)
	if err := c.Refresh(ctx); err != nil {
		t.Fatalf("within backoff: %v", err)
	}
	for _, s := range f.scripts[n:] {
		if strings.Contains(s, "set ") {
			t.Fatalf("retried within the backoff: %q", f.scripts[n:])
		}
	}
	f.setErr = ""
	now = now.Add(moveBackoff + time.Second)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := (fdict{"ServerAddresses": arr("10.0.0.1", "fd00::1")}); !reflect.DeepEqual(f.keys[dnsKey(svc2)], want) {
		t.Errorf("after the backoff %v", f.keys[dnsKey(svc2)])
	}
}

func TestDarwinDNSIPv6OnlyPrimaryAndSetupOverride(t *testing.T) {
	f := newFakeStore(t)
	f.keys["State:/Network/Global/IPv6"] = fdict{"PrimaryService": str(svc1)}
	f.keys["Setup:/Network/Service/"+svc1+"/DNS"] = fdict{"ServerAddresses": arr("1.1.1.1")}
	res, err := newDarwin(f, nil).Apply(ctx, darwinDNSPlan(DNSPrimary))
	if err != nil {
		t.Fatal(err)
	}
	// DNS servers set by hand in System Settings win over the dynamic
	// store's: reported, not hidden.
	if res.DNS != DNSOutcomeScutilPrimaryOverridden {
		t.Errorf("Applied.DNS = %q, want %q", res.DNS, DNSOutcomeScutilPrimaryOverridden)
	}
	if _, ok := f.keys[dnsKey(svc1)]; !ok {
		t.Error("IPv6 primary service not used")
	}

	// No primary service at all: nothing to set now; Refresh applies once
	// one appears.
	f2 := newFakeStore(t)
	c := newDarwin(f2, nil)
	if res, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil || res.DNS != DNSOutcomeScutilPrimary {
		t.Fatalf("offline Apply: %+v %v", res, err)
	}
	if len(f2.writes()) != 0 {
		t.Fatalf("offline Apply wrote %q", f2.writes())
	}
	f2.setPrimary(svc1)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := f2.keys[dnsKey(svc1)]; !ok {
		t.Error("Refresh did not apply DNS to the new primary service")
	}
}

func TestDarwinDNSRejectsBadInput(t *testing.T) {
	bad := []Plan{darwinDNSPlan(DNSPrimary, "a b"), darwinDNSPlan(DNSPrimary, "a\nset X"), darwinDNSPlan(DNSScoped, "-x")}
	zoned := darwinDNSPlan(DNSPrimary)
	zoned.DNS = append(zoned.DNS, netip.MustParseAddr("fe80::1%en0"))
	bad = append(bad, zoned)
	for _, p := range bad {
		f := newFakeStore(t)
		f.setPrimary(svc1)
		if _, err := newDarwin(f, nil).Apply(ctx, p); err == nil {
			t.Errorf("%v %q accepted", p.DNS, p.DNSSearch)
		}
		if len(f.writes()) != 0 || slices.ContainsFunc(f.cmds, func(c string) bool { return c != "scutil" }) {
			t.Errorf("changed the system before failing: %q", f.cmds)
		}
	}
	// A service ID that would leave its key, or a dictionary that cannot
	// be read, fails before any change.
	for _, setup := range []func(f *fakeStore){
		func(f *fakeStore) { f.setPrimary("../Global/IPv4") },
		func(f *fakeStore) { f.setPrimary("a b") },
	} {
		f := newFakeStore(t)
		setup(f)
		if _, err := newDarwin(f, nil).Apply(ctx, darwinDNSPlan(DNSPrimary)); err == nil || len(f.writes()) != 0 {
			t.Errorf("bad service: err=%v writes=%q", err, f.writes())
		}
	}
	r := &recorder{out: map[string]string{"scutil": "garbage\n"}}
	if _, err := newDarwin(r, nil).Apply(ctx, darwinDNSPlan(DNSPrimary)); err == nil {
		t.Error("unreadable scutil output accepted")
	}
	// Bad interface names never reach a scoped key.
	p := darwinDNSPlan(DNSScoped, "corp.example")
	p.Iface = "utun7/x"
	if _, err := newDarwin(newFakeStore(t), nil).Apply(ctx, p); err == nil {
		t.Error("bad interface name accepted")
	}
}

// scutil reports its errors on stdout and exits 0: any output from a
// write is a failure, and Apply rolls back.
func TestDarwinDNSWriteFailure(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	orig := fdict{"ServerAddresses": arr("192.168.1.1")}
	f.keys[dnsKey(svc1)] = maps2(orig)
	f.setErr = "  set: Permission denied"
	j, _ := newJournal(t)
	_, err := newDarwin(f, j).Apply(ctx, darwinDNSPlan(DNSPrimary))
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig) {
		t.Errorf("store %v", f.keys[dnsKey(svc1)])
	}
	if e := j.Entries()["utun7"]; len(e) != 0 {
		t.Errorf("journal after rollback: %v", e)
	}
}

func TestParseScutilDict(t *testing.T) {
	out := `<dictionary> {
  ConfirmedServiceID : 95CB9790
  DomainName : home.lan
  Nested : <dictionary> {
    A : b
  }
  Options : ndots:2 timeout:3
  SearchOrder : 200
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : fe80::1%en0
  }
  SupplementalMatchDomains : <array> {
    0 :
    1 : corp.example
  }
  SupplementalMatchOrders : <array> {
    0 : 100
  }
  SortList : <array> {
  }
  Unknown : x
  __FLAGS__ : 2
}
`
	d, found, err := parseScutilDict(out)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	keep, dropped := restorableDNS(d)
	wantDropped := []string{"Nested", "SupplementalMatchOrders", "SortList", "Unknown", "__FLAGS__"}
	if !reflect.DeepEqual(dropped, wantDropped) {
		t.Errorf("dropped %q, want %q", dropped, wantDropped)
	}
	wantScript := "d.init\n" +
		"d.add ConfirmedServiceID 95CB9790\n" +
		"d.add DomainName home.lan\n" +
		"d.add Options \"ndots:2 timeout:3\"\n" +
		"d.add SearchOrder # 200\n" +
		"d.add ServerAddresses * 192.168.1.1 fe80::1%en0\n" +
		"d.add SupplementalMatchDomains * \"\" corp.example\n"
	if got := dictScript(keep); got != wantScript {
		t.Errorf("script:\n%s\nwant:\n%s", got, wantScript)
	}
	if _, found, err := parseScutilDict("  No such key\n"); found || err != nil {
		t.Errorf("no such key: found=%v err=%v", found, err)
	}
	for _, bad := range []string{"", "garbage\n", "<dictionary> {\n  A : b\n", "<dictionary> {\n  junk\n}\n"} {
		if _, _, err := parseScutilDict(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	// Values scutil cannot take back are dropped, not mangled.
	d = scDict{
		{key: "DomainName", vals: []string{"#"}},
		{key: "Options", vals: []string{`a"b`}},
		{key: "SearchOrder", vals: []string{"x"}},
		{key: "SearchDomains", array: true, vals: []string{"a\tb"}},
	}
	if keep, dropped := restorableDNS(d); len(keep) != 0 || len(dropped) != 4 {
		t.Errorf("kept %v, dropped %q", keep, dropped)
	}
}

func TestScutilUndoUnreadableLeavesAlone(t *testing.T) {
	f := newFakeStore(t)
	f.keys[dnsKey(svc1)] = fdict{"ServerAddresses": arr("10.0.0.1")}
	// A malformed journal step fails instead of running.
	if err := runUndo(ctx, f, Step{Name: "scutil", Stdin: []byte("d.init\n")}); err == nil {
		t.Error("undo without a target accepted")
	}
	// Reading the key fails: an error, kept for a retry, nothing written.
	r := &recorder{failOn: "scutil", failErr: errors.New("exit status 1")}
	s := Step{Name: "scutil", Stdin: []byte("# expect d.add ServerAddresses * 10.0.0.1\nremove " + dnsKey(svc1) + "\n")}
	if err := runUndo(ctx, r, s); err == nil || len(r.cmds) != 1 {
		t.Errorf("err=%v cmds=%q", err, r.cmds)
	}
	// Output that cannot be read: left alone, no error.
	r = &recorder{out: map[string]string{"scutil": "garbage\n"}}
	if err := runUndo(ctx, r, s); err != nil || len(r.cmds) != 1 {
		t.Errorf("unreadable: err=%v cmds=%q", err, r.cmds)
	}
}

// An empty array in the original is left out of the undo: d.add cannot
// write one, and the whole restore would fail.
func TestDarwinDNSEmptyArrayRestores(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	f.keys[dnsKey(svc1)] = fdict{"ServerAddresses": arr("192.168.1.1"), "SearchDomains": arr()}
	c := newDarwin(f, nil)
	if _, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if want := (fdict{"ServerAddresses": arr("192.168.1.1")}); !reflect.DeepEqual(f.keys[dnsKey(svc1)], want) {
		t.Errorf("restored %v, want %v", f.keys[dnsKey(svc1)], want)
	}
}

// P12: one DNSPrimary tunnel per process. A second one applies no DNS and
// says so; the first one's original is restored intact; ownership ends with
// Remove or a rolled-back Apply.
func TestDarwinDNSPrimaryOneOwner(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	orig := fdict{"ServerAddresses": arr("192.168.1.1")}
	f.keys[dnsKey(svc1)] = maps2(orig)
	j, _ := newJournal(t)
	a, b := newDarwin(f, j), newDarwin(f, j)
	if res, err := a.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil || res.DNS != DNSOutcomeScutilPrimary {
		t.Fatalf("first: %+v %v", res, err)
	}
	pb := darwinDNSPlan(DNSPrimary, "other.example")
	pb.Iface, pb.Addresses = "utun8", pfx("10.9.0.2/32")
	pb.DNS = []netip.Addr{netip.MustParseAddr("10.9.0.1")}
	n := len(f.scripts)
	res, err := b.Apply(ctx, pb)
	if err != nil || res.DNS != DNSOutcomePrimaryBusy {
		t.Fatalf("second: %+v %v", res, err)
	}
	if len(f.scripts) != n || len(scutilUndos(j, "utun8")) != 0 {
		t.Errorf("second tunnel touched DNS: %q", f.scripts[n:])
	}
	if err := b.Refresh(ctx); err != nil || len(f.scripts) != n {
		t.Errorf("second tunnel's Refresh touched DNS: %v %q", err, f.scripts[n:])
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig) {
		t.Errorf("restored %v, want %v", f.keys[dnsKey(svc1)], orig)
	}
	// Released by Remove: b can have it now.
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomeScutilPrimary {
		t.Fatalf("after release: %+v %v", res, err)
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	// Released by a rolled-back Apply.
	f.setErr = "  set: Permission denied"
	if _, err := a.Apply(ctx, darwinDNSPlan(DNSPrimary)); err == nil {
		t.Fatal("failing Apply succeeded")
	}
	f.setErr = ""
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomeScutilPrimary {
		t.Fatalf("after rollback: %+v %v", res, err)
	}
	// Scoped DNS is not limited.
	ps := darwinDNSPlan(DNSScoped, "corp.example")
	if res, err := newDarwin(f, nil).Apply(ctx, ps); err != nil || res.DNS != DNSOutcomeScutilScoped {
		t.Fatalf("scoped next to a primary: %+v %v", res, err)
	}
}

// Another tool that keeps rewriting the DNS: each Refresh (the daemon's
// 30 s tick, P12) puts the tunnel's back, logging it once per service and
// without "leaving them alone" noise; overridden follows the service.
func TestDarwinDNSFightLogsOnce(t *testing.T) {
	logs := captureLog(t)
	f := newFakeStore(t)
	f.setPrimary(svc1)
	f.keys["Setup:/Network/Service/"+svc1+"/DNS"] = fdict{"ServerAddresses": arr("1.1.1.1")}
	c := newDarwin(f, nil).(*configurer)
	if res, err := c.Apply(ctx, darwinDNSPlan(DNSPrimary)); err != nil || res.DNS != DNSOutcomeScutilPrimaryOverridden || !c.dn.overridden {
		t.Fatalf("%+v %v overridden=%v", res, err, c.dn.overridden)
	}
	ours := fdict{"ServerAddresses": arr("10.0.0.1", "fd00::1")}
	for i := range 3 {
		f.keys[dnsKey(svc1)] = fdict{"ServerAddresses": arr(fmt.Sprintf("192.168.1.%d", i+10))}
		if err := c.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(f.keys[dnsKey(svc1)], ours) {
			t.Fatalf("round %d: %v", i, f.keys[dnsKey(svc1)])
		}
	}
	out := logs.String()
	if n := strings.Count(out, "DNS applied again to network service "+svc1); n != 1 {
		t.Errorf("re-apply logged %d times:\n%s", n, out)
	}
	if strings.Contains(out, "leaving them alone") {
		t.Errorf("fight logged as foreign settings:\n%s", out)
	}
	// The last rewrite is what Remove restores.
	f.setPrimary(svc2)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if c.dn.overridden {
		t.Error("overridden kept after moving to a service without manual DNS")
	}
	if want := (fdict{"ServerAddresses": arr("192.168.1.12")}); !reflect.DeepEqual(f.keys[dnsKey(svc1)], want) {
		t.Errorf("svc1 restored %v, want %v", f.keys[dnsKey(svc1)], want)
	}
}

// captureLog sends the log to a buffer until the test ends.
func captureLog(t *testing.T) *strings.Builder {
	t.Helper()
	var b strings.Builder
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &b
}
