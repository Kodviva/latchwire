package netcfg

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const srcValidMarkRead = "sysctl -n net.ipv4.conf.all.src_valid_mark"

// render returns a plan's commands in apply order and the undo commands in
// the order Remove runs them (reverse), persistent ones marked with "P ".
func render(ss []step) (do, undo []string) {
	for _, s := range ss {
		do = append(do, s.do.String())
	}
	for i := len(ss) - 1; i >= 0; i-- {
		if u := ss[i].undo; u != nil {
			p := "  "
			if u.Persistent {
				p = "P "
			}
			undo = append(undo, p+u.String())
		}
	}
	return
}

func TestLinuxFullTunnelPlan(t *testing.T) {
	ss := planLinuxFullTunnel("wg0", 51820, true, true, pfx("10.0.0.2/32", "fd00::2/128"), "0")
	do, undo := render(ss)
	wantDo := []string{
		"sysctl -q net.ipv4.conf.all.src_valid_mark=1",
		"ip -4 route add 0.0.0.0/0 dev wg0 table 51820",
		"ip -4 rule add not fwmark 51820 table 51820 protocol 251",
		"ip -4 rule add table main suppress_prefixlength 0 protocol 251",
		"ip -6 route add ::/0 dev wg0 table 51820",
		"ip -6 rule add not fwmark 51820 table 51820 protocol 251",
		"ip -6 rule add table main suppress_prefixlength 0 protocol 251",
		"nft -f -",
	}
	// The table route goes with the interface, so it is not persistent;
	// rules, the sysctl and the nft table outlive it.
	wantUndo := []string{
		"P nft -f -",
		"P ip -6 rule del table main suppress_prefixlength 0 protocol 251",
		"P ip -6 rule del not fwmark 51820 table 51820 protocol 251",
		"  ip -6 route del ::/0 dev wg0 table 51820",
		"P ip -4 rule del table main suppress_prefixlength 0 protocol 251",
		"P ip -4 rule del not fwmark 51820 table 51820 protocol 251",
		"  ip -4 route del 0.0.0.0/0 dev wg0 table 51820",
		"P sysctl -q net.ipv4.conf.all.src_valid_mark=0",
	}
	if !reflect.DeepEqual(do, wantDo) {
		t.Errorf("apply:\n%q\nwant:\n%q", do, wantDo)
	}
	if !reflect.DeepEqual(undo, wantUndo) {
		t.Errorf("undo:\n%q\nwant:\n%q", undo, wantUndo)
	}
	nft := ss[len(ss)-1]
	if nft.missing == "" {
		t.Error("the nft step must be skipped when nft is not installed")
	}
	// The nft undo succeeds whether or not the table is still there.
	if got, want := string(nft.undo.Stdin), "table inet latchwire_rp_wg0 {}\ndelete table inet latchwire_rp_wg0\n"; got != want {
		t.Errorf("nft undo script %q, want %q", got, want)
	}
	// Every rule Latchwire adds or deletes carries its protocol tag, so
	// an identical rule of another tool is never removed.
	for _, s := range ss {
		for _, st := range []*Step{&s.do, s.undo} {
			if st != nil && slices.Contains(st.Args, "rule") && !strings.HasSuffix(st.String(), " protocol 251") {
				t.Errorf("%q lacks protocol 251", st)
			}
		}
	}
	script := string(nft.do.Stdin)
	for _, want := range []string{
		"table inet latchwire_rp_wg0 {",
		"delete table inet latchwire_rp_wg0\n",
		"type filter hook prerouting priority -300; policy accept;",
		`iifname != "wg0" iifname != "lo" ip daddr 10.0.0.2 drop`,
		`iifname != "wg0" iifname != "lo" ip6 daddr fd00::2 drop`,
		"type filter hook output priority -150; policy accept;",
		"meta mark 51820 ct mark set meta mark",
		"type filter hook prerouting priority -150; policy accept;",
		"meta l4proto udp ct mark 51820 meta mark set ct mark",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("nft script lacks %q:\n%s", want, script)
		}
	}

	// IPv4 only: no IPv6 rules; IPv6 only: no sysctl (it is IPv4's).
	do, _ = render(planLinuxFullTunnel("wg0", 51821, true, false, pfx("10.0.0.2/32"), "0"))
	for _, c := range do {
		if strings.Contains(c, "-6") {
			t.Errorf("IPv4-only plan has %q", c)
		}
	}
	do, _ = render(planLinuxFullTunnel("wg0", 51821, false, true, pfx("fd00::2/128"), "0"))
	if do[0] != "ip -6 route add ::/0 dev wg0 table 51821" {
		t.Errorf("IPv6-only plan starts with %q", do[0])
	}
}

func TestLinuxTablePicksFirstFree(t *testing.T) {
	// A table only a rule looks up (its routes gone, e.g. with a stale
	// rule left by another tunnel or tool) is not free either.
	r := &recorder{out: map[string]string{
		"ip -4 rule show": "0:\tfrom all lookup local\n32765:\tnot from all fwmark 0xca6c lookup 51820 proto 251\n32766:\tfrom all lookup main\n",
		"ip -6 rule show": "32765:\tfrom all fwmark 0x1 lookup 51821\n",
	}}
	if got, err := LinuxTable(ctx, r); err != nil || got != 51822 {
		t.Fatalf("LinuxTable = %d, %v; want 51822 (51820 and 51821 looked up by rules)", got, err)
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "table 51820") || strings.Contains(c, "table 51821") {
			t.Errorf("probed a table a rule uses: %q", c)
		}
	}
	if _, err := LinuxTable(ctx, &recorder{failOn: "ip -4 rule show"}); err == nil {
		t.Fatal("LinuxTable succeeded although ip rule failed")
	}

	r = &recorder{out: map[string]string{
		"ip -4 route show table 51820": "default dev other scope link \n",
		"ip -6 route show table 51821": "default dev other metric 1024 pref medium\n",
	}}
	got, err := LinuxTable(ctx, r)
	if err != nil || got != 51822 {
		t.Fatalf("LinuxTable = %d, %v; want 51822 (51820 has IPv4 routes, 51821 IPv6)", got, err)
	}
	// Free at once.
	if got, err := LinuxTable(ctx, &recorder{}); err != nil || got != 51820 {
		t.Fatalf("LinuxTable = %d, %v; want 51820", got, err)
	}
	// A table that was never created is free: recent kernels fail the
	// query instead of printing nothing.
	r = &recorder{failOn: "ip -4 route show table 5182", failErr: errors.New("exit status 2: Error: ipv4: FIB table does not exist.\nDump terminated")}
	if got, err := LinuxTable(ctx, r); err != nil || got != 51820 {
		t.Fatalf("LinuxTable with no such table = %d, %v; want 51820", got, err)
	}
	// ip itself failing is an error, not a free table.
	if _, err := LinuxTable(ctx, &recorder{failOn: "ip -4 route show"}); err == nil {
		t.Fatal("LinuxTable succeeded although ip failed")
	}
	// IPv6 disabled on the host: its error does not block the choice.
	if got, err := LinuxTable(ctx, &recorder{failOn: "ip -6"}); err != nil || got != 51820 {
		t.Fatalf("LinuxTable without IPv6 = %d, %v; want 51820", got, err)
	}
}

func TestLinuxSrcValidMarkRestored(t *testing.T) {
	full := plan("wg0", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	full.FwMark = 51820
	for _, tc := range []struct {
		prev     string
		wantUndo string // "" = no sysctl change at all
	}{
		{"0\n", "sysctl -q net.ipv4.conf.all.src_valid_mark=0"},
		{"1\n", ""},
		// Unreadable: restore the kernel default.
		{"", "sysctl -q net.ipv4.conf.all.src_valid_mark=0"},
	} {
		j, _ := newJournal(t)
		r := &recorder{out: map[string]string{srcValidMarkRead: tc.prev}}
		if tc.prev == "" {
			r.failOn = srcValidMarkRead
		}
		if _, err := newLinux(r, j).Apply(ctx, full); err != nil {
			t.Fatalf("prev %q: %v", tc.prev, err)
		}
		var set, undo []string
		for _, c := range r.cmds {
			if strings.HasPrefix(c, "sysctl -q") {
				set = append(set, c)
			}
		}
		for _, s := range j.Entries()["wg0"] {
			if s.Name == "sysctl" {
				undo = append(undo, s.String())
				if !s.Persistent {
					t.Errorf("prev %q: sysctl undo not persistent", tc.prev)
				}
			}
		}
		if tc.wantUndo == "" {
			if len(set) != 0 || len(undo) != 0 {
				t.Errorf("prev %q: set %q undo %q, want neither", tc.prev, set, undo)
			}
			continue
		}
		if !reflect.DeepEqual(set, []string{"sysctl -q net.ipv4.conf.all.src_valid_mark=1"}) ||
			!reflect.DeepEqual(undo, []string{tc.wantUndo}) {
			t.Errorf("prev %q: set %q undo %q, want undo %q", tc.prev, set, undo, tc.wantUndo)
		}
	}
	// A value other than a number is not written back: the kernel
	// default 0 is restored instead.
	j, _ := newJournal(t)
	if _, err := newLinux(&recorder{out: map[string]string{srcValidMarkRead: "1; reboot\n"}}, j).Apply(ctx, full); err != nil {
		t.Fatal(err)
	}
	var undo []string
	for _, s := range j.Entries()["wg0"] {
		if s.Name == "sysctl" {
			undo = append(undo, s.String())
		}
	}
	if want := []string{"sysctl -q net.ipv4.conf.all.src_valid_mark=0"}; !reflect.DeepEqual(undo, want) {
		t.Errorf("sysctl undo %q, want %q", undo, want)
	}
}

func TestFullTunnelNoLongerRejected(t *testing.T) {
	r := &recorder{out: map[string]string{
		srcValidMarkRead:               "0\n",
		"ip -4 route show table 51820": "default dev x\n",
	}}
	j, _ := newJournal(t)
	a, err := newLinux(r, j).Apply(ctx, plan("wg0", pfx("10.0.0.2/24", "fd00::2/128"), pfx("10.0.0.0/24", "0.0.0.0/0", "::/0")))
	if err != nil {
		t.Fatal(err)
	}
	if want := (Applied{FullTunnel: true, Table: 51821, RPFilter: true, DNS: DNSOutcomeNone}); a != want {
		t.Errorf("Applied = %+v, want %+v", a, want)
	}
	want := []string{
		"ip -4 rule show",
		"ip -6 rule show",
		"ip -4 route show table 51820",
		"ip -4 route show table 51821",
		"ip -6 route show table 51821",
		srcValidMarkRead,
		"ip address add 10.0.0.2/24 dev wg0",
		"ip address add fd00::2/128 dev wg0",
		"ip link set wg0 up",
		"sysctl -q net.ipv4.conf.all.src_valid_mark=1",
		"ip -4 route add 0.0.0.0/0 dev wg0 table 51821",
		"ip -4 rule add not fwmark 51821 table 51821 protocol 251",
		"ip -4 rule add table main suppress_prefixlength 0 protocol 251",
		"ip -6 route add ::/0 dev wg0 table 51821",
		"ip -6 rule add not fwmark 51821 table 51821 protocol 251",
		"ip -6 rule add table main suppress_prefixlength 0 protocol 251",
		"nft -f -",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	if !strings.Contains(r.stdin["nft -f -"], "table inet latchwire_rp_wg0 {") {
		t.Errorf("nft read %q", r.stdin["nft -f -"])
	}

	// A table chosen by the caller (the daemon, which also needs it for the
	// fwmark) is used without probing.
	r = &recorder{}
	p := plan("wg0", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	p.FwMark = 51830
	if a, err := newLinux(r, nil).Apply(ctx, p); err != nil || a.Table != 51830 {
		t.Fatalf("Apply = %+v, %v; want table 51830", a, err)
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "route show") {
			t.Errorf("probed tables although FwMark was given: %q", c)
		}
	}

	// A split tunnel reports no full tunnel.
	if a, err := newLinux(&recorder{}, nil).Apply(ctx, plan("wg0", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err != nil || a.FullTunnel || a.Table != 0 {
		t.Fatalf("split Apply = %+v, %v", a, err)
	}
}

// P3: without nft the full tunnel still comes up, without the reverse-path
// table, and says so.
func TestLinuxFullTunnelWithoutNft(t *testing.T) {
	j, _ := newJournal(t)
	r := &recorder{missing: "nft"}
	p := plan("wg0", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	p.FwMark = 51820
	c := newLinux(r, j)
	a, err := c.Apply(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if !a.FullTunnel || a.RPFilter {
		t.Errorf("Applied = %+v, want a full tunnel without RPFilter", a)
	}
	for _, s := range j.Entries()["wg0"] {
		if s.Name == "nft" {
			t.Errorf("journal keeps %q although nft never ran", s)
		}
	}
	r.cmds = nil
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range r.cmds {
		if strings.HasPrefix(cmd, "nft") {
			t.Errorf("Remove ran %q", cmd)
		}
	}
	// Any other failure of nft is a failure of the full tunnel.
	r = &recorder{failOn: "nft"}
	if _, err := newLinux(r, nil).Apply(ctx, p); err == nil {
		t.Fatal("Apply succeeded although nft failed")
	}
}

func fullPlan() Plan {
	p := plan("wg0", pfx("10.0.0.2/32"), pfx("0.0.0.0/0"))
	p.FwMark = 51820
	return p
}

func journalStrings(j *Journal, owner string) []string {
	var out []string
	for _, s := range j.Entries()[owner] {
		out = append(out, s.String())
	}
	return out
}

// P7: a persistent step whose undo fails stays in the journal for the next
// start; a non-persistent one is forgotten.
func TestRemoveKeepsFailedPersistentSteps(t *testing.T) {
	j, path := newJournal(t)
	r := &recorder{out: map[string]string{srcValidMarkRead: "0\n"}}
	c := newLinux(r, j)
	if _, err := c.Apply(ctx, fullPlan()); err != nil {
		t.Fatal(err)
	}
	r.failOn = "ip -4 r" // the rules (persistent) and the table route (not)
	r.failErr = errors.New("exit status 2: RTNETLINK answers: Operation not permitted")
	if err := c.Remove(ctx); err == nil {
		t.Fatal("Remove error = nil, want the failures reported")
	}
	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip -4 rule del not fwmark 51820 table 51820 protocol 251",
		"ip -4 rule del table main suppress_prefixlength 0 protocol 251",
	}
	if got := journalStrings(j2, "wg0"); !reflect.DeepEqual(got, want) {
		t.Fatalf("journal after Remove:\n%q\nwant:\n%q", got, want)
	}
	for _, s := range j2.Entries()["wg0"] {
		if !s.Persistent {
			t.Errorf("%s lost its persistent flag", s)
		}
	}

	// The next Apply for the same interface retries them first, and keeps
	// what still fails ahead of its own steps.
	r = &recorder{out: map[string]string{srcValidMarkRead: "0\n"}, failOn: "ip -4 rule del table main",
		failErr: errors.New("exit status 2: RTNETLINK answers: Operation not permitted")}
	c = newLinux(r, j)
	if _, err := c.Apply(ctx, fullPlan()); err != nil {
		t.Fatal(err)
	}
	if got := r.cmds[:2]; !reflect.DeepEqual(got, []string{want[1], want[0]}) {
		t.Errorf("first commands %q, want the kept steps retried in reverse", got)
	}
	got := journalStrings(j, "wg0")
	if len(got) == 0 || got[0] != want[1] || strings.Count(strings.Join(got, "\n"), want[0]) != 1 {
		t.Errorf("journal after Apply: %q, want the still-failing step first", got)
	}
	// Remove now succeeds for everything, the carried step included.
	r.failOn = ""
	r.cmds = nil
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if r.cmds[len(r.cmds)-1] != want[1] {
		t.Errorf("Remove did not retry the carried step last: %q", r.cmds)
	}
	if e := j.Entries(); len(e) != 0 {
		t.Fatalf("journal after clean Remove: %v", e)
	}
}

// P7: Remove with a cancelled context forgets nothing.
func TestRemoveCancelledForgetsNothing(t *testing.T) {
	j, path := newJournal(t)
	r := &recorder{}
	c := newLinux(r, j)
	if _, err := c.Apply(ctx, fullPlan()); err != nil {
		t.Fatal(err)
	}
	before := journalStrings(j, "wg0")
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	r.cmds = nil
	if err := c.Remove(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Remove error = %v, want context.Canceled", err)
	}
	if len(r.cmds) != 0 {
		t.Errorf("commands ran with a cancelled context: %q", r.cmds)
	}
	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := journalStrings(j2, "wg0"); !reflect.DeepEqual(got, before) {
		t.Fatalf("journal after cancelled Remove:\n%q\nwant unchanged:\n%q", got, before)
	}

	// Cancelled half-way: what ran is not forgotten either.
	j, path = newJournal(t)
	cctx, cancel = context.WithCancel(ctx)
	r = &recorder{}
	c = newLinux(r, j)
	if _, err := c.Apply(ctx, fullPlan()); err != nil {
		t.Fatal(err)
	}
	before = journalStrings(j, "wg0")
	r.cmds = nil
	r.onRun = func(string) { cancel() }
	if err := c.Remove(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Remove error = %v, want context.Canceled", err)
	}
	if len(r.cmds) != 1 {
		t.Errorf("commands after cancel: %q, want only the first", r.cmds)
	}
	j2, _ = OpenJournal(path)
	if got := journalStrings(j2, "wg0"); !reflect.DeepEqual(got, before) {
		t.Fatalf("journal after cancelled Remove:\n%q\nwant unchanged:\n%q", got, before)
	}
}

func TestRPTableName(t *testing.T) {
	for in, want := range map[string]string{
		"wg0":    "latchwire_rp_wg0",
		"my-vpn": "latchwire_rp_my-vpn",
		"Home_1": "latchwire_rp_Home_1",
		// Characters a tunnel name may hold but an nft name may not.
		"a=b": "latchwire_rpx_613d62",
		"a+b": "latchwire_rpx_612b62",
		"a.b": "latchwire_rpx_612e62",
	} {
		if got := rpTableName(in); got != want {
			t.Errorf("rpTableName(%q) = %q, want %q", in, got, want)
		}
	}
	// The interface name is quoted in the script, whatever it holds.
	ss := planLinuxFullTunnel("a=b", 51820, true, false, pfx("10.0.0.2/32"), "1")
	if s := string(ss[len(ss)-1].do.Stdin); !strings.Contains(s, `iifname != "a=b"`) || !strings.Contains(s, "table inet latchwire_rpx_613d62 {") {
		t.Errorf("script:\n%s", s)
	}
}

// An undo whose target is already gone (a rule another program such as
// systemd-networkd removed) succeeded: it is not reported, not kept and not
// retried, so it can never later remove a rule a newer tunnel added.
func TestAbsentRuleUndoForgotten(t *testing.T) {
	gone := errors.New("exit status 2: RTNETLINK answers: No such file or directory")
	j, path := newJournal(t)
	r := &recorder{}
	c := newLinux(r, j)
	if _, err := c.Apply(ctx, fullPlan()); err != nil {
		t.Fatal(err)
	}
	r.failOn, r.failErr = "ip -4 rule del", gone
	if err := c.Remove(ctx); err != nil {
		t.Fatalf("Remove = %v, want nil: the rules were already gone", err)
	}
	j2, _ := OpenJournal(path)
	if e := j2.Entries(); len(e) != 0 {
		t.Fatalf("journal after Remove: %v, want empty", e)
	}

	// The same for a kept step retried by Apply and for Cleanup.
	kept := Step{Name: "ip", Args: []string{"-4", "rule", "del", "not", "fwmark", "51820", "table", "51820", "protocol", "251"}, Persistent: true}
	j.Record("wg0", []Step{kept})
	r = &recorder{failOn: "ip -4 rule del", failErr: gone}
	c = newLinux(r, j)
	if _, err := c.Apply(ctx, fullPlan()); err != nil {
		t.Fatal(err)
	}
	if got := journalStrings(j, "wg0"); slices.Contains(got[:1], kept.String()) {
		t.Errorf("journal after Apply still carries the gone rule: %q", got)
	}
	j.Record("other", []Step{kept})
	if err := Cleanup(ctx, &recorder{failOn: "ip", failErr: gone}, j, func(o string) bool { return o == "wg0" }); err != nil {
		t.Errorf("Cleanup = %v, want nil for a gone rule", err)
	}

	// Any other failure is still a failure.
	if alreadyUndone(kept, errors.New("exit status 2: RTNETLINK answers: Operation not permitted")) {
		t.Error("EPERM taken for an absent rule")
	}
	if alreadyUndone(Step{Name: "ip", Args: []string{"route", "del", "x"}}, gone) {
		t.Error("only rule deletes are recognised")
	}
}
