package netcfg

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

// dnsSteps returns the journaled DNS undo steps of owner.
func dnsSteps(j *Journal, owner string) []string {
	var out []string
	for _, s := range j.Entries()[owner] {
		if isDNSUndo(s) {
			out = append(out, s.String())
		}
	}
	return out
}

// P18 on Linux (systemd-resolved): the primary tunnel is demoted to scoped
// DNS in place. The new role's system reads come first, then the old DNS is
// undone, then the new one applied; the journal holds one revert; the
// ownership is free for the full tunnel.
func TestLinuxSetDNSRoleDemotes(t *testing.T) {
	freshPrimaryDNS(t)
	stub := resolvFile(t, stubResolv)
	j, _ := newJournal(t)
	mk := func(r *recorder) *configurer {
		c := newLinux(r, j).(*configurer)
		c.dns = func(ctx2 context.Context, rr Runner, p Plan) ([]step, string, error) {
			return linuxDNS(ctx2, rr, stub, p)
		}
		return c
	}
	ra, rb := &recorder{}, &recorder{}
	a, b := mk(ra), mk(rb)
	pa := dnsPlan(DNSPrimary, "corp.example")
	pa.Addresses = pfx("10.0.0.2/32")
	pb := dnsPlan(DNSPrimary)
	pb.Iface, pb.Addresses = "wg1", pfx("10.9.0.2/32")
	if res, err := a.Apply(ctx, pa); err != nil || res.DNS != DNSOutcomeResolved {
		t.Fatalf("apply: %+v %v", res, err)
	}

	// The revert fails: nothing changes, the ownership stays (P13).
	ra.cmds, ra.failOn = nil, "resolvectl revert"
	if how, err := a.SetDNSRole(ctx, DNSScoped); err == nil || how != DNSOutcomeResolved {
		t.Fatalf("failing demotion: %q %v", how, err)
	}
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomePrimaryBusy {
		t.Fatalf("primary taken while the demotion failed: %+v %v", res, err)
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if got := dnsSteps(j, "wg0"); len(got) != 1 {
		t.Fatalf("journal after the failed demotion: %q", got)
	}

	ra.cmds, ra.failOn = nil, ""
	how, err := a.SetDNSRole(ctx, DNSScoped)
	if err != nil || how != DNSOutcomeResolved {
		t.Fatalf("demotion: %q %v", how, err)
	}
	want := []string{
		"resolvectl status",
		"resolvectl revert wg0",
		"resolvectl dns wg0 10.0.0.1 fd00::1",
		"resolvectl domain wg0 ~corp.example",
		"resolvectl default-route wg0 false",
	}
	if !reflect.DeepEqual(ra.cmds, want) {
		t.Errorf("ran:\n%q\nwant:\n%q", ra.cmds, want)
	}
	if got := dnsSteps(j, "wg0"); !reflect.DeepEqual(got, []string{"resolvectl revert wg0"}) {
		t.Errorf("journal %q", got)
	}
	// The same role again changes nothing.
	ra.cmds = nil
	if how, err := a.SetDNSRole(ctx, DNSScoped); err != nil || how != DNSOutcomeResolved || len(ra.cmds) != 0 {
		t.Errorf("same role: %q %v %q", how, err, ra.cmds)
	}
	// The full tunnel can have the primary now.
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomeResolved {
		t.Fatalf("primary after the demotion: %+v %v", res, err)
	}

	// Applying the new role fails after the old DNS was undone: what was
	// applied of it is undone, the error returned, the outcome is none.
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetDNSRole(ctx, DNSPrimary); err != nil {
		t.Fatal(err)
	}
	ra.cmds, ra.failOn = nil, "resolvectl domain"
	if how, err := a.SetDNSRole(ctx, DNSScoped); err == nil || how != DNSOutcomeNone {
		t.Fatalf("failing re-apply: %q %v", how, err)
	}
	want = []string{
		"resolvectl status",
		"resolvectl revert wg0",
		"resolvectl dns wg0 10.0.0.1 fd00::1",
		"resolvectl domain wg0 ~corp.example",
		"resolvectl revert wg0",
	}
	if !reflect.DeepEqual(ra.cmds, want) {
		t.Errorf("failing re-apply ran:\n%q\nwant:\n%q", ra.cmds, want)
	}
	if got := dnsSteps(j, "wg0"); len(got) != 0 {
		t.Errorf("journal after the failed re-apply: %q", got)
	}
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomeResolved {
		t.Fatalf("primary after the failed re-apply: %+v %v", res, err)
	}
	ra.failOn = ""
	if how, err := a.SetDNSRole(ctx, DNSScoped); err != nil || how != DNSOutcomeResolved {
		t.Fatalf("scoped again: %q %v", how, err)
	}

	// Without the DNS: only the revert.
	ra.cmds = nil
	if how, err := a.SetDNSRole(ctx, DNSNone); err != nil || how != DNSOutcomeNone {
		t.Fatalf("to none: %q %v", how, err)
	}
	if !reflect.DeepEqual(ra.cmds, []string{"resolvectl revert wg0"}) {
		t.Errorf("to none ran %q", ra.cmds)
	}
	if got := dnsSteps(j, "wg0"); len(got) != 0 {
		t.Errorf("journal after to none: %q", got)
	}
	// Remove still undoes the rest, and runs no DNS undo.
	ra.cmds = nil
	if err := a.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(ra.cmds, func(c string) bool { return c == "resolvectl revert wg0" }) {
		t.Errorf("Remove reverted DNS again: %q", ra.cmds)
	}
	if _, err := a.SetDNSRole(ctx, DNSScoped); err == nil {
		t.Error("SetDNSRole without an applied configuration succeeded")
	}
}

// P18 on macOS: the primary service's dictionary is restored, the scoped
// key written, and Refresh no longer follows the primary service.
func TestDarwinSetDNSRoleDemotes(t *testing.T) {
	f := newFakeStore(t)
	f.setPrimary(svc1)
	orig := fdict{"ServerAddresses": arr("192.168.1.1")}
	f.keys[dnsKey(svc1)] = maps2(orig)
	j, _ := newJournal(t)
	a := newDarwin(f, j).(*configurer)
	if res, err := a.Apply(ctx, darwinDNSPlan(DNSPrimary, "corp.example")); err != nil || res.DNS != DNSOutcomeScutilPrimary {
		t.Fatalf("apply: %+v %v", res, err)
	}
	how, err := a.SetDNSRole(ctx, DNSScoped)
	if err != nil || how != DNSOutcomeScutilScoped {
		t.Fatalf("demotion: %q %v", how, err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig) {
		t.Errorf("primary service %v, want the original %v", f.keys[dnsKey(svc1)], orig)
	}
	key := "State:/Network/Service/latchwire-utun7/DNS"
	want := fdict{"ServerAddresses": arr("10.0.0.1", "fd00::1"), "SupplementalMatchDomains": arr("corp.example")}
	if !reflect.DeepEqual(f.keys[key], want) {
		t.Errorf("scoped key %v, want %v", f.keys[key], want)
	}
	if got := scutilUndos(j, "utun7"); !reflect.DeepEqual(got, []string{"P remove " + key + "\n"}) {
		t.Errorf("journal %q", got)
	}
	if a.dn.dnsPrimary {
		t.Error("still following the primary service")
	}

	// The full tunnel takes the primary; the demoted one's Refresh
	// leaves it alone.
	b := newDarwin(f, j)
	pb := darwinDNSPlan(DNSPrimary)
	pb.Iface, pb.Addresses = "utun8", pfx("10.9.0.2/32")
	pb.DNS = []netip.Addr{netip.MustParseAddr("10.9.0.1")}
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomeScutilPrimary {
		t.Fatalf("primary after the demotion: %+v %v", res, err)
	}
	n := len(f.writes())
	if err := a.Refresh(ctx); err != nil || len(f.writes()) != n {
		t.Errorf("demoted Refresh wrote: %v %q", err, f.writes()[n:])
	}
	if err := a.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys[key]; ok {
		t.Error("scoped key left after Remove")
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.keys[dnsKey(svc1)], orig) {
		t.Errorf("restored %v, want %v", f.keys[dnsKey(svc1)], orig)
	}
}
