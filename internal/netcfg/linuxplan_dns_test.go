package netcfg

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"net/netip"
)

func resolvFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if content != "" {
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

const stubResolv = "# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0 trust-ad\n"

func dnsPlan(role DNSRole, search ...string) Plan {
	return Plan{
		Iface: "wg0", DNSRole: role, DNSSearch: search,
		DNS: []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")},
	}
}

func TestLinuxDNSResolvedPrimary(t *testing.T) {
	r := &recorder{}
	ss, got, err := linuxDNS(ctx, r, resolvFile(t, stubResolv), dnsPlan(DNSPrimary, "corp.example", "lan"))
	if err != nil || got != DNSOutcomeResolved {
		t.Fatalf("got %q, %v", got, err)
	}
	if !reflect.DeepEqual(r.cmds, []string{"resolvectl status"}) {
		t.Errorf("detection ran %q", r.cmds)
	}
	// A status that fails (resolved not answering yet) does not matter
	// when resolv.conf lists the stub.
	if _, got, err := linuxDNS(ctx, &recorder{failOn: "resolvectl"}, resolvFile(t, stubResolv), dnsPlan(DNSPrimary)); err != nil || got != DNSOutcomeResolved {
		t.Errorf("stub with failing status: %q, %v", got, err)
	}
	do, undo := render(ss)
	wantDo := []string{
		"resolvectl dns wg0 10.0.0.1 fd00::1",
		"resolvectl domain wg0 corp.example lan ~.",
		"resolvectl default-route wg0 true",
	}
	// One revert undoes all three, and it goes with the interface: not
	// persistent.
	wantUndo := []string{"  resolvectl revert wg0"}
	if !reflect.DeepEqual(do, wantDo) {
		t.Errorf("apply:\n%q\nwant:\n%q", do, wantDo)
	}
	if !reflect.DeepEqual(undo, wantUndo) {
		t.Errorf("undo:\n%q\nwant:\n%q", undo, wantUndo)
	}
	// Without search domains the primary route is still set.
	ss, _, err = linuxDNS(ctx, &recorder{}, resolvFile(t, stubResolv), dnsPlan(DNSPrimary))
	if err != nil {
		t.Fatal(err)
	}
	if do, _ = render(ss); do[1] != "resolvectl domain wg0 ~." {
		t.Errorf("domain step %q", do[1])
	}
}

func TestLinuxDNSResolvedScoped(t *testing.T) {
	// No stub in resolv.conf: resolved is found through resolvectl status.
	r := &recorder{}
	ss, got, err := linuxDNS(ctx, r, resolvFile(t, "nameserver 192.168.1.1\n"), dnsPlan(DNSScoped, "corp.example", "lan"))
	if err != nil || got != DNSOutcomeResolved {
		t.Fatalf("got %q, %v", got, err)
	}
	if !reflect.DeepEqual(r.cmds, []string{"resolvectl status"}) {
		t.Errorf("detection ran %q", r.cmds)
	}
	do, undo := render(ss)
	wantDo := []string{
		"resolvectl dns wg0 10.0.0.1 fd00::1",
		"resolvectl domain wg0 ~corp.example ~lan",
		"resolvectl default-route wg0 false",
	}
	if !reflect.DeepEqual(do, wantDo) {
		t.Errorf("apply:\n%q\nwant:\n%q", do, wantDo)
	}
	if !reflect.DeepEqual(undo, []string{"  resolvectl revert wg0"}) {
		t.Errorf("undo %q", undo)
	}
	// resolv.conf missing altogether: same.
	if _, got, err = linuxDNS(ctx, &recorder{}, resolvFile(t, ""), dnsPlan(DNSScoped, "lan")); err != nil || got != DNSOutcomeResolved {
		t.Errorf("no resolv.conf: got %q, %v", got, err)
	}
}

const openresolvVersion = "openresolv 3.12.0\nCopyright (c) 2007-2020 Roy Marples\n"

func TestLinuxDNSResolvconfFallback(t *testing.T) {
	// openresolv: resolved is not there (resolv.conf is plain and
	// resolvectl fails); its flags are used.
	r := &recorder{failOn: "resolvectl", out: map[string]string{"resolvconf --version": openresolvVersion}}
	ss, got, err := linuxDNS(ctx, r, resolvFile(t, "nameserver 192.168.1.1\n"), dnsPlan(DNSPrimary, "corp.example", "lan"))
	if err != nil || got != DNSOutcomeResolvconf {
		t.Fatalf("got %q, %v", got, err)
	}
	do, undo := render(ss)
	if !reflect.DeepEqual(do, []string{"resolvconf -a wg0 -m 0 -x"}) {
		t.Errorf("apply %q", do)
	}
	if want := "nameserver 10.0.0.1\nnameserver fd00::1\nsearch corp.example lan\n"; string(ss[0].do.Stdin) != want {
		t.Errorf("stdin %q, want %q", ss[0].do.Stdin, want)
	}
	// The entry lives in /run/resolvconf, not on the link, and -f makes
	// the delete succeed when it is gone.
	if !reflect.DeepEqual(undo, []string{"P resolvconf -d wg0 -f"}) {
		t.Errorf("undo %q", undo)
	}
	// A missing search list leaves out the search line.
	ss, _, _ = linuxDNS(ctx, &recorder{failOn: "resolvectl"}, resolvFile(t, ""), dnsPlan(DNSPrimary))
	if want := "nameserver 10.0.0.1\nnameserver fd00::1\n"; string(ss[0].do.Stdin) != want {
		t.Errorf("stdin %q, want %q", ss[0].do.Stdin, want)
	}

	// Scoped DNS cannot be expressed: nothing is applied, and it is said.
	for _, out := range []string{openresolvVersion, "Debian resolvconf 1.91+nmu1\n"} {
		r = &recorder{failOn: "resolvectl", out: map[string]string{"resolvconf --version": out}}
		ss, got, err = linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSScoped, "lan"))
		if err != nil || got != DNSOutcomeScopedUnsupported || len(ss) != 0 {
			t.Errorf("scoped: %q %v steps %d", got, err, len(ss))
		}
	}
}

// The Debian/Ubuntu resolvconf has no -m, -x or -f: it must get plain
// "-a IFACE" and "-d IFACE" (its delete of an unknown interface succeeds).
func TestLinuxDNSClassicResolvconf(t *testing.T) {
	// Classic resolvconf has no exclusive mode (P11): primary DNS is
	// reported as shared, with a warning saying why.
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	if _, got, _ := linuxDNS(ctx, &recorder{failOn: "resolvectl"}, resolvFile(t, ""), dnsPlan(DNSPrimary)); got != DNSOutcomeResolvconfShared {
		t.Errorf("classic primary: %q", got)
	}
	if !strings.Contains(logs.String(), "not exclusive") || !strings.Contains(logs.String(), "kill switch") {
		t.Errorf("warning %q", logs.String())
	}
	// openresolv is exclusive: no warning.
	logs.Reset()
	r := &recorder{failOn: "resolvectl", out: map[string]string{"resolvconf --version": openresolvVersion}}
	if _, got, _ := linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSPrimary)); got != DNSOutcomeResolvconf || logs.Len() != 0 {
		t.Errorf("openresolv: %q, log %q", got, logs.String())
	}

	for name, r := range map[string]*recorder{
		"debian version":        {failOn: "resolvectl", out: map[string]string{"resolvconf --version": "Debian resolvconf 1.91+nmu1\nCopyright: \n"}},
		"silent version":        {failOn: "resolvectl"},
		"version not supported": {failOn: "resolvectl", fail: map[string]error{"resolvconf --version": errors.New("exit status 1")}},
		"openresolv not first":  {failOn: "resolvectl", out: map[string]string{"resolvconf --version": "Debian resolvconf (openresolv compatible)\n"}},
	} {
		ss, got, err := linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSPrimary, "lan"))
		if err != nil || got != DNSOutcomeResolvconfShared {
			t.Fatalf("%s: got %q, %v", name, got, err)
		}
		do, undo := render(ss)
		if !reflect.DeepEqual(do, []string{"resolvconf -a wg0"}) {
			t.Errorf("%s: apply %q", name, do)
		}
		if !reflect.DeepEqual(undo, []string{"P resolvconf -d wg0"}) {
			t.Errorf("%s: undo %q", name, undo)
		}
		if want := "nameserver 10.0.0.1\nnameserver fd00::1\nsearch lan\n"; string(ss[0].do.Stdin) != want {
			t.Errorf("%s: stdin %q", name, ss[0].do.Stdin)
		}
	}
}

// openresolv found through -V when --version fails or says nothing useful;
// the classic resolvconf rejects -V.
func TestLinuxDNSOpenresolvDashV(t *testing.T) {
	vars := "DOMAIN=''\nSEARCH=''\nNAMESERVERS=''\nLOCALNAMESERVERS=''\nDOMAINS=''\n"
	for name, r := range map[string]*recorder{
		"--version fails, -V prints variables": {failOn: "resolvectl", fail: map[string]error{"resolvconf --version": errors.New("exit status 1")},
			out: map[string]string{"resolvconf -V": vars}},
		"--version silent, -V prints version": {failOn: "resolvectl", out: map[string]string{"resolvconf -V": "openresolv 3.5.0\n"}},
	} {
		ss, got, err := linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSPrimary))
		if err != nil || got != DNSOutcomeResolvconf {
			t.Fatalf("%s: %q, %v", name, got, err)
		}
		if do, _ := render(ss); !reflect.DeepEqual(do, []string{"resolvconf -a wg0 -m 0 -x"}) {
			t.Errorf("%s: apply %q", name, do)
		}
	}
	// Both fail (classic rejects -V): classic.
	r := &recorder{failOn: "resolvectl", fail: map[string]error{
		"resolvconf --version": errors.New("exit status 1"),
		"resolvconf -V":        errors.New("exit status 99"),
	}}
	if _, got, err := linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSPrimary)); err != nil || got != DNSOutcomeResolvconfShared {
		t.Errorf("classic: %q, %v", got, err)
	}
	// Not installed: --version says so and -V is not tried.
	r = &recorder{failOn: "resolvectl", fail: map[string]error{"resolvconf --version": exec.ErrNotFound}}
	if _, _, err := linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSPrimary)); !errors.Is(err, ErrDNSUnsupported) || slices.Contains(r.cmds, "resolvconf -V") {
		t.Errorf("absent: %v, ran %q", err, r.cmds)
	}
}

// Either resolvconf's delete is idempotent, so a persistent undo never
// stays stuck in the journal; the command being gone counts as undone.
func TestLinuxResolvconfUndoRetired(t *testing.T) {
	for _, openresolv := range []bool{true, false} {
		ss := planResolvconf(dnsPlan(DNSPrimary), openresolv)
		u := *ss[0].undo
		if !u.Persistent {
			t.Error("resolvconf undo must be persistent")
		}
		// Run through the real undo path: a missing resolvconf succeeds,
		// another failure does not.
		if err := runUndo(ctx, &recorder{missing: "resolvconf"}, u); err != nil {
			t.Errorf("openresolv=%v: command gone: %v", openresolv, err)
		}
		if err := runUndo(ctx, &recorder{failOn: "resolvconf"}, u); err == nil {
			t.Errorf("openresolv=%v: a failing delete reported success", openresolv)
		}
		r := &recorder{}
		if err := runUndo(ctx, r, u); err != nil || len(r.cmds) != 1 {
			t.Errorf("openresolv=%v: %v %q", openresolv, err, r.cmds)
		}
	}
}

func TestLinuxDNSRejectsZonedServers(t *testing.T) {
	p := dnsPlan(DNSPrimary)
	p.DNS = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fe80::1%eth0")}
	r := &recorder{}
	ss, _, err := linuxDNS(ctx, r, resolvFile(t, stubResolv), p)
	if err == nil || !strings.Contains(err.Error(), "fe80::1%eth0") || len(ss) != 0 || len(r.cmds) != 0 {
		t.Errorf("err %v, %d steps, ran %q", err, len(ss), r.cmds)
	}
	// No DNS role: the address is not used, so it is not an error.
	p.DNSRole = DNSNone
	if _, got, err := linuxDNS(ctx, r, resolvFile(t, ""), p); err != nil || got != DNSOutcomeNone {
		t.Errorf("no role: %q, %v", got, err)
	}
}

// A stub in resolv.conf without the resolvectl command to drive it is not
// systemd-resolved we can use: fall through to resolvconf, then give up.
func TestLinuxDNSStubWithoutResolvectl(t *testing.T) {
	r := &recorder{missing: "resolvectl", out: map[string]string{"resolvconf --version": openresolvVersion}}
	ss, got, err := linuxDNS(ctx, r, resolvFile(t, stubResolv), dnsPlan(DNSPrimary))
	if err != nil || got != DNSOutcomeResolvconf || ss[0].do.Name != "resolvconf" {
		t.Errorf("got %q, %v", got, err)
	}
	r = &recorder{missing: "resolvectl", fail: map[string]error{"resolvconf --version": exec.ErrNotFound}}
	if _, _, err := linuxDNS(ctx, r, resolvFile(t, stubResolv), dnsPlan(DNSPrimary)); !errors.Is(err, ErrDNSUnsupported) {
		t.Errorf("err %v, want ErrDNSUnsupported", err)
	}
}

func TestLinuxDNSUnsupported(t *testing.T) {
	r := &recorder{failOn: "resolvectl"}
	r.fail = map[string]error{"resolvconf --version": exec.ErrNotFound}
	ss, got, err := linuxDNS(ctx, r, resolvFile(t, "nameserver 192.168.1.1\n"), dnsPlan(DNSPrimary, "lan"))
	if !errors.Is(err, ErrDNSUnsupported) || len(ss) != 0 {
		t.Fatalf("got %q, %v, %d steps", got, err, len(ss))
	}
	// resolvectl not installed either.
	r = &recorder{missing: "resolvectl"}
	r.fail = map[string]error{"resolvconf --version": exec.ErrNotFound}
	if _, _, err = linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSScoped, "lan")); !errors.Is(err, ErrDNSUnsupported) {
		t.Errorf("err %v", err)
	}
}

func TestLinuxDNSNothingToDo(t *testing.T) {
	r := &recorder{}
	for _, p := range []Plan{
		{Iface: "wg0"},
		{Iface: "wg0", DNSRole: DNSNone, DNS: dnsPlan(0).DNS},
		{Iface: "wg0", DNSRole: DNSPrimary}, // no servers
	} {
		ss, got, err := linuxDNS(ctx, r, resolvFile(t, ""), p)
		if err != nil || got != DNSOutcomeNone || len(ss) != 0 {
			t.Errorf("%+v: %q %v %d", p, got, err, len(ss))
		}
	}
	if len(r.cmds) != 0 {
		t.Errorf("ran %q", r.cmds)
	}
}

func TestLinuxDNSRejectsBadDomains(t *testing.T) {
	for _, d := range []string{"a\nnameserver 6.6.6.6", "-x", "a b", "~", ""} {
		if _, _, err := linuxDNS(ctx, &recorder{}, resolvFile(t, stubResolv), dnsPlan(DNSPrimary, d)); err == nil {
			t.Errorf("domain %q accepted", d)
		}
	}
}

func TestLinuxDNSUndoAlreadyGone(t *testing.T) {
	revert := Step{Name: "resolvectl", Args: []string{"revert", "wg0"}}
	for _, msg := range []string{
		"Failed to resolve interface \"wg0\": No such device",
		"Failed to revert interface configuration: No such device",
	} {
		if !alreadyUndone(revert, errors.New("exit status 1: "+msg)) {
			t.Errorf("%q not treated as gone", msg)
		}
	}
	if alreadyUndone(revert, errors.New("exit status 1: Access denied")) {
		t.Error("other failures must stay failures")
	}
	del := Step{Name: "resolvconf", Args: []string{"-d", "wg0", "-f"}}
	if !alreadyUndone(del, exec.ErrNotFound) || alreadyUndone(del, errors.New("boom")) {
		t.Error("resolvconf delete: only a missing command is gone")
	}
}

// Through the Configurer: DNS comes after the link is up, is reported, and
// the journal holds the revert.
func TestLinuxApplyDNS(t *testing.T) {
	freshPrimaryDNS(t)
	r := &recorder{}
	c := newLinux(r, nil).(*configurer)
	c.dns = func(ctx2 context.Context, rr Runner, p Plan) ([]step, string, error) {
		return linuxDNS(ctx2, rr, resolvFile(t, stubResolv), p)
	}
	p := dnsPlan(DNSPrimary)
	p.Addresses = pfx("10.0.0.2/32")
	res, err := c.Apply(ctx, p)
	if err != nil || res.DNS != DNSOutcomeResolved {
		t.Fatalf("%+v %v", res, err)
	}
	want := []string{
		"resolvectl status", // read first: nothing changes if DNS is unsupported
		"ip address add 10.0.0.2/32 dev wg0",
		"ip link set wg0 up",
		"resolvectl dns wg0 10.0.0.1 fd00::1",
		"resolvectl domain wg0 ~.",
		"resolvectl default-route wg0 true",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Errorf("ran:\n%q\nwant:\n%q", r.cmds, want)
	}
	// Link already gone at Remove: revert fails as "No such device" and
	// the remove still succeeds.
	r.failOn = "resolvectl revert"
	r.failErr = errors.New("exit status 1: Failed to resolve interface \"wg0\": No such device")
	if err := c.Remove(ctx); err != nil {
		t.Errorf("remove: %v", err)
	}
}

func TestLinuxApplyDNSUnsupportedRunsNothing(t *testing.T) {
	freshPrimaryDNS(t)
	r := &recorder{failOn: "resolvectl"}
	r.fail = map[string]error{"resolvconf --version": exec.ErrNotFound}
	c := newLinux(r, nil).(*configurer)
	c.dns = func(ctx2 context.Context, rr Runner, p Plan) ([]step, string, error) {
		return linuxDNS(ctx2, rr, resolvFile(t, "nameserver 1.1.1.1\n"), p)
	}
	p := dnsPlan(DNSPrimary)
	p.Addresses = pfx("10.0.0.2/32")
	if _, err := c.Apply(ctx, p); !errors.Is(err, ErrDNSUnsupported) {
		t.Fatalf("err %v", err)
	}
	for _, cmd := range r.cmds {
		if strings.HasPrefix(cmd, "ip ") {
			t.Errorf("changed the system before failing: %q", r.cmds)
		}
	}
}

// P12 on Linux: a second DNSPrimary tunnel applies no DNS; the owner's
// Remove releases it, and so does a failed Apply.
func TestLinuxDNSPrimaryOneOwner(t *testing.T) {
	freshPrimaryDNS(t)
	stub := resolvFile(t, stubResolv)
	mk := func(r *recorder) *configurer {
		c := newLinux(r, nil).(*configurer)
		c.dns = func(ctx2 context.Context, rr Runner, p Plan) ([]step, string, error) {
			return linuxDNS(ctx2, rr, stub, p)
		}
		return c
	}
	ra, rb := &recorder{}, &recorder{}
	a, b := mk(ra), mk(rb)
	pa := dnsPlan(DNSPrimary)
	pa.Addresses = pfx("10.0.0.2/32")
	pb := pa
	pb.Iface = "wg1"
	if res, err := a.Apply(ctx, pa); err != nil || res.DNS != DNSOutcomeResolved {
		t.Fatalf("first: %+v %v", res, err)
	}
	res, err := b.Apply(ctx, pb)
	if err != nil || res.DNS != DNSOutcomePrimaryBusy {
		t.Fatalf("second: %+v %v", res, err)
	}
	for _, c := range rb.cmds {
		if strings.HasPrefix(c, "resolvectl") {
			t.Errorf("second tunnel ran %q", c)
		}
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	rb.cmds = nil
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomeResolved {
		t.Fatalf("after release: %+v %v", res, err)
	}
	if !slices.Contains(rb.cmds, "resolvectl dns wg1 10.0.0.1 fd00::1") {
		t.Errorf("ran %q", rb.cmds)
	}
	if err := b.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	// A rolled-back Apply releases it.
	ra.failOn = "resolvectl dns"
	if _, err := a.Apply(ctx, pa); err == nil {
		t.Fatal("failing Apply succeeded")
	}
	if res, err := b.Apply(ctx, pb); err != nil || res.DNS != DNSOutcomeResolved {
		t.Fatalf("after rollback: %+v %v", res, err)
	}
}
