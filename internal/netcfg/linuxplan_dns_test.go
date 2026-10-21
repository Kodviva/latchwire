package netcfg

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	if len(r.cmds) != 0 {
		t.Errorf("a stub resolv.conf needs no command to detect resolved, ran %q", r.cmds)
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

func TestLinuxDNSResolvconfFallback(t *testing.T) {
	// resolved is not there: resolv.conf is plain and resolvectl fails.
	r := &recorder{failOn: "resolvectl"}
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
	// The resolvconf entry lives in /run/resolvconf, not on the link, and
	// -f makes the delete succeed when it is gone.
	if !reflect.DeepEqual(undo, []string{"P resolvconf -d wg0 -f"}) {
		t.Errorf("undo %q", undo)
	}
	// A missing search list leaves out the search line.
	ss, _, _ = linuxDNS(ctx, &recorder{failOn: "resolvectl"}, resolvFile(t, ""), dnsPlan(DNSPrimary))
	if want := "nameserver 10.0.0.1\nnameserver fd00::1\n"; string(ss[0].do.Stdin) != want {
		t.Errorf("stdin %q, want %q", ss[0].do.Stdin, want)
	}

	// Scoped DNS cannot be expressed: nothing is applied, and it is said.
	ss, got, err = linuxDNS(ctx, &recorder{failOn: "resolvectl"}, resolvFile(t, ""), dnsPlan(DNSScoped, "lan"))
	if err != nil || got != DNSOutcomeScopedUnsupported || len(ss) != 0 {
		t.Errorf("scoped: %q %v steps %d", got, err, len(ss))
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
	// A resolvconf that exists but rejects --version is still resolvconf.
	r = &recorder{failOn: "resolvectl"}
	r.fail = map[string]error{"resolvconf --version": errors.New("exit status 1")}
	if _, got, err = linuxDNS(ctx, r, resolvFile(t, ""), dnsPlan(DNSPrimary)); err != nil || got != DNSOutcomeResolvconf {
		t.Errorf("got %q, %v", got, err)
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
