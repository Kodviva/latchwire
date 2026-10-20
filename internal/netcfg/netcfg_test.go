package netcfg

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// recorder records commands instead of running them. failOn makes the
// command whose rendering starts with it fail.
type recorder struct {
	cmds   []string
	failOn string
}

func (r *recorder) run(name string, args ...string) error {
	c := strings.Join(append([]string{name}, args...), " ")
	r.cmds = append(r.cmds, c)
	if r.failOn != "" && strings.HasPrefix(c, r.failOn) {
		return errors.New("exit status 1")
	}
	return nil
}

func pfx(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range s {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func TestDarwinApplyCommands(t *testing.T) {
	r := &recorder{}
	c := newDarwin(r.run)
	if err := c.Apply("utun7", pfx("10.0.0.2/32"), pfx("10.0.0.0/24")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ifconfig utun7 inet 10.0.0.2 10.0.0.2 alias",
		"route -q -n add -inet 10.0.0.0/24 -interface utun7",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

func TestDarwinApplyIPv6AndRemove(t *testing.T) {
	r := &recorder{}
	c := newDarwin(r.run)
	if err := c.Apply("utun3", pfx("fd00::2/128"), pfx("fd00::/64", "10.0.0.1/32")); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	if err := c.Remove(); err != nil {
		t.Fatal(err)
	}
	// Everything Apply did is undone in reverse order.
	want := []string{
		"route -q -n delete -inet 10.0.0.1/32 -interface utun3",
		"route -q -n delete -inet6 fd00::/64 -interface utun3",
		"ifconfig utun3 inet6 fd00::2 -alias",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("remove commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	r.cmds = nil
	if err := c.Remove(); err != nil || len(r.cmds) != 0 {
		t.Fatalf("second Remove: err=%v cmds=%q, want no-op", err, r.cmds)
	}
}

func TestLinuxApplyCommands(t *testing.T) {
	r := &recorder{}
	c := newLinux(r.run)
	if err := c.Apply("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip address add 10.0.0.2/32 dev X",
		"ip link set X up",
		"ip route add 10.0.0.0/24 dev X",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	r.cmds = nil
	if err := c.Remove(); err != nil {
		t.Fatal(err)
	}
	want = []string{"ip route del 10.0.0.0/24 dev X", "ip address del 10.0.0.2/32 dev X"}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("remove commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

// An address with a shorter prefix already brings its connected route; adding
// it again would fail with "File exists".
func TestLinuxSkipsConnectedRoute(t *testing.T) {
	r := &recorder{}
	c := newLinux(r.run)
	if err := c.Apply("X", pfx("10.0.0.2/24"), pfx("10.0.0.0/24", "10.1.0.0/16")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip address add 10.0.0.2/24 dev X",
		"ip link set X up",
		"ip route add 10.1.0.0/16 dev X",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

func TestFullTunnelRejected(t *testing.T) {
	for _, full := range []string{"0.0.0.0/0", "::/0"} {
		for name, c := range map[string]func(func(string, ...string) error) Configurer{
			"darwin": newDarwin, "linux": newLinux,
		} {
			r := &recorder{}
			err := c(r.run).Apply("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24", full))
			if !errors.Is(err, ErrFullTunnelUnsupported) {
				t.Errorf("%s %s: err = %v, want ErrFullTunnelUnsupported", name, full, err)
			}
			if len(r.cmds) != 0 {
				t.Errorf("%s %s: commands ran: %q", name, full, r.cmds)
			}
		}
	}
}

// A failing command rolls back what was already applied and is reported.
func TestApplyFailureRollsBack(t *testing.T) {
	r := &recorder{failOn: "ip route add 10.1.0.0/16"}
	c := newLinux(r.run)
	err := c.Apply("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24", "10.1.0.0/16"))
	if err == nil {
		t.Fatal("Apply succeeded, want error")
	}
	if !strings.Contains(err.Error(), "ip route add 10.1.0.0/16 dev X") {
		t.Errorf("error %q does not name the failing command", err)
	}
	want := []string{
		"ip address add 10.0.0.2/32 dev X",
		"ip link set X up",
		"ip route add 10.0.0.0/24 dev X",
		"ip route add 10.1.0.0/16 dev X",
		"ip route del 10.0.0.0/24 dev X",
		"ip address del 10.0.0.2/32 dev X",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

func TestNewPicksPlatform(t *testing.T) {
	if New((&recorder{}).run) == nil {
		t.Fatal("New returned nil")
	}
}
