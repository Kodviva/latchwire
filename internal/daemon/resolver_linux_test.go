package daemon

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// The marked resolver's sockets carry SO_MARK = the table. Setting the mark
// needs CAP_NET_ADMIN, so without it the dial must fail rather than send an
// unmarked query.
func TestMarkControlSetsSOMark(t *testing.T) {
	d := net.Dialer{Control: markControl(51820)}
	c, err := d.Dial("udp", "127.0.0.1:9")
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("no CAP_NET_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		mark, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil || gerr != nil {
		t.Fatal(err, gerr)
	}
	if mark != 51820 {
		t.Fatalf("SO_MARK = %d, want 51820", mark)
	}
}

func TestMarkedResolverOnlyWithMark(t *testing.T) {
	if r := resolverFor(0); r != net.DefaultResolver {
		t.Error("mark 0 must use the default resolver")
	}
	r := resolverFor(51820)
	if r == net.DefaultResolver || !r.PreferGo || r.Dial == nil {
		t.Errorf("mark 51820: resolver %+v, want the Go resolver with a marking dialer", r)
	}
}
