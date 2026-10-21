//go:build darwin

package netmon

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"

	"golang.org/x/net/route"
)

func TestClassifyRoute(t *testing.T) {
	names := map[int]string{4: "en0", 20: "utun7"}
	byIndex := func(i int) string { return names[i] }
	cases := []struct {
		name  string
		msgs  []route.Message
		iface string
		ok    bool
	}{
		{"link change names itself", []route.Message{&route.InterfaceMessage{Type: syscall.RTM_IFINFO, Index: 20, Name: "utun7"}}, "utun7", true},
		{"link change index only", []route.Message{&route.InterfaceMessage{Type: syscall.RTM_IFINFO, Index: 4}}, "en0", true},
		{"address added", []route.Message{&route.InterfaceAddrMessage{Type: syscall.RTM_NEWADDR, Index: 4}}, "en0", true},
		{"route added on iface", []route.Message{&route.RouteMessage{Type: syscall.RTM_ADD, Index: 20}}, "utun7", true},
		{"route deleted, no iface", []route.Message{&route.RouteMessage{Type: syscall.RTM_DELETE}}, "", true},
		{"route lookup reply is not a change", []route.Message{&route.RouteMessage{Type: syscall.RTM_GET, Index: 4}}, "", false},
		{"route miss is not a change", []route.Message{&route.RouteMessage{Type: syscall.RTM_MISS}}, "", false},
		{"multicast address is not a change", []route.Message{&route.InterfaceMulticastAddrMessage{Type: syscall.RTM_NEWMADDR, Index: 4}}, "", false},
		{"neighbour cache entry is not a change", []route.Message{&route.RouteMessage{Type: syscall.RTM_ADD, Index: 4, Flags: syscall.RTF_LLINFO}}, "", false},
		{"cloned host route is not a change", []route.Message{&route.RouteMessage{Type: syscall.RTM_DELETE, Index: 4, Flags: syscall.RTF_WASCLONED}}, "", false},
		{"unknown index", []route.Message{&route.RouteMessage{Type: syscall.RTM_ADD, Index: 99}}, "", true},
		{"nothing parsed", nil, "", false},
		{"two ifaces: unnamed", []route.Message{
			&route.RouteMessage{Type: syscall.RTM_ADD, Index: 20},
			&route.RouteMessage{Type: syscall.RTM_ADD, Index: 4},
		}, "", true},
		{"same iface twice", []route.Message{
			&route.RouteMessage{Type: syscall.RTM_ADD, Index: 20},
			&route.InterfaceAddrMessage{Type: syscall.RTM_NEWADDR, Index: 20},
		}, "utun7", true},
	}
	for _, c := range cases {
		iface, ok := classifyRoute(c.msgs, byIndex)
		if iface != c.iface || ok != c.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, iface, ok, c.iface, c.ok)
		}
	}
}

// ifinfoRaw builds an RTM_IFINFO message shaped like the kernel's rt_ifmsg:
// an if_msghdr (112 bytes; if_msghdr2 is 160) whose ifm_addrs is 0, so no
// interface name is attached.
func ifinfoRaw(typ byte, index uint16) []byte {
	size := 112
	if typ == syscall.RTM_IFINFO2 {
		size = 160
	}
	b := make([]byte, size)
	binary.NativeEndian.PutUint16(b[0:], uint16(len(b)))
	b[2], b[3] = syscall.RTM_VERSION, typ
	binary.NativeEndian.PutUint32(b[8:], syscall.IFF_UP) // ifm_flags
	binary.NativeEndian.PutUint16(b[12:], index)
	return b
}

// rtRaw builds a 92-byte rt_msghdr with no addresses.
func rtRaw(typ byte, index uint16) []byte {
	b := make([]byte, 92)
	binary.NativeEndian.PutUint16(b[0:], uint16(len(b)))
	b[2], b[3] = syscall.RTM_VERSION, typ
	binary.NativeEndian.PutUint16(b[4:], index)
	return b
}

func darwinCache(names map[int]string) *ifaceCache {
	return &ifaceCache{
		names:   names,
		fresh:   map[int]bool{},
		byIndex: func(int) (string, error) { return "", errors.New("gone") },
	}
}

func TestParseRouteIfInfo(t *testing.T) {
	// Premise of the fix: the library drops the kernel's IFINFO messages.
	for _, typ := range []byte{syscall.RTM_IFINFO, syscall.RTM_IFINFO2} {
		msgs, err := route.ParseRIB(route.RIBTypeRoute, ifinfoRaw(typ, 4))
		if err != nil || len(msgs) != 0 {
			t.Fatalf("type %#x: ParseRIB = %v, %v; the premise of parseRoute is gone", typ, msgs, err)
		}
	}
	cache := darwinCache(map[int]string{4: "en0", 20: "utun7"})
	for _, typ := range []byte{syscall.RTM_IFINFO, syscall.RTM_IFINFO2} {
		if iface, ok := parseRoute(ifinfoRaw(typ, 4), cache); !ok || iface != "en0" {
			t.Errorf("link event %#x on en0: (%q, %v)", typ, iface, ok)
		}
		// The own tunnel's link going down is named, so Watch can ignore it.
		if iface, ok := parseRoute(ifinfoRaw(typ, 20), cache); !ok || iface != "utun7" {
			t.Errorf("link event %#x on utun7: (%q, %v)", typ, iface, ok)
		}
	}
	// A link we have never heard of is still a change, unnamed.
	if iface, ok := parseRoute(ifinfoRaw(syscall.RTM_IFINFO, 99), cache); !ok || iface != "" {
		t.Errorf("unknown link: (%q, %v)", iface, ok)
	}
	// Two messages in one datagram.
	two := append(ifinfoRaw(syscall.RTM_IFINFO, 20), ifinfoRaw(syscall.RTM_IFINFO, 20)...)
	if iface, ok := parseRoute(two, cache); !ok || iface != "utun7" {
		t.Errorf("two link events: (%q, %v)", iface, ok)
	}
	two = append(ifinfoRaw(syscall.RTM_IFINFO, 20), ifinfoRaw(syscall.RTM_IFINFO, 4)...)
	if iface, ok := parseRoute(two, cache); !ok || iface != "" {
		t.Errorf("two interfaces: (%q, %v)", iface, ok)
	}
}

func TestParseRouteRoutes(t *testing.T) {
	cache := darwinCache(map[int]string{4: "en0", 20: "utun7"})
	if iface, ok := parseRoute(rtRaw(syscall.RTM_DELETE, 20), cache); !ok || iface != "utun7" {
		t.Errorf("route delete on vanished utun7: (%q, %v)", iface, ok)
	}
	if iface, ok := parseRoute(rtRaw(syscall.RTM_ADD, 4), cache); !ok || iface != "en0" {
		t.Errorf("route add: (%q, %v)", iface, ok)
	}
	if _, ok := parseRoute(rtRaw(syscall.RTM_GET, 4), cache); ok {
		t.Error("RTM_GET reply counted as a change")
	}
}

func TestParseRouteUnparsed(t *testing.T) {
	cache := darwinCache(nil)
	// A type ParseRIB does not know: bytes arrived, something changed.
	if iface, ok := parseRoute(rtRaw(0x7f, 0), cache); !ok || iface != "" {
		t.Errorf("unknown type: (%q, %v)", iface, ok)
	}
	// Truncated and garbage input.
	for _, b := range [][]byte{{1}, {200, 0, 5, 1}, make([]byte, 8)} {
		if iface, ok := parseRoute(b, cache); !ok || iface != "" {
			t.Errorf("garbage %v: (%q, %v)", b, iface, ok)
		}
	}
	// A message of another routing version is skipped, as ParseRIB does.
	other := rtRaw(syscall.RTM_ADD, 4)
	other[2] = 99
	if _, ok := parseRoute(other, cache); ok {
		t.Error("foreign version counted as a change")
	}
}
