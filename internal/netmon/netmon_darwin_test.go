//go:build darwin

package netmon

import (
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
