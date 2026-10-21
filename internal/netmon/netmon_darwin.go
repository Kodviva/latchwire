package netmon

import (
	"fmt"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// NewSource opens an AF_ROUTE socket. It only listens: it needs no
// privileges and changes nothing. The returned Source is also an io.Closer.
func NewSource() (Source, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("netmon: route socket: %w", err)
	}
	return newSockSource(fd, "route", parseRoute)
}

func parseRoute(b []byte) (string, bool) {
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return "", true // cannot tell what it is: assume a change
	}
	return classifyRoute(msgs, ifaceNameByIndex)
}

// routeNoise are route flags of entries the kernel creates and expires by
// itself (neighbour cache entries and cloned host routes).
const routeNoise = syscall.RTF_LLINFO | syscall.RTF_WASCLONED

// classifyRoute decides whether the messages signal a network change, and
// which interface (by name) they concern. Interface changes, address changes
// and added, deleted or changed routes count; replies to route lookups
// (RTM_GET), misses, redirects, multicast group changes and the kernel's own
// neighbour and cloned routes do not. The name is "" unless every counted
// message names the same interface.
func classifyRoute(msgs []route.Message, byIndex func(int) string) (iface string, ok bool) {
	var names []string
	for _, m := range msgs {
		switch m := m.(type) {
		case *route.InterfaceMessage:
			name := m.Name
			if name == "" {
				name = byIndex(m.Index)
			}
			names = append(names, name)
		case *route.InterfaceAddrMessage:
			names = append(names, byIndex(m.Index))
		case *route.RouteMessage:
			switch m.Type {
			case syscall.RTM_ADD, syscall.RTM_DELETE, syscall.RTM_CHANGE:
			default:
				continue
			}
			if m.Flags&routeNoise != 0 {
				continue
			}
			names = append(names, byIndex(m.Index))
		}
	}
	if len(names) == 0 {
		return "", false
	}
	return commonIface(names), true
}
