package netmon

import (
	"encoding/binary"
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
	cache := newIfaceCache()
	return newSockSource(fd, "route", func(b []byte) (string, bool) { return parseRoute(b, cache) })
}

// Header offsets of struct if_msghdr and if_msghdr2 (net/if.h) that matter.
const (
	rtmHdrLen   = 4  // msglen (u16), version, type
	ifmIndexOff = 12 // ifm_index (u16)
	ifmMinLen   = 14
)

// parseRoute reads one datagram of routing messages. RTM_IFINFO is read from
// its raw header: route.ParseRIB drops it unless the message carries an
// RTA_IFP address, and the kernel sends none (ifm_addrs is 0), so a link
// going up or down would otherwise never be seen. Messages ParseRIB cannot
// make sense of count as an unnamed change.
func parseRoute(b []byte, cache *ifaceCache) (string, bool) {
	cache.begin()
	var names []string
	for len(b) > 0 {
		if len(b) < rtmHdrLen {
			names = append(names, "")
			break
		}
		l := int(binary.NativeEndian.Uint16(b[0:]))
		if l < rtmHdrLen || l > len(b) {
			names = append(names, "")
			break
		}
		msg := b[:l]
		b = b[l:]
		if msg[2] != syscall.RTM_VERSION {
			continue
		}
		switch int(msg[3]) {
		case syscall.RTM_IFINFO, syscall.RTM_IFINFO2:
			name := ""
			if l >= ifmMinLen {
				name = cache.name(int(binary.NativeEndian.Uint16(msg[ifmIndexOff:])), true)
			}
			names = append(names, name)
			continue
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, msg)
		if err != nil || len(msgs) == 0 {
			// Unparseable or of a type ParseRIB does not know.
			names = append(names, "")
			continue
		}
		for _, m := range msgs {
			if im, ok := m.(*route.InterfaceMessage); ok {
				cache.learn(im.Index, im.Name)
			}
		}
		if name, ok := classifyRoute(msgs, func(i int) string { return cache.name(i, false) }); ok {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", false
	}
	return commonIface(names), true
}

// routeNoise are route flags of entries the kernel creates and expires by
// itself (neighbour cache entries and cloned host routes).
const routeNoise = syscall.RTF_LLINFO | syscall.RTF_WASCLONED

// classifyRoute decides whether the messages signal a network change, and
// which interface (by name) they concern. Interface changes, address changes
// and added, deleted or changed routes count; replies to route lookups
// (RTM_GET), failed route requests, misses, redirects, multicast group
// changes and the kernel's own neighbour and cloned routes do not. The name is "" unless every counted
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
			// A failed request (rtm_errno set) is echoed to every
			// routing socket but changed nothing; counting it would
			// let a failing route change in Refresh trigger itself.
			if m.Flags&routeNoise != 0 || m.Err != nil {
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
