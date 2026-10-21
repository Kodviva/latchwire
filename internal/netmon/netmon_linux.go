package netmon

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// netlinkGroups are the rtnetlink multicast groups to listen to: links,
// addresses and routes of both families.
const netlinkGroups = unix.RTMGRP_LINK |
	unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
	unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE

// NewSource opens a NETLINK_ROUTE socket subscribed to netlinkGroups. It only
// listens: it needs no privileges and changes nothing. The returned Source is
// also an io.Closer.
func NewSource() (Source, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netmon: netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: netlinkGroups}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netmon: netlink bind: %w", err)
	}
	cache := newIfaceCache()
	return newSockSource(fd, "netlink", func(b []byte) (string, bool) { return parseLinux(b, cache) })
}

func parseLinux(b []byte, cache *ifaceCache) (string, bool) {
	return resolveChanges(parseNetlink(b), cache)
}
