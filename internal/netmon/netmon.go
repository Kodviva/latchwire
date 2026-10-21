// Package netmon reports that the machine's network changed (an interface, an
// address or a route) and gives the current network a stable identity.
//
// Consumers use an Event only as a hint: they re-read the system state they
// depend on (endpoint routes, DNS, MTU, the network identity) themselves.
// Watching needs no privileges and changes nothing on the host.
package netmon

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// Event says that something in the network configuration changed.
type Event struct{ At time.Time }

// errUnsupported is returned for what this OS cannot do.
var errUnsupported = errors.ErrUnsupported

// maxDebounceFactor bounds how long a steady stream of notifications can
// postpone an Event, as a multiple of the debounce time.
const maxDebounceFactor = 10

// Source delivers raw network change notifications from the operating
// system (an AF_ROUTE socket on macOS, a NETLINK_ROUTE socket on Linux).
//
// Next blocks until the next notification and returns the name of the
// interface it concerns, or "" when the notification names none (or the name
// cannot be resolved, for instance because the interface is already gone).
// Next returns ctx.Err() once ctx ends, and a different error when the
// source has failed for good. It is called from one goroutine at a time.
//
// If a Source also implements io.Closer, Watch closes it when it stops.
type Source interface {
	Next(ctx context.Context) (iface string, err error)
}

// Watch turns a Source into debounced Events. A burst of notifications ends,
// debounce after the last one, in a single Event (so a flapping link or a
// DHCP renewal does not trigger a refresh per message). A notification for an
// interface that ignoreIfaces reports true for (our own tunnel interfaces) is
// dropped; ignoreIfaces may be nil. Notifications without an interface name
// are never dropped.
//
// Watch takes ownership of src: the returned channel is closed, and src is
// closed if it implements io.Closer, once ctx ends or src fails. The channel
// holds at most one pending Event; a slow consumer misses none, because a
// pending Event already means "re-read the state".
func Watch(ctx context.Context, src Source, debounce time.Duration, ignoreIfaces func(string) bool) <-chan Event {
	out := make(chan Event, 1)
	go watch(ctx, src, debounce, ignoreIfaces, out)
	return out
}

type note struct {
	iface string
	err   error
}

func watch(ctx context.Context, src Source, debounce time.Duration, ignore func(string) bool, out chan<- Event) {
	defer close(out)
	rctx, cancel := context.WithCancel(ctx)
	if c, ok := src.(io.Closer); ok {
		defer c.Close()
	}
	defer cancel() // runs first: unblocks the reader, then the source closes

	notes := make(chan note)
	go func() {
		for {
			iface, err := src.Next(rctx)
			select {
			case notes <- note{iface, err}:
			case <-rctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	var (
		armed bool
		first time.Time // when the current burst began
	)
	for {
		var fire <-chan time.Time
		if armed {
			fire = timer.C
		}
		select {
		case <-rctx.Done():
			return
		case n := <-notes:
			if n.err != nil {
				return
			}
			if n.iface != "" && ignore != nil && ignore(n.iface) {
				continue
			}
			now := time.Now()
			if !armed {
				armed, first = true, now
			}
			wait := min(debounce, max(first.Add(maxDebounceFactor*debounce).Sub(now), 0))
			timer.Reset(wait)
		case <-fire:
			armed = false
			select {
			case out <- Event{At: time.Now()}:
			default: // one Event is already pending
			}
		}
	}
}

// maxCachedIfaces bounds the interface cache; it is cleared when exceeded.
const maxCachedIfaces = 1024

// ifaceCache maps interface indexes to names. The kernel reports an
// interface that is already gone (our own tunnel being torn down) by index
// only, and the system can no longer resolve it, so the names are remembered
// from earlier: seeded at start, then updated on every successful lookup and
// on every message that carries a name. It is used from one goroutine (the
// source's Next) and needs no locking.
type ifaceCache struct {
	names   map[int]string
	fresh   map[int]bool // indexes looked up live during this datagram
	byIndex func(int) (string, error)
}

func newIfaceCache() *ifaceCache {
	c := &ifaceCache{
		names: map[int]string{},
		fresh: map[int]bool{},
		byIndex: func(i int) (string, error) {
			ifc, err := net.InterfaceByIndex(i)
			if err != nil {
				return "", err
			}
			return ifc.Name, nil
		},
	}
	if ifcs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifcs {
			c.names[ifc.Index] = ifc.Name
		}
	}
	return c
}

// begin starts a new datagram: live lookups are deduplicated within one.
func (c *ifaceCache) begin() { clear(c.fresh) }

// learn records a name the kernel gave for index.
func (c *ifaceCache) learn(index int, name string) {
	if index <= 0 || name == "" {
		return
	}
	if len(c.names) >= maxCachedIfaces {
		clear(c.names)
	}
	c.names[index] = name
}

// name returns the name of the interface with the given index, or "" if it
// is unknown. Plain lookups use the cache and only ask the system on a miss.
// With refresh (the interface itself changed, so its index may have been
// reused) the system is asked, once per datagram. A system lookup that fails
// (the interface vanished) falls back to the cache.
func (c *ifaceCache) name(index int, refresh bool) string {
	if index <= 0 {
		return ""
	}
	cached, ok := c.names[index]
	if ok && !refresh {
		return cached
	}
	if !c.fresh[index] {
		c.fresh[index] = true
		if n, err := c.byIndex(index); err == nil {
			c.learn(index, n)
			return n
		}
	}
	return cached
}

// commonIface returns the interface name that all of names agree on, or ""
// when they differ or one of them is unknown. A notification batch that
// touches several interfaces must not be dropped because one of them is ours.
func commonIface(names []string) string {
	if len(names) == 0 {
		return ""
	}
	for _, n := range names[1:] {
		if n != names[0] {
			return ""
		}
	}
	return names[0]
}
