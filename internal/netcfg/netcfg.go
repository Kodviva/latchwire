// Package netcfg configures a tunnel interface's addresses and routes by
// running the platform's network commands (ifconfig/route on macOS, ip on
// Linux). Only split-tunnel routes are supported for now; DNS and full-tunnel
// routing come later.
package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/Kodviva/latchwire/internal/msg"
)

// ErrFullTunnelUnsupported is returned, before any command runs, when a route
// is a default route (0.0.0.0/0 or ::/0).
var ErrFullTunnelUnsupported = errors.New(msg.NetFullTunnelUnsupported)

// Configurer sets up and removes one interface's network configuration.
// Remove undoes what Apply did; it is a no-op when nothing is applied.
type Configurer interface {
	Apply(iface string, addrs, routes []netip.Prefix) error
	Remove() error
}

// step is one command and the command that undoes it (nil: nothing to undo).
type step struct {
	do, undo []string
}

// planner turns a configuration into the commands for one platform.
type planner func(iface string, addrs, routes []netip.Prefix) []step

type configurer struct {
	run  func(name string, args ...string) error
	plan planner

	mu      sync.Mutex
	applied []step // undo order is reverse
}

func newConfigurer(run func(string, ...string) error, p planner) *configurer {
	return &configurer{run: run, plan: p}
}

func (c *configurer) Apply(iface string, addrs, routes []netip.Prefix) error {
	for _, r := range routes {
		if r.Bits() == 0 {
			return ErrFullTunnelUnsupported
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) > 0 {
		return errors.New(msg.NetAlreadyApplied)
	}
	for _, s := range c.plan(iface, addrs, routes) {
		if err := c.exec(s.do); err != nil {
			c.removeLocked()
			return err
		}
		c.applied = append(c.applied, s)
	}
	return nil
}

func (c *configurer) Remove() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.removeLocked()
}

// removeLocked undoes every applied step, reporting the first failure.
func (c *configurer) removeLocked() error {
	var first error
	for i := len(c.applied) - 1; i >= 0; i-- {
		if u := c.applied[i].undo; u != nil {
			if err := c.exec(u); err != nil && first == nil {
				first = err
			}
		}
	}
	c.applied = nil
	return first
}

func (c *configurer) exec(cmd []string) error {
	if err := c.run(cmd[0], cmd[1:]...); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(cmd, " "), err)
	}
	return nil
}

func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "-inet"
	}
	return "-inet6"
}

// planDarwin: addresses are point-to-point on utun, routes point at the
// interface. Setting the first address marks the interface up.
func planDarwin(iface string, addrs, routes []netip.Prefix) []step {
	var out []step
	for _, a := range addrs {
		ip := a.Addr().String()
		if a.Addr().Is4() {
			out = append(out, step{
				do:   []string{"ifconfig", iface, "inet", ip, ip, "alias"},
				undo: []string{"ifconfig", iface, "inet", ip, "-alias"},
			})
		} else {
			out = append(out, step{
				do:   []string{"ifconfig", iface, "inet6", ip, "prefixlen", strconv.Itoa(a.Bits()), "alias"},
				undo: []string{"ifconfig", iface, "inet6", ip, "-alias"},
			})
		}
	}
	for _, r := range routes {
		r = r.Masked()
		out = append(out, step{
			do:   []string{"route", "-q", "-n", "add", family(r), r.String(), "-interface", iface},
			undo: []string{"route", "-q", "-n", "delete", family(r), r.String(), "-interface", iface},
		})
	}
	return out
}

// planLinux: an address with a prefix shorter than the host length already
// installs its connected route, so that route is not added again.
func planLinux(iface string, addrs, routes []netip.Prefix) []step {
	var out []step
	connected := map[netip.Prefix]bool{}
	for _, a := range addrs {
		out = append(out, step{
			do:   []string{"ip", "address", "add", a.String(), "dev", iface},
			undo: []string{"ip", "address", "del", a.String(), "dev", iface},
		})
		if a.Bits() < a.Addr().BitLen() {
			connected[a.Masked()] = true
		}
	}
	out = append(out, step{do: []string{"ip", "link", "set", iface, "up"}})
	for _, r := range routes {
		r = r.Masked()
		if connected[r] {
			continue
		}
		out = append(out, step{
			do:   []string{"ip", "route", "add", r.String(), "dev", iface},
			undo: []string{"ip", "route", "del", r.String(), "dev", iface},
		})
	}
	return out
}

func newDarwin(run func(string, ...string) error) Configurer {
	return newConfigurer(run, planDarwin)
}

func newLinux(run func(string, ...string) error) Configurer {
	return newConfigurer(run, planLinux)
}
