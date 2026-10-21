// Package netcfg configures a tunnel interface's addresses and routes by
// running the platform's network commands (ifconfig/route on macOS, ip on
// Linux). Only split-tunnel routes are supported for now; DNS and full-tunnel
// routing come later.
//
// Every change to the system is written to a Journal before it is made, so
// that a crash leaves the commands that undo it; Cleanup runs them at start.
package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/Kodviva/latchwire/internal/msg"
)

// ErrFullTunnelUnsupported is returned, before any command runs, when a route
// is a default route (0.0.0.0/0 or ::/0).
var ErrFullTunnelUnsupported = errors.New(msg.NetFullTunnelUnsupported)

// Runner runs one system command and returns its standard output. stdin may
// be nil. Arguments must never carry secrets; stdin may.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)
}

// DNSRole says how a tunnel's DNS servers take part in name resolution.
type DNSRole int

const (
	DNSNone    DNSRole = iota // the tunnel sets no DNS
	DNSPrimary                // its servers answer every name
	DNSScoped                 // its servers answer only DNSSearch domains
)

// Plan is what to configure for one tunnel interface.
type Plan struct {
	Iface     string
	Addresses []netip.Prefix
	Routes    []netip.Prefix
	MTU       int
	DNS       []netip.Addr
	DNSSearch []string
	DNSRole   DNSRole
	Endpoints []netip.AddrPort
	FwMark    uint32
}

// Applied reports what Apply put in place.
type Applied struct {
	MTU        int
	FullTunnel bool
	Table      uint32
}

// Configurer sets up and removes one interface's network configuration.
// Remove undoes what Apply did; it is a no-op when nothing is applied.
// Refresh re-reads the system state the applied configuration depends on.
type Configurer interface {
	Apply(ctx context.Context, p Plan) (Applied, error)
	Refresh(ctx context.Context) error
	Remove(ctx context.Context) error
}

// step is one command and the command that undoes it (nil: nothing to undo).
type step struct {
	do   Step
	undo *Step
}

// planner turns a Plan into the commands for one platform.
type planner func(p Plan) []step

type configurer struct {
	run  Runner
	j    *Journal // nil: nothing is journaled
	plan planner

	mu      sync.Mutex
	owner   string
	applied []step // undo order is reverse
}

func newConfigurer(r Runner, j *Journal, p planner) *configurer {
	return &configurer{run: r, j: j, plan: p}
}

func (c *configurer) Apply(ctx context.Context, p Plan) (Applied, error) {
	for _, r := range p.Routes {
		if r.Bits() == 0 {
			return Applied{}, ErrFullTunnelUnsupported
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) > 0 {
		return Applied{}, errors.New(msg.NetAlreadyApplied)
	}
	c.owner = p.Iface
	var undo []Step
	for _, s := range c.plan(p) {
		// The undo step reaches the journal before the change it undoes.
		if s.undo != nil && c.j != nil {
			undo = append(undo, *s.undo)
			if err := c.j.Record(c.owner, undo); err != nil {
				c.rollbackLocked(ctx)
				return Applied{}, err
			}
		}
		if err := c.exec(ctx, s.do); err != nil {
			c.rollbackLocked(ctx)
			return Applied{}, err
		}
		c.applied = append(c.applied, s)
	}
	return Applied{MTU: p.MTU}, nil
}

// Refresh does nothing yet: split tunnels depend on no system state.
func (c *configurer) Refresh(ctx context.Context) error { return nil }

// Remove undoes the applied steps and always drops the owner's journal
// record. Callers close the tunnel device first, which takes the interface,
// its addresses and its routes with it, so the undo commands usually fail;
// keeping the record would replay them at the next start, possibly against
// an unrelated interface that reused the name (utunN on macOS). The errors
// are still returned.
func (c *configurer) Remove(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) == 0 {
		return nil
	}
	err := c.undoLocked(ctx)
	if c.j != nil {
		if ferr := c.j.Forget(c.owner); err == nil {
			err = ferr
		}
	}
	return err
}

// rollbackLocked undoes a failed Apply. It must finish even when ctx is
// cancelled (the usual reason an Apply fails late), so it does not use ctx's
// cancellation. The owner's record goes either way: the commands that
// remain are not worth a retry at the next start.
func (c *configurer) rollbackLocked(ctx context.Context) {
	c.undoLocked(context.WithoutCancel(ctx))
	if c.j != nil {
		c.j.Forget(c.owner)
	}
}

// undoLocked undoes every applied step, reporting the first failure.
func (c *configurer) undoLocked(ctx context.Context) error {
	var first error
	for i := len(c.applied) - 1; i >= 0; i-- {
		if u := c.applied[i].undo; u != nil {
			if err := c.exec(ctx, *u); err != nil && first == nil {
				first = err
			}
		}
	}
	c.applied = nil
	return first
}

func (c *configurer) exec(ctx context.Context, s Step) error {
	if _, err := c.run.Run(ctx, s.Name, s.Args, s.Stdin); err != nil {
		return fmt.Errorf("%s: %w", s, err)
	}
	return nil
}

func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "-inet"
	}
	return "-inet6"
}

func newDarwin(r Runner, j *Journal) Configurer {
	return newConfigurer(r, j, planDarwin)
}

func newLinux(r Runner, j *Journal) Configurer {
	return newConfigurer(r, j, planLinux)
}
