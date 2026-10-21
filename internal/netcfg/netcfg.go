// Package netcfg configures a tunnel interface's addresses and routes by
// running the platform's network commands (ifconfig/route on macOS, ip on
// Linux). Linux routes full tunnels (0.0.0.0/0, ::/0) with fwmark policy
// routing; macOS supports only split-tunnel routes for now. DNS comes later.
//
// Every change to the system is written to a Journal before it is made, so
// that a crash leaves the commands that undo it; Cleanup runs them at start.
package netcfg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"slices"
	"sync"

	"github.com/Kodviva/latchwire/internal/msg"
)

// ErrFullTunnelUnsupported is returned, before any command runs, when a route
// is a default route (0.0.0.0/0 or ::/0) on a platform without full-tunnel
// support yet (macOS).
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

// Plan is what to configure for one tunnel interface. FwMark, for a full
// tunnel on Linux, is the routing table (and mark) to use; 0 = Apply picks
// one.
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

// Applied reports what Apply put in place. Table is a full tunnel's routing
// table (Linux). RPFilter reports whether a full tunnel got its reverse-path
// filter (false when nft is not installed).
type Applied struct {
	MTU        int
	FullTunnel bool
	Table      uint32
	RPFilter   bool
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
// missing, when set, makes a command that is not installed (exec.ErrNotFound)
// no failure: the message is logged and the step skipped.
type step struct {
	do      Step
	undo    *Step
	missing string
}

// planner turns a Plan into the commands for one platform.
type planner func(p Plan) []step

// fullPlanner returns the extra steps of a full tunnel and its table. It may
// read system state through r.
type fullPlanner func(ctx context.Context, r Runner, p Plan) ([]step, uint32, error)

type configurer struct {
	run  Runner
	j    *Journal // nil: nothing is journaled
	plan planner
	full fullPlanner // nil: full tunnels are not supported

	mu      sync.Mutex
	owner   string
	applied []step // undo order is reverse
	// carried are persistent undo steps an earlier configurer of the same
	// owner could not run; they stay journaled ahead of this one's.
	carried []Step
}

func newConfigurer(r Runner, j *Journal, p planner, full fullPlanner) *configurer {
	return &configurer{run: r, j: j, plan: p, full: full}
}

func (c *configurer) Apply(ctx context.Context, p Plan) (Applied, error) {
	v4, v6 := defaultFamilies(p.Routes)
	full := v4 || v6
	if full && c.full == nil {
		return Applied{}, ErrFullTunnelUnsupported
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) > 0 {
		return Applied{}, errors.New(msg.NetAlreadyApplied)
	}
	c.owner = p.Iface
	if err := c.retryLocked(ctx); err != nil {
		return Applied{}, err
	}
	res := Applied{MTU: p.MTU, FullTunnel: full}
	steps := c.plan(p)
	if full {
		fs, table, err := c.full(ctx, c.run, p)
		if err != nil {
			return Applied{}, err
		}
		steps = append(steps, fs...)
		res.Table = table
	}
	undo := slices.Clone(c.carried)
	for _, s := range steps {
		// The undo step reaches the journal before the change it undoes.
		if s.undo != nil && c.j != nil {
			undo = append(undo, *s.undo)
			if err := c.j.Record(c.owner, undo); err != nil {
				c.rollbackLocked(ctx)
				return Applied{}, err
			}
		}
		if err := c.exec(ctx, s.do); err != nil {
			if s.missing != "" && errors.Is(err, exec.ErrNotFound) {
				log.Print(s.missing)
				if s.undo != nil && c.j != nil {
					undo = undo[:len(undo)-1]
					if err := c.j.Record(c.owner, undo); err != nil {
						c.rollbackLocked(ctx)
						return Applied{}, err
					}
				}
				continue
			}
			c.rollbackLocked(ctx)
			return Applied{}, err
		}
		c.applied = append(c.applied, s)
		if s.do.Name == "nft" && full {
			res.RPFilter = true
		}
	}
	return res, nil
}

// retryLocked runs, in reverse, the undo steps the journal still holds for
// the owner: persistent steps a previous Remove could not undo. Re-adding an
// ip rule that is still there would fail, and the record is about to be
// replaced. Persistent steps that fail again are carried into the new
// record.
func (c *configurer) retryLocked(ctx context.Context) error {
	c.carried = nil
	if c.j == nil {
		return nil
	}
	old := c.j.Entries()[c.owner]
	for i := len(old) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.exec(ctx, old[i]); err != nil && old[i].Persistent && ctx.Err() == nil && !alreadyUndone(old[i], err) {
			c.carried = append(c.carried, old[i])
		}
	}
	slices.Reverse(c.carried)
	return ctx.Err()
}

// Refresh does nothing yet: split tunnels depend on no system state.
func (c *configurer) Refresh(ctx context.Context) error { return nil }

// Remove undoes the applied steps. Callers close the tunnel device first,
// which takes the interface, its addresses and its routes with it, so those
// undo commands usually fail; they are forgotten, or the next start would
// replay them, possibly against an unrelated interface that reused the name
// (utunN on macOS). Persistent steps (rules, sysctls, nft tables) that fail
// stay journaled for a retry. When ctx ends, nothing is forgotten. The
// errors are returned.
func (c *configurer) Remove(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) == 0 {
		return nil
	}
	return c.undoLocked(ctx)
}

// rollbackLocked undoes a failed Apply. It must finish even when ctx is
// cancelled (the usual reason an Apply fails late), so it does not use ctx's
// cancellation.
func (c *configurer) rollbackLocked(ctx context.Context) {
	c.undoLocked(context.WithoutCancel(ctx))
}

// undoLocked undoes every applied step and the carried ones, reporting the
// first failure, then journals what is left: the persistent steps that
// failed, or nothing. When ctx ends it stops and leaves the journal as it
// is: the failures of a cancelled run say nothing about the system.
func (c *configurer) undoLocked(ctx context.Context) error {
	all := slices.Clone(c.carried)
	for _, s := range c.applied {
		if s.undo != nil {
			all = append(all, *s.undo)
		}
	}
	c.applied, c.carried = nil, nil
	var first error
	var keep []Step
	for i := len(all) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.exec(ctx, all[i]); err != nil && !alreadyUndone(all[i], err) {
			if first == nil {
				first = err
			}
			if all[i].Persistent {
				keep = append(keep, all[i])
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.j == nil {
		return first
	}
	slices.Reverse(keep)
	var jerr error
	if len(keep) == 0 {
		jerr = c.j.Forget(c.owner)
	} else {
		jerr = c.j.Record(c.owner, keep)
	}
	if first == nil {
		first = jerr
	}
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
	return newConfigurer(r, j, planDarwin, nil)
}

func newLinux(r Runner, j *Journal) Configurer {
	return newConfigurer(r, j, planLinux, linuxFullTunnel)
}
