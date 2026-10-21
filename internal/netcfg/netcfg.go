// Package netcfg configures a tunnel interface's addresses and routes by
// running the platform's network commands (ifconfig/route on macOS, ip on
// Linux). Linux routes full tunnels (0.0.0.0/0, ::/0) with fwmark policy
// routing; macOS with /1 routes and endpoint host routes that follow the
// default gateway (Refresh). DNS goes through systemd-resolved or resolvconf
// (Linux), or configd's dynamic store with scutil (macOS).
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
	"time"

	"github.com/Kodviva/latchwire/internal/msg"
)

// ErrFullTunnelUnsupported is returned, before any command runs, when a route
// is a default route (0.0.0.0/0 or ::/0) on a platform without full-tunnel
// support.
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
// one. MTUAuto says that MTU came from AutoMTU, so Refresh may change it
// when the network changes (macOS).
type Plan struct {
	Iface     string
	Addresses []netip.Prefix
	Routes    []netip.Prefix
	MTU       int
	MTUAuto   bool
	DNS       []netip.Addr
	DNSSearch []string
	DNSRole   DNSRole
	Endpoints []netip.AddrPort
	FwMark    uint32
}

// Applied reports what Apply put in place. Table is a full tunnel's routing
// table (Linux). RPFilter reports whether a full tunnel got its reverse-path
// filter (false when nft is not installed). DNS says how the tunnel's DNS
// servers were applied (a DNSOutcome value; "" where Apply does not handle
// DNS).
type Applied struct {
	MTU        int
	FullTunnel bool
	Table      uint32
	RPFilter   bool
	DNS        string
}

// Configurer sets up and removes one interface's network configuration.
// Remove undoes what Apply did; it is a no-op when nothing is applied.
// Refresh re-reads the system state the applied configuration depends on
// (the default gateway, the automatic MTU) and changes the configuration
// only when that state changed. The three are serialized.
type Configurer interface {
	Apply(ctx context.Context, p Plan) (Applied, error)
	Refresh(ctx context.Context) error
	Remove(ctx context.Context) error
}

// step is one command and the command that undoes it (nil: nothing to undo).
// missing, when set, makes a command that is not installed (exec.ErrNotFound)
// no failure: the message is logged and the step skipped. hostRoute marks a
// macOS endpoint host route: Refresh moves it, and a route to the endpoint
// that exists already is left alone (the step is skipped). dnsPrimary marks
// the macOS step that writes the primary service's DNS: Refresh moves it.
type step struct {
	do         Step
	undo       *Step
	missing    string
	hostRoute  bool
	dnsPrimary bool
}

// planner turns a Plan into the commands for one platform.
type planner func(p Plan) []step

// dnsPlanner returns the steps that apply p's DNS and how (Applied.DNS). It
// may read system state through r, changes none, and fails with
// ErrDNSUnsupported when the DNS cannot be applied.
type dnsPlanner func(ctx context.Context, r Runner, p Plan) ([]step, string, error)

// fullPlanner returns the extra steps of a full tunnel and its table. It may
// read system state through r.
type fullPlanner func(ctx context.Context, r Runner, p Plan) ([]step, uint32, error)

type configurer struct {
	run     Runner
	j       *Journal // nil: nothing is journaled
	plan    planner
	full    fullPlanner                     // nil: full tunnels are not supported
	refresh func(ctx context.Context) error // nil: Refresh does nothing; called with mu held
	dns     dnsPlanner                      // nil: DNS is not applied

	mu      sync.Mutex
	owner   string
	applied []step // undo order is reverse
	// carried are persistent undo steps an earlier configurer of the same
	// owner could not run; they stay journaled ahead of this one's.
	carried []Step
	dn      darwinFollow     // macOS: what Refresh follows
	now     func() time.Time // nil: time.Now
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
	c.dn = darwinFollow{iface: p.Iface, mtu: p.MTU, mtuAuto: p.MTUAuto}
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
	// DNS goes last: its commands need the interface to exist and be up.
	// Its system reads happen before the first change, so an unsupported
	// system fails Apply with nothing to undo.
	// Only one tunnel at a time answers every name (P12): a second
	// DNSPrimary tunnel would journal the first one's servers as the
	// original and leave them behind.
	busy := false
	if c.dns != nil && p.DNSRole == DNSPrimary && len(p.DNS) > 0 {
		if holder, ok := c.claimPrimaryDNS(p.Iface); !ok {
			log.Printf(msg.NetDNSPrimaryBusyFmt, p.Iface, holder)
			busy, res.DNS = true, DNSOutcomePrimaryBusy
		}
	}
	if c.dns != nil && !busy {
		ds, how, err := c.dns(ctx, c.run, p)
		if err != nil {
			c.releasePrimaryDNS()
			return Applied{}, err
		}
		steps = append(steps, ds...)
		res.DNS = how
	}
	for _, s := range steps {
		ran, err := c.applyStepLocked(ctx, s)
		if err != nil {
			c.rollbackLocked(ctx)
			return Applied{}, err
		}
		if ran && s.do.Name == "nft" && full {
			res.RPFilter = true
		}
	}
	return res, nil
}

// undoListLocked is what the journal holds for the owner: the carried steps,
// then the undo steps of what is applied (apply order).
func (c *configurer) undoListLocked() []Step {
	undo := slices.Clone(c.carried)
	for _, s := range c.applied {
		if s.undo != nil {
			undo = append(undo, *s.undo)
		}
	}
	return undo
}

// recordLocked journals undoListLocked.
func (c *configurer) recordLocked() error {
	if c.j == nil {
		return nil
	}
	return c.j.Record(c.owner, c.undoListLocked())
}

// applyStepLocked journals s's undo, then runs s and adds it to the applied
// steps. A step skipped as allowed (a missing optional command, a foreign
// host route to the endpoint, see existingHostRoute) reports ran false and
// leaves its undo out of the journal. On
// failure the journal may still hold s's undo; the caller rolls back or
// re-records.
func (c *configurer) applyStepLocked(ctx context.Context, s step) (ran bool, err error) {
	// The undo step reaches the journal before the change it undoes.
	if s.undo != nil && c.j != nil {
		if err := c.j.Record(c.owner, append(c.undoListLocked(), *s.undo)); err != nil {
			return false, err
		}
	}
	if err := c.exec(ctx, s.do); err != nil {
		switch {
		case s.missing != "" && errors.Is(err, exec.ErrNotFound):
			log.Print(s.missing)
		case s.hostRoute && routeExists(err):
			retry, herr := existingHostRoute(ctx, c.run, s.do, c.dn.iface)
			if herr != nil {
				return false, herr
			}
			if retry {
				if err := c.exec(ctx, s.do); err != nil {
					return false, err
				}
				c.applied = append(c.applied, s)
				return true, nil
			}
		default:
			return false, err
		}
		if s.undo != nil {
			return false, c.recordLocked()
		}
		return false, nil
	}
	c.applied = append(c.applied, s)
	return true, nil
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
		if err := runUndo(ctx, c.run, old[i]); err != nil && old[i].Persistent && ctx.Err() == nil {
			c.carried = append(c.carried, old[i])
		}
	}
	slices.Reverse(c.carried)
	return ctx.Err()
}

// Refresh re-reads the network state the applied configuration follows and
// updates it; see the platform's refresh. Linux has none: its full tunnel
// does not depend on the gateway, and its automatic MTU, read from the
// endpoint's route, would see the tunnel's own table once it is up.
func (c *configurer) Refresh(ctx context.Context) error {
	if c.refresh == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) == 0 {
		return nil
	}
	return c.refresh(ctx)
}

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
		c.releasePrimaryDNS()
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
	all := c.undoListLocked()
	c.applied, c.carried, c.dn = nil, nil, darwinFollow{}
	c.releasePrimaryDNS()
	var first error
	var keep []Step
	for i := len(all) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runUndo(ctx, c.run, all[i]); err != nil {
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

// primaryDNS is the configurer whose DNS answers every name (DNSPrimary):
// at most one per process (P12), from its Apply until its Remove or
// rollback.
var primaryDNS struct {
	mu    sync.Mutex
	owner *configurer
	iface string
}

// claimPrimaryDNS makes c the DNSPrimary owner, or reports the interface
// of the configurer that is.
func (c *configurer) claimPrimaryDNS(iface string) (holder string, ok bool) {
	primaryDNS.mu.Lock()
	defer primaryDNS.mu.Unlock()
	if primaryDNS.owner != nil && primaryDNS.owner != c {
		return primaryDNS.iface, false
	}
	primaryDNS.owner, primaryDNS.iface = c, iface
	return "", true
}

// releasePrimaryDNS gives up the DNSPrimary ownership if c holds it.
func (c *configurer) releasePrimaryDNS() {
	primaryDNS.mu.Lock()
	defer primaryDNS.mu.Unlock()
	if primaryDNS.owner == c {
		primaryDNS.owner, primaryDNS.iface = nil, ""
	}
}

func (c *configurer) exec(ctx context.Context, s Step) error {
	if err := runStep(ctx, c.run, s); err != nil {
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
	c := newConfigurer(r, j, planDarwin, nil)
	c.full = c.darwinFullTunnel
	c.refresh = c.refreshDarwin
	c.dns = c.darwinDNS
	return c
}

func newLinux(r Runner, j *Journal) Configurer {
	c := newConfigurer(r, j, planLinux, linuxFullTunnel)
	c.dns = func(ctx context.Context, r Runner, p Plan) ([]step, string, error) {
		return linuxDNS(ctx, r, resolvConfPath, p)
	}
	return c
}
