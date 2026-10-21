package killswitch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

// The macOS kill switch is one pf anchor below the stock com.apple anchor
// point, which /etc/pf.conf declares (anchor "com.apple/*") and the system
// loads at boot. Its rules are evaluated with the other com.apple anchors,
// in name order; quick rules end the evaluation.
const (
	pfctlCmd = "pfctl"
	pfAnchor = "com.apple/250.latchwire"
)

// pfLinkLines are the rules that let a link come up, in pf.conf syntax.
//
//   - DHCP (P16): requests only from root's sockets (user root; the
//     system's DHCP client is root) and only to the broadcast address or
//     private and link-local networks, replies only from those (or
//     0.0.0.0); DHCPv6 only from a link-local address to ff02::1:2, replies
//     only from link-local addresses. An unprivileged process (macOS lets
//     any process bind ports below 1024) can thus not reach arbitrary
//     hosts on ports 67 or 547.
//   - IPv6 neighbour discovery: router and neighbour solicitation and
//     advertisement (redirects, 137, are left out, as in the nft rules),
//     only from a link-local source or to a link-local or link-scope
//     multicast destination. That covers the default router, duplicate
//     address detection and address resolution through the solicited-node
//     groups; neighbour discovery between two global addresses (an
//     endpoint on the local link) is not covered.
//   - MLD (reports out, queries in), which a switch that snoops MLD needs
//     to keep forwarding the solicited-node groups. pf cannot match the
//     hop limit (255 for neighbour discovery, 1 for MLD), so MLD is
//     limited to link-local and unspecified sources instead.
var pfLinkLines = []string{
	"pass out quick inet proto udp from any port 68 to { 255.255.255.255, " + pfDHCP4Nets + " } port 67 user root no state",
	"pass in quick inet proto udp from { 0.0.0.0, " + pfDHCP4Nets + " } port 67 to any port 68 no state",
	"pass out quick inet6 proto udp from fe80::/10 port 546 to ff02::1:2 port 547 user root no state",
	"pass in quick inet6 proto udp from fe80::/10 port 547 to any port 546 no state",
	"pass quick inet6 proto icmp6 from fe80::/10 to any icmp6-type { 133, 134, 135, 136 } no state",
	"pass quick inet6 proto icmp6 from any to { fe80::/10, ff02::/16 } icmp6-type { 133, 134, 135, 136 } no state",
	"pass out quick inet6 proto icmp6 from { fe80::/10, ::/128 } to any icmp6-type { 131, 143 } no state",
	"pass in quick inet6 proto icmp6 from { fe80::/10, ::/128 } to any icmp6-type 130 no state",
}

// pfDHCP4Nets are the networks a DHCPv4 server can be on.
const pfDHCP4Nets = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16"

// pfRules returns the anchor's ruleset for s, loaded with pfctl -a <anchor>
// -f - (which replaces the anchor's rules as a whole). s.Block must be set;
// s.FwMark has no meaning on macOS.
//
// In order, all quick: loopback and the tunnel interfaces pass both ways
// (stateless); then what a link needs (pfLinkLines); then UDP out to each
// endpoint, and UDP in from each endpoint to the tunnel's listen port only
// (the peer may start a handshake; no other local port is open to a source
// address anyone can forge), both keeping state, which also passes the
// replies and ICMP errors about the flow (path MTU). A tunnel still
// connecting (no interface, no listen port yet) gets the outbound rule
// only: its state lets the replies in. Everything else is blocked: outgoing
// packets with an error to the sender (TCP reset, ICMP unreachable) so
// applications fail at once, incoming ones silently.
//
// There is no DNS rule (P14): DNS passes only through the tunnel
// interfaces, so a query never leaves in clear text over the local
// network.
func pfRules(s State) ([]byte, error) {
	if err := validState(s); err != nil {
		return nil, err
	}
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
		b.WriteString("\n")
	}
	line("pass quick on lo0 all no state")
	for _, t := range s.Tunnels {
		if t.Iface != "" {
			line("pass quick on %s all no state", t.Iface)
		}
	}
	for _, l := range pfLinkLines {
		line("%s", l)
	}
	for _, t := range s.Tunnels {
		for _, e := range t.Endpoints {
			a := e.Addr().Unmap()
			af := "inet"
			if a.Is6() {
				af = "inet6"
			}
			line("pass out quick %s proto udp from any to %s port %d keep state", af, a, e.Port())
			if t.ListenPort != 0 {
				line("pass in quick %s proto udp from %s port %d to any port %d keep state", af, a, e.Port(), t.ListenPort)
			}
		}
	}
	line("block return out quick all")
	line("block drop in quick all")
	return []byte(b.String()), nil
}

// pfHasAppleAnchor reports whether out, the main ruleset as pfctl -sr
// prints it, evaluates the com.apple anchors for all packets: a line
// `anchor "com.apple/*" all` (or without "all"). A custom pf.conf without
// it would never evaluate the kill switch's anchor.
func pfHasAppleAnchor(out string) bool {
	for l := range strings.Lines(out) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "anchor" && f[1] == `"com.apple/*"` && (len(f) == 2 || len(f) == 3 && f[2] == "all") {
			return true
		}
	}
	return false
}

// parsePfToken finds the "Token : <n>" line pfctl -E prints (on stderr)
// and returns the token; pf never hands out 0.
func parsePfToken(out string) (uint64, bool) {
	for l := range strings.Lines(out) {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok || strings.TrimSpace(k) != "Token" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil || n == 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// pfFlushStep removes the anchor's rules (and tables, though it has none);
// idempotent, see netcfg.AlreadyUndone.
func pfFlushStep() netcfg.Step {
	return netcfg.Step{Name: pfctlCmd, Args: []string{"-a", pfAnchor, "-F", "all"}, Persistent: true}
}

// pfReleaseStep releases pf's enable reference tok: pf stops when the last
// reference goes, unless something enabled it without one (pfctl -e).
func pfReleaseStep(tok uint64) netcfg.Step {
	return netcfg.Step{Name: pfctlCmd, Args: []string{"-X", strconv.FormatUint(tok, 10)}, Persistent: true}
}

// pfFirewall is the macOS kill switch: the rules in one anchor and pf
// enabled with a reference (pfctl -E) of its own, so that pf runs while
// the kill switch is on and other users of pf (the application firewall,
// Internet Sharing) are not disturbed when it goes.
//
// Existing pf states are not killed (pfctl -k): the stock main ruleset
// creates none (packets it passes match no rule), and flushing every state
// (-F states) would cut other services' connections. A connection opened
// before the kill switch came on therefore gets no state and is blocked
// like any other packet; one that some other anchor keeps state for may
// survive.
type pfFirewall struct {
	r netcfg.Runner
	j *netcfg.Journal // nil: nothing is journaled

	mu sync.Mutex
	// tokens are the enable references held, oldest first; normally one.
	tokens []uint64
}

// newPf returns the firewall. A kill switch a previous run left in place
// (journaled) is taken over with its tokens, so the next Set or release
// handles them.
func newPf(r netcfg.Runner, j *netcfg.Journal) *pfFirewall {
	f := &pfFirewall{r: r, j: j}
	if j != nil {
		for _, s := range j.Entries()[JournalOwner] {
			if s.Name == pfctlCmd && len(s.Args) == 2 && s.Args[0] == "-X" {
				if n, err := strconv.ParseUint(s.Args[1], 10, 64); err == nil && n != 0 {
					f.tokens = append(f.tokens, n)
				}
			}
		}
	}
	return f
}

// Set puts the rules for s in place (s.Block) or removes them.
//
// Blocking checks the main ruleset (ErrUnsupported without the com.apple
// anchor point or pfctl; nothing is changed then), journals the removal of
// the anchor and of the references held, loads the rules, and enables pf
// with a new reference before it releases the older ones. Taking a new
// reference at every Set makes sure pf runs even when someone disabled it
// (pfctl -d drops every reference) since the previous Set. The new token is
// journaled as soon as it is known; a crash between pfctl -E and that
// write leaves an unreleased reference behind (pf then stays enabled with
// an empty anchor, which blocks nothing).
//
// Removing flushes the anchor and releases the references; both are
// idempotent. Whatever fails stays journaled for a retry.
func (f *pfFirewall) Set(ctx context.Context, s State) error {
	if !s.Block {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.releaseLocked(ctx)
	}
	rules, err := pfRules(s)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out, err := f.r.Run(ctx, pfctlCmd, []string{"-sr"}, nil)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return unsupportedError(msg.KillSwitchPfMissing)
		}
		return fmt.Errorf("killswitch: pfctl -sr: %w", err)
	}
	if !pfHasAppleAnchor(string(out)) {
		return unsupportedError(msg.KillSwitchPfNoAnchor)
	}
	if err := f.recordLocked(); err != nil {
		return err
	}
	if _, err := f.r.Run(ctx, pfctlCmd, []string{"-a", pfAnchor, "-f", "-"}, rules); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return unsupportedError(msg.KillSwitchPfMissing)
		}
		return fmt.Errorf("killswitch: pfctl -a %s -f -: %w", pfAnchor, err)
	}
	out, err = runCombined(ctx, f.r, pfctlCmd, []string{"-E"})
	if err != nil {
		return fmt.Errorf("killswitch: pfctl -E: %w", err)
	}
	tok, ok := parsePfToken(string(out))
	if !ok {
		return fmt.Errorf("killswitch: pfctl -E: no token in its output %q", strings.TrimSpace(string(out)))
	}
	old := f.tokens
	f.tokens = append(slices.Clone(old), tok)
	if err := f.recordLocked(); err != nil {
		return err
	}
	var kept []uint64
	for _, o := range old {
		if err := f.undo(ctx, pfReleaseStep(o)); err != nil {
			log.Printf("killswitch: releasing an older pf reference: %v", err)
			kept = append(kept, o)
		}
	}
	f.tokens = append(kept, tok)
	return f.recordLocked()
}

// Verify checks that pf is enabled (pfctl -s info: "Status: Enabled"),
// that the anchor still holds rules (pfctl -a <anchor> -sr), and that the
// main ruleset still evaluates the com.apple anchors (pfctl -sr). A main
// ruleset replaced by one without that anchor point (pfctl -f with a
// custom pf.conf) leaves the anchor's rules loaded but never evaluated:
// that is reported as ok false with an ErrUnsupported error, since setting
// the rules again cannot fix it.
func (f *pfFirewall) Verify(ctx context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out, err := f.r.Run(ctx, pfctlCmd, []string{"-s", "info"}, nil)
	if err != nil {
		return false, fmt.Errorf("killswitch: pfctl -s info: %w", err)
	}
	if !pfEnabled(string(out)) {
		return false, nil
	}
	out, err = f.r.Run(ctx, pfctlCmd, []string{"-a", pfAnchor, "-sr"}, nil)
	if err != nil {
		return false, fmt.Errorf("killswitch: pfctl -a %s -sr: %w", pfAnchor, err)
	}
	if strings.TrimSpace(string(out)) == "" {
		return false, nil
	}
	out, err = f.r.Run(ctx, pfctlCmd, []string{"-sr"}, nil)
	if err != nil {
		return false, fmt.Errorf("killswitch: pfctl -sr: %w", err)
	}
	if !pfHasAppleAnchor(string(out)) {
		return false, unsupportedError(msg.KillSwitchPfNoAnchor)
	}
	return true, nil
}

// pfEnabled reads the Status line of pfctl -s info ("Status: Enabled for
// 0 days 00:01:02   Debug: Urgent").
func pfEnabled(info string) bool {
	for l := range strings.Lines(info) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "Status:" {
			return f[1] == "Enabled"
		}
	}
	return false
}

// releaseLocked flushes the anchor and releases every reference held, then
// forgets the journal; what failed stays journaled.
func (f *pfFirewall) releaseLocked(ctx context.Context) error {
	first := f.undo(ctx, pfFlushStep())
	var kept []uint64
	for _, t := range f.tokens {
		if err := f.undo(ctx, pfReleaseStep(t)); err != nil {
			kept = append(kept, t)
			if first == nil {
				first = err
			}
		}
	}
	f.tokens = kept
	if first != nil {
		if err := f.recordLocked(); err != nil {
			log.Printf("killswitch: journaling the kill switch's removal: %v", err)
		}
		return first
	}
	if f.j != nil {
		return f.j.Forget(JournalOwner)
	}
	return nil
}

// recordLocked journals the undo of the kill switch: the anchor's flush,
// then the release of each reference (undone in reverse, so the references
// go first).
func (f *pfFirewall) recordLocked() error {
	if f.j == nil {
		return nil
	}
	steps := []netcfg.Step{pfFlushStep()}
	for _, t := range f.tokens {
		steps = append(steps, pfReleaseStep(t))
	}
	return f.j.Record(JournalOwner, steps)
}

// undo runs one undo step; one that finds nothing to undo succeeded.
func (f *pfFirewall) undo(ctx context.Context, s netcfg.Step) error {
	if _, err := f.r.Run(ctx, s.Name, s.Args, s.Stdin); err != nil && !netcfg.AlreadyUndone(s, err) {
		return fmt.Errorf("killswitch: %s: %w", s, err)
	}
	return nil
}

// runCombined runs a command whose result may be on stderr, through
// r.RunCombined when r has it.
func runCombined(ctx context.Context, r netcfg.Runner, name string, args []string) ([]byte, error) {
	if c, ok := r.(netcfg.CombinedRunner); ok {
		return c.RunCombined(ctx, name, args, nil)
	}
	return r.Run(ctx, name, args, nil)
}
