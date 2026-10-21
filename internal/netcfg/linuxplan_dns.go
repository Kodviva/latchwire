package netcfg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/Kodviva/latchwire/internal/msg"
)

// Applied.DNS values: how a tunnel's DNS servers were put in place.
const (
	DNSOutcomeNone              = "none"               // the tunnel sets no DNS
	DNSOutcomeResolved          = "resolved"           // through systemd-resolved
	DNSOutcomeResolvconf        = "resolvconf"         // through openresolv, which takes the servers exclusively
	DNSOutcomeResolvconfShared  = "resolvconf-shared"  // through classic resolvconf: other interfaces' servers stay in the list
	DNSOutcomeScopedUnsupported = "scoped-unsupported" // scoped DNS wanted, resolvconf cannot do it: not applied
)

// ErrDNSUnsupported is returned, before any command runs, when a tunnel has
// DNS servers and the system has neither systemd-resolved nor resolvconf.
var ErrDNSUnsupported = errors.New(msg.NetDNSUnsupported)

// resolvConfPath is what linuxDNS reads to find a systemd-resolved stub.
const resolvConfPath = "/etc/resolv.conf"

// resolvedStub is the address systemd-resolved's stub listens on.
const resolvedStub = "127.0.0.53"

// linuxDNS returns the steps that point the tunnel's DNS servers at its
// interface, and how it did (an Applied.DNS value). It reads the system
// through r and resolvConf (the path of /etc/resolv.conf) and changes
// nothing. The steps need the interface to exist: they run after its
// addresses and link-up.
//
// systemd-resolved is in use when resolv.conf lists its stub or "resolvectl
// status" works; else resolvconf is used when it is installed; else the
// result is ErrDNSUnsupported. A resolv.conf stub does not count when the
// resolvectl command is missing. With resolvconf, scoped DNS cannot be
// expressed (resolvconf merges every nameserver into one list), so nothing
// is applied.
func linuxDNS(ctx context.Context, r Runner, resolvConf string, p Plan) ([]step, string, error) {
	if p.DNSRole == DNSNone || len(p.DNS) == 0 {
		return nil, DNSOutcomeNone, nil
	}
	for _, a := range p.DNS {
		// A link-local server needs its zone, which names an interface of
		// the user's machine; without one the address is useless, so the
		// tunnel is refused rather than half configured.
		if a.Zone() != "" {
			return nil, "", fmt.Errorf(msg.NetZonedDNSFmt, a)
		}
	}
	for _, d := range p.DNSSearch {
		if !plainDomain(d) {
			return nil, "", fmt.Errorf(msg.NetBadSearchDomainFmt, d)
		}
	}
	switch {
	case usesResolved(ctx, r, resolvConf):
		return planResolved(p), DNSOutcomeResolved, nil
	}
	flavor := resolvconfFlavor(ctx, r)
	if flavor == resolvconfAbsent {
		return nil, "", ErrDNSUnsupported
	}
	if p.DNSRole == DNSScoped {
		log.Printf(msg.NetDNSScopedUnsupportedFmt, p.Iface)
		return nil, DNSOutcomeScopedUnsupported, nil
	}
	if flavor == resolvconfOpen {
		return planResolvconf(p, true), DNSOutcomeResolvconf, nil
	}
	// The classic resolvconf has no exclusive mode: names may still go to
	// other interfaces' servers, outside the tunnel.
	log.Printf(msg.NetDNSSharedFmt, p.Iface)
	return planResolvconf(p, false), DNSOutcomeResolvconfShared, nil
}

// usesResolved reports whether systemd-resolved manages the system's DNS:
// resolvectl is installed and either resolv.conf lists the stub or its
// status works.
func usesResolved(ctx context.Context, r Runner, resolvConf string) bool {
	_, err := r.Run(ctx, "resolvectl", []string{"status"}, nil)
	if errors.Is(err, exec.ErrNotFound) {
		return false
	}
	if err == nil {
		return true
	}
	if b, rerr := os.ReadFile(resolvConf); rerr == nil {
		for line := range strings.Lines(string(b)) {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" && f[1] == resolvedStub {
				return true
			}
		}
	}
	return false
}

type resolvconfKind int

const (
	resolvconfAbsent  resolvconfKind = iota
	resolvconfClassic                // Debian/Ubuntu resolvconf: -a IFACE, -d IFACE only
	resolvconfOpen                   // openresolv: also -m METRIC, -x, -f
)

// resolvconfFlavor finds which resolvconf is installed. Only a missing
// command means none. openresolv prints a first line starting with
// "openresolv" for --version; when that fails or prints nothing useful, its
// -V is tried (openresolv answers it with its version or with its variables,
// NAMESERVERS=...; the classic resolvconf rejects it). Any other answer is
// the classic resolvconf, which rejects openresolv's flags (-m, -x, -f).
func resolvconfFlavor(ctx context.Context, r Runner) resolvconfKind {
	out, err := r.Run(ctx, "resolvconf", []string{"--version"}, nil)
	if errors.Is(err, exec.ErrNotFound) {
		return resolvconfAbsent
	}
	if err == nil && isOpenresolv(out) {
		return resolvconfOpen
	}
	if out, err = r.Run(ctx, "resolvconf", []string{"-V"}, nil); err == nil && isOpenresolv(out) {
		return resolvconfOpen
	}
	return resolvconfClassic
}

// isOpenresolv reports whether the output of "resolvconf --version" or
// "-V" is openresolv's.
func isOpenresolv(out []byte) bool {
	for line := range strings.Lines(string(out)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "openresolv") || strings.HasPrefix(line, "NAMESERVERS=") {
			return true
		}
	}
	return false
}

// plainDomain reports whether d is safe as one resolvectl argument and one
// word of a resolv.conf search line: letters, digits, hyphens and dots, not
// starting with a hyphen. (config.Parse allows no more; this keeps the
// planner safe by itself.)
func plainDomain(d string) bool {
	if d == "" || d[0] == '-' || d[0] == '.' {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

// planResolved: one "resolvectl revert" undoes all three commands. It is not
// persistent: the settings live on the link and go with it, and a revert
// that finds the link gone has nothing left to do (alreadyUndone).
func planResolved(p Plan) []step {
	iface := p.Iface
	out := []step{{
		do:   command("resolvectl", append([]string{"dns", iface}, addrStrings(p.DNS)...)...),
		undo: undoOf("resolvectl", "revert", iface),
	}}
	if p.DNSRole == DNSScoped {
		// Only the search domains are sent to the tunnel's servers
		// ("~" makes a domain routing-only), and the link is not the
		// default route for other names.
		if len(p.DNSSearch) > 0 {
			args := []string{"domain", iface}
			for _, d := range p.DNSSearch {
				args = append(args, "~"+d)
			}
			out = append(out, step{do: command("resolvectl", args...)})
		}
		return append(out, step{do: command("resolvectl", "default-route", iface, "false")})
	}
	args := append([]string{"domain", iface}, p.DNSSearch...)
	return append(out,
		step{do: command("resolvectl", append(args, "~.")...)},
		step{do: command("resolvectl", "default-route", iface, "true")},
	)
}

// planResolvconf: the entry lives in /run/resolvconf, outside the link, so
// its undo is persistent. openresolv gets metric 0 and exclusive mode, and
// -f on the delete (both quiet when the entry is gone); the classic
// resolvconf takes neither flag, and its "-d" of an unknown interface
// already succeeds (checked with resolvconf 1.91 on Debian 12).
func planResolvconf(p Plan, openresolv bool) []step {
	var b strings.Builder
	for _, s := range addrStrings(p.DNS) {
		b.WriteString("nameserver " + s + "\n")
	}
	if len(p.DNSSearch) > 0 {
		b.WriteString("search " + strings.Join(p.DNSSearch, " ") + "\n")
	}
	add := []string{"-a", p.Iface}
	del := []string{"-d", p.Iface}
	if openresolv {
		add = append(add, "-m", "0", "-x")
		del = append(del, "-f")
	}
	do := command("resolvconf", add...)
	do.Stdin = []byte(b.String())
	return []step{{do: do, undo: persistentUndo("resolvconf", del...)}}
}

// dnsUndoneAlready reports whether err from undo step s only says that what
// s removes is already gone: "resolvectl revert" of an interface that no
// longer exists, or resolvconf itself no longer installed.
func dnsUndoneAlready(s Step, err error) bool {
	switch s.Name {
	case "resolvectl":
		return slices.Contains(s.Args, "revert") &&
			(strings.Contains(err.Error(), "Failed to resolve interface") || strings.Contains(err.Error(), "No such device"))
	case "resolvconf":
		return errors.Is(err, exec.ErrNotFound)
	}
	return false
}
