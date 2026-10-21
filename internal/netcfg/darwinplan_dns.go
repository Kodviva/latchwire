package netcfg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kodviva/latchwire/internal/msg"
)

// macOS DNS goes through configd's dynamic store, with scutil reading its
// commands from stdin (never a shell, never arguments). Only State: keys
// are written: they live in memory and are gone after a reboot. networksetup
// is never used: it changes the persistent Setup: preferences.
//
// DNSPrimary replaces the DNS dictionary of the primary network service
// (State:/Network/Service/<id>/DNS) with the tunnel's servers and search
// domains. The original dictionary is read first and journaled in the undo
// step, which writes it back, or removes the key when there was none. The
// undo outlives the tunnel's interface (Persistent, P7), and it restores
// only while the key still holds what Latchwire wrote: a dictionary written
// since by somebody else (DHCP, another VPN) is left alone. A leak is safer
// than clobbering a newer configuration. Refresh follows the primary
// service when it changes (P9).
//
// DNSScoped writes a key of Latchwire's own, State:/Network/Service/
// latchwire-<iface>/DNS, with the servers and the search domains as
// SupplementalMatchDomains: only names in those domains go to the tunnel's
// servers. Its undo removes the key.

// Applied.DNS values on macOS.
const (
	DNSOutcomeScutilPrimary = "scutil-primary" // the primary service's DNS is the tunnel's
	// DNSOutcomeScutilPrimaryOverridden: as scutil-primary, but DNS servers
	// set by hand for the service (Setup:) take precedence, so the
	// tunnel's servers may not be used.
	DNSOutcomeScutilPrimaryOverridden = "scutil-primary-overridden"
	DNSOutcomeScutilScoped            = "scutil-scoped" // supplemental resolver for the search domains
)

const scutilCmd = "scutil"

// errScutilUnreadable marks scutil output that is not what it should be.
var errScutilUnreadable = errors.New("unreadable scutil output")

const (
	globalIPv4Key = "State:/Network/Global/IPv4"
	globalIPv6Key = "State:/Network/Global/IPv6"
	serviceKeyPfx = "State:/Network/Service/"
	dnsKeySuffix  = "/DNS"
)

func serviceDNSKey(id string) string { return serviceKeyPfx + id + dnsKeySuffix }
func setupDNSKey(id string) string   { return "Setup:/Network/Service/" + id + dnsKeySuffix }
func scopedServiceID(iface string) string {
	return "latchwire-" + iface
}

// serviceIDOK reports whether id is safe inside a dynamic-store key and as
// one scutil word: letters, digits, dots, hyphens and underscores, starting
// with a letter or digit. Service IDs are UUIDs.
func serviceIDOK(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '-' || c == '_'):
		default:
			return false
		}
	}
	return true
}

// scEntry is one key of a dynamic-store dictionary as scutil prints it. A
// value scutil prints as an array has array set; nested marks a value
// that is a dictionary (or holds one), which is not kept. number is set
// for keys written as numbers (d.add KEY # N); scutil's output does not
// tell numbers from strings.
type scEntry struct {
	key    string
	array  bool
	nested bool
	number bool
	vals   []string
}

type scDict []scEntry

// cutField splits "key : value" (the value may be empty: "key :").
func cutField(line string) (k, v string, ok bool) {
	if k, v, ok = strings.Cut(line, " : "); !ok {
		k, ok = strings.CutSuffix(line, " :")
	}
	return k, v, ok && k != ""
}

// skipBlock returns the index after the line that closes the block opened
// on lines[i], or -1.
func skipBlock(lines []string, i int) int {
	depth := 0
	for ; i < len(lines); i++ {
		switch {
		case strings.HasSuffix(lines[i], "{"):
			depth++
		case lines[i] == "}":
			depth--
		}
		if depth == 0 {
			return i + 1
		}
	}
	return -1
}

// parseScutilDict reads the output of scutil's "show KEY": a dictionary,
// or "No such key" (found false). Scalars and arrays of scalars are read;
// nested dictionaries are skipped and marked.
func parseScutilDict(out string) (d scDict, found bool, err error) {
	var lines []string
	for l := range strings.Lines(out) {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 1 && lines[0] == "No such key" {
		return nil, false, nil
	}
	if len(lines) < 2 || lines[0] != "<dictionary> {" || lines[len(lines)-1] != "}" {
		return nil, false, errScutilUnreadable
	}
	body := lines[1 : len(lines)-1]
	d = scDict{}
	for i := 0; i < len(body); {
		k, v, ok := cutField(body[i])
		if !ok {
			return nil, false, errScutilUnreadable
		}
		e := scEntry{key: k}
		switch {
		case v == "<array> {":
			e.array = true
			for i++; i < len(body) && body[i] != "}"; {
				_, ev, ok := cutField(body[i])
				if !ok {
					return nil, false, errScutilUnreadable
				}
				if strings.HasSuffix(ev, "{") {
					e.nested = true
					if i = skipBlock(body, i); i < 0 {
						return nil, false, errScutilUnreadable
					}
					continue
				}
				e.vals = append(e.vals, ev)
				i++
			}
			if i >= len(body) {
				return nil, false, errScutilUnreadable
			}
			i++
		case strings.HasSuffix(v, "{"):
			e.nested = true
			if i = skipBlock(body, i); i < 0 {
				return nil, false, errScutilUnreadable
			}
		default:
			e.vals = []string{v}
			i++
		}
		d = append(d, e)
	}
	return d, true, nil
}

// dnsKeyKinds are the keys of a service's DNS dictionary that an undo
// writes back, with their types: 's' string, 'n' number, 'a' array of
// strings (SCSchemaDefinitions.h, kSCPropNetDNS*). Others are dropped:
// their type cannot be read from scutil's output, and an array of numbers
// (SupplementalMatchOrders) cannot be written with d.add.
var dnsKeyKinds = map[string]byte{
	"ConfirmedServiceID":               's',
	"DomainName":                       's',
	"Options":                          's',
	"SearchOrder":                      'n',
	"ServerPort":                       'n',
	"ServerTimeout":                    'n',
	"ServiceIdentifier":                'n',
	"SupplementalMatchDomainsNoSearch": 'n',
	"SearchDomains":                    'a',
	"ServerAddresses":                  'a',
	"SortList":                         'a',
	"SupplementalMatchDomains":         'a',
}

// scutilValueOK reports whether v can be written back by d.add as it was:
// printable ASCII without quotes or backslashes (a value with spaces is
// quoted).
func scutilValueOK(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// typeMarker reports whether v, as d.add's first value, would be read as
// the type ("*", "#", "?", "%"), quoted or not.
func typeMarker(v string) bool {
	return len(v) == 1 && strings.Contains("*#?%", v)
}

// restorableDNS returns the entries of d that an undo can write back
// exactly, and the keys it drops.
func restorableDNS(d scDict) (keep scDict, dropped []string) {
	for _, e := range d {
		kind, ok := dnsKeyKinds[e.key]
		ok = ok && !e.nested
		for _, v := range e.vals {
			ok = ok && scutilValueOK(v)
		}
		switch kind {
		case 'a':
			// d.add cannot write an empty array ("d.add: no
			// values."), and an empty array says nothing.
			ok = ok && e.array && len(e.vals) > 0
		case 's':
			ok = ok && !e.array && len(e.vals) == 1 && e.vals[0] != "" && !typeMarker(e.vals[0])
		case 'n':
			ok = ok && !e.array && len(e.vals) == 1
			if ok {
				_, err := strconv.ParseInt(e.vals[0], 10, 64)
				ok = err == nil
			}
			e.number = true
		}
		if !ok {
			dropped = append(dropped, e.key)
			continue
		}
		e.vals = slices.Clone(e.vals)
		keep = append(keep, e)
	}
	return keep, dropped
}

// scutilWord quotes v when scutil would otherwise split it or read it as
// a type.
func scutilWord(v string) string {
	if v == "" || strings.ContainsRune(v, ' ') || typeMarker(v) {
		return `"` + v + `"`
	}
	return v
}

// addLine is the d.add command that adds e, without its newline.
func addLine(e scEntry) string {
	parts := []string{"d.add", e.key}
	switch {
	case e.array:
		parts = append(parts, "*")
	case e.number:
		parts = append(parts, "#")
	}
	for _, v := range e.vals {
		parts = append(parts, scutilWord(v))
	}
	return strings.Join(parts, " ")
}

// dictScript is the scutil script that builds d as the current dictionary.
func dictScript(d scDict) string {
	var b strings.Builder
	b.WriteString("d.init\n")
	for _, e := range d {
		b.WriteString(addLine(e) + "\n")
	}
	return b.String()
}

// sameDict reports whether got (as read) holds exactly want's keys and
// values. Types are not compared: scutil prints numbers as strings.
func sameDict(got, want scDict) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		i := slices.IndexFunc(got, func(g scEntry) bool { return g.key == w.key })
		if i < 0 || got[i].nested || got[i].array != w.array || !slices.Equal(got[i].vals, w.vals) {
			return false
		}
	}
	return true
}

// validateDNS checks what goes into DNS commands: servers without a zone
// (a link-local server's zone names an interface of the user's machine,
// useless elsewhere, so the tunnel is refused rather than half
// configured) and plain search domains.
func validateDNS(p Plan) error {
	for _, a := range p.DNS {
		if a.Zone() != "" {
			return fmt.Errorf(msg.NetZonedDNSFmt, a)
		}
	}
	for _, d := range p.DNSSearch {
		if !plainDomain(d) {
			return fmt.Errorf(msg.NetBadSearchDomainFmt, d)
		}
	}
	return nil
}

// primaryDict is what DNSPrimary writes: the servers and, when there are
// any, the search domains.
func primaryDict(p Plan) scDict {
	d := scDict{{key: "ServerAddresses", array: true, vals: addrStrings(p.DNS)}}
	if len(p.DNSSearch) > 0 {
		d = append(d, scEntry{key: "SearchDomains", array: true, vals: slices.Clone(p.DNSSearch)})
	}
	return d
}

// scopedDict is what DNSScoped writes.
func scopedDict(p Plan) scDict {
	return scDict{
		{key: "ServerAddresses", array: true, vals: addrStrings(p.DNS)},
		{key: "SupplementalMatchDomains", array: true, vals: slices.Clone(p.DNSSearch)},
	}
}

func scutilStep(script string, persistent bool) Step {
	return Step{Name: scutilCmd, Stdin: []byte(script), Persistent: persistent}
}

// setDNSStep writes d to key.
func setDNSStep(key string, d scDict) Step {
	return scutilStep(dictScript(d)+"set "+key+"\n", false)
}

// primaryUndo is the undo of writing ours to key: "# expect" comment lines
// (scutil ignores them) carry what Latchwire wrote, then the original
// dictionary is written back, or the key removed when there was none.
func primaryUndo(key string, ours, orig scDict, found bool) *Step {
	var b strings.Builder
	for _, e := range ours {
		b.WriteString("# expect " + addLine(e) + "\n")
	}
	if found {
		b.WriteString(dictScript(orig) + "set " + key + "\n")
	} else {
		b.WriteString("remove " + key + "\n")
	}
	s := scutilStep(b.String(), true)
	return &s
}

// scutilUndo is what an scutil undo step says: the key it sets or removes
// and, when it has "# expect" lines, what the key must still hold.
type scutilUndo struct {
	key    string
	remove bool
	expect scDict // nil: the key is Latchwire's by name
}

// parseScutilUndo reads an undo step written by primaryUndo or the
// scoped plan.
func parseScutilUndo(stdin []byte) (u scutilUndo, ok bool) {
	var last string
	for l := range strings.Lines(string(stdin)) {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		last = l
		rest, isExpect := strings.CutPrefix(l, "# expect d.add ")
		if !isExpect {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 || f[1] != "*" {
			return scutilUndo{}, false
		}
		u.expect = append(u.expect, scEntry{key: f[0], array: true, vals: f[2:]})
	}
	op, key, _ := strings.Cut(last, " ")
	id, okKey := strings.CutPrefix(key, serviceKeyPfx)
	id, okSuffix := strings.CutSuffix(id, dnsKeySuffix)
	if (op != "set" && op != "remove") || !okKey || !okSuffix || !serviceIDOK(id) {
		return scutilUndo{}, false
	}
	u.key, u.remove = key, op == "remove"
	return u, true
}

// scutilOutputErr turns scutil's output to a write into an error: scutil
// reports failures on stdout and exits 0, and a write prints nothing when
// it succeeds.
func scutilOutputErr(stdin, out []byte) error {
	o := strings.TrimSpace(string(out))
	if o == "" {
		return nil
	}
	target := ""
	for l := range strings.Lines(string(stdin)) {
		if l = strings.TrimSpace(l); l != "" {
			target = l
		}
	}
	return fmt.Errorf("%s: %s", target, strings.Join(strings.Fields(o), " "))
}

// runStep runs s; for scutil, output is an error.
func runStep(ctx context.Context, r Runner, s Step) error {
	out, err := r.Run(ctx, s.Name, s.Args, s.Stdin)
	if err == nil && s.Name == scutilCmd {
		err = scutilOutputErr(s.Stdin, out)
	}
	return err
}

// scutilShow reads key from the dynamic store. Output that cannot be read
// is an error wrapping errScutilUnreadable.
func scutilShow(ctx context.Context, r Runner, key string) (scDict, bool, error) {
	out, err := r.Run(ctx, scutilCmd, nil, []byte("show "+key+"\n"))
	if err != nil {
		return nil, false, fmt.Errorf("scutil show %s: %w", key, err)
	}
	d, found, err := parseScutilDict(string(out))
	if err != nil {
		return nil, false, fmt.Errorf("scutil show %s: %w", key, err)
	}
	return d, found, nil
}

// primaryService returns the ID of the primary network service (IPv4, else
// IPv6), or "" when there is none.
func primaryService(ctx context.Context, r Runner) (string, error) {
	for _, k := range []string{globalIPv4Key, globalIPv6Key} {
		d, found, err := scutilShow(ctx, r, k)
		if err != nil {
			return "", err
		}
		i := slices.IndexFunc(d, func(e scEntry) bool { return e.key == "PrimaryService" })
		if !found || i < 0 {
			continue
		}
		e := d[i]
		if e.array || e.nested || len(e.vals) != 1 || !serviceIDOK(e.vals[0]) {
			return "", fmt.Errorf("scutil show %s: %w: PrimaryService %q", k, errScutilUnreadable, e.vals)
		}
		return e.vals[0], nil
	}
	return "", nil
}

// manualDNS reports whether the service has DNS servers set by hand
// (Setup:), which configd prefers to the State: ones.
func manualDNS(ctx context.Context, r Runner, svc string) bool {
	d, found, err := scutilShow(ctx, r, setupDNSKey(svc))
	if err != nil || !found {
		return false
	}
	return slices.ContainsFunc(d, func(e scEntry) bool { return e.key == "ServerAddresses" && len(e.vals) > 0 })
}

// primaryDNSStep reads svc's DNS dictionary and returns the step that
// replaces it with ours and journals it for the undo. A dictionary that
// cannot be read fails: it could not be restored.
func primaryDNSStep(ctx context.Context, r Runner, svc string, ours scDict) (step, error) {
	key := serviceDNSKey(svc)
	orig, found, err := scutilShow(ctx, r, key)
	if err != nil {
		if errors.Is(err, errScutilUnreadable) {
			return step{}, fmt.Errorf(msg.NetDNSUnreadableFmt, svc, err)
		}
		return step{}, err
	}
	keep, dropped := restorableDNS(orig)
	if len(dropped) > 0 {
		log.Printf("netcfg: %s: not restorable, left out of the undo: %s", key, strings.Join(dropped, ", "))
	}
	return step{do: setDNSStep(key, ours), undo: primaryUndo(key, ours, keep, found), dnsPrimary: true}, nil
}

// scutilUndoOurs decides whether the scutil undo step s may run: the key
// must still be there and, when s says what Latchwire wrote, still hold
// exactly that. Output that cannot be read leaves the key alone.
func scutilUndoOurs(ctx context.Context, r Runner, s Step) (bool, error) {
	u, ok := parseScutilUndo(s.Stdin)
	if !ok {
		return false, fmt.Errorf("scutil: unrecognised undo step %q", s.Stdin)
	}
	cur, found, err := scutilShow(ctx, r, u.key)
	switch {
	case errors.Is(err, errScutilUnreadable):
		log.Printf("netcfg: %s: cannot read it; leaving it alone", u.key)
		return false, nil
	case err != nil:
		return false, err
	case !found:
		return false, nil // gone: the service went down, or undone already
	case u.expect != nil && !sameDict(cur, u.expect):
		log.Printf("netcfg: %s: not the DNS settings Latchwire wrote; leaving them alone", u.key)
		return false, nil
	}
	return true, nil
}

// darwinDNS is the macOS dnsPlanner. c.mu is held; for DNSPrimary it keeps
// what Refresh follows in c.dn.
func (c *configurer) darwinDNS(ctx context.Context, r Runner, p Plan) ([]step, string, error) {
	if (p.DNSRole != DNSPrimary && p.DNSRole != DNSScoped) || len(p.DNS) == 0 {
		return nil, DNSOutcomeNone, nil
	}
	if err := validateDNS(p); err != nil {
		return nil, "", err
	}
	if p.DNSRole == DNSScoped {
		id := scopedServiceID(p.Iface)
		if !ifaceName(p.Iface) || !serviceIDOK(id) {
			return nil, "", fmt.Errorf("netcfg: interface name %q cannot name a DNS key", p.Iface)
		}
		if len(p.DNSSearch) == 0 {
			// Only search domains go to scoped servers: none, nothing
			// to answer.
			return nil, DNSOutcomeScutilScoped, nil
		}
		key := serviceDNSKey(id)
		undo := scutilStep("remove "+key+"\n", true)
		return []step{{do: setDNSStep(key, scopedDict(p)), undo: &undo}}, DNSOutcomeScutilScoped, nil
	}
	ours := primaryDict(p)
	svc, err := primaryService(ctx, r)
	if err != nil {
		return nil, "", err
	}
	c.dn.dnsPrimary, c.dn.dnsOurs = true, ours
	if svc == "" {
		log.Printf(msg.NetDNSNoServiceFmt, p.Iface)
		return nil, DNSOutcomeScutilPrimary, nil
	}
	s, err := primaryDNSStep(ctx, r, svc, ours)
	if err != nil {
		return nil, "", err
	}
	how := DNSOutcomeScutilPrimary
	if c.dn.overridden = manualDNS(ctx, r, svc); c.dn.overridden {
		log.Printf(msg.NetDNSManualFmt, p.Iface)
		how = DNSOutcomeScutilPrimaryOverridden
	}
	c.dn.dnsSvc = svc
	return []step{s}, how, nil
}

// refreshDNSLocked follows the primary service: when it changed, or its
// DNS no longer holds the tunnel's (DHCP wrote it again, the network came
// back), the old service's dictionary is restored (only if it still is
// Latchwire's) and the tunnel's written to the current one. Otherwise it
// only reads (P9). Offline (no primary service) nothing changes. A move
// that failed is not retried for moveBackoff unless the service changes.
// The daemon calls Refresh every 30 s as well (P12); a re-apply is logged
// once per service, so a tool that keeps rewriting the DNS does not flood
// the log.
func (c *configurer) refreshDNSLocked(ctx context.Context) error {
	d := &c.dn
	svc, err := primaryService(ctx, c.run)
	if err != nil || svc == "" {
		return err
	}
	rewritten := false
	if svc == d.dnsSvc {
		cur, found, err := scutilShow(ctx, c.run, serviceDNSKey(svc))
		if err != nil {
			return err
		}
		if found && sameDict(cur, d.dnsOurs) {
			return nil
		}
		rewritten = true
	}
	now := c.clock()
	if d.dnsFailed && d.dnsFailSvc == svc && now.Sub(d.dnsFailAt) < moveBackoff {
		return nil
	}
	if err := c.moveDNSLocked(ctx, svc, rewritten); err != nil {
		d.dnsFailed, d.dnsFailSvc, d.dnsFailAt = true, svc, now
		log.Printf("netcfg: %s: moving the DNS settings to network service %s failed (retried at the first network check after %v, which the daemon makes every 30 s and at network changes, or at once when the service changes): %v",
			d.iface, svc, moveBackoff, err)
		return err
	}
	d.dnsFailed = false
	if d.dnsLogged != svc {
		d.dnsLogged = svc
		log.Printf("netcfg: %s: DNS applied again to network service %s (the primary service changed or its DNS was rewritten; logged once per service)", d.iface, svc)
	}
	return nil
}

// moveDNSLocked undoes the applied primary DNS step, forgets it in the
// journal, then journals and applies one for svc. rewritten says that svc
// is the service the step wrote and its DNS was just read as no longer
// Latchwire's: the old undo has nothing to restore and is dropped without
// running (and without logging that it leaves the key alone).
func (c *configurer) moveDNSLocked(ctx context.Context, svc string, rewritten bool) error {
	d := &c.dn
	for i := len(c.applied) - 1; i >= 0; i-- {
		s := c.applied[i]
		if !s.dnsPrimary {
			continue
		}
		if !rewritten {
			if err := runUndo(ctx, c.run, *s.undo); err != nil {
				return err
			}
		}
		c.applied = slices.Delete(c.applied, i, i+1)
		d.dnsSvc = ""
		if err := c.recordLocked(); err != nil {
			return err
		}
	}
	s, err := primaryDNSStep(ctx, c.run, svc, d.dnsOurs)
	if err != nil {
		return err
	}
	if _, err := c.applyStepLocked(ctx, s); err != nil {
		// Its undo must not stay journaled: the change did not happen.
		if jerr := c.recordLocked(); jerr != nil {
			err = errors.Join(err, jerr)
		}
		return err
	}
	d.dnsSvc = svc
	was := d.overridden
	if d.overridden = manualDNS(ctx, c.run, svc); d.overridden && !was {
		log.Printf(msg.NetDNSManualFmt, d.iface)
	}
	return nil
}

// dnsFollow is what a macOS configurer keeps for the DNS Refresh follows
// (part of darwinFollow).
type dnsFollow struct {
	dnsPrimary bool   // DNSPrimary: the DNS follows the primary service
	dnsOurs    scDict // what is written
	dnsSvc     string // the service whose DNS holds it ("" none)
	// overridden: dnsSvc has DNS servers set by hand (Setup:), which
	// configd prefers (Applied.DNS scutil-primary-overridden), as last
	// read.
	overridden bool
	dnsLogged  string // the service a re-apply was last logged for
	dnsFailed  bool
	dnsFailSvc string
	dnsFailAt  time.Time
}
