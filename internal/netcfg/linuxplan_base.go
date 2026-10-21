package netcfg

import "net/netip"

// planLinux: an address with a prefix shorter than the host length already
// installs its connected route, so that route is not added again.
func planLinux(p Plan) []step {
	iface := p.Iface
	var out []step
	connected := map[netip.Prefix]bool{}
	for _, a := range p.Addresses {
		out = append(out, step{
			do:   command("ip", "address", "add", a.String(), "dev", iface),
			undo: undoOf("ip", "address", "del", a.String(), "dev", iface),
		})
		if a.Bits() < a.Addr().BitLen() {
			connected[a.Masked()] = true
		}
	}
	out = append(out, step{do: command("ip", "link", "set", iface, "up")})
	for _, r := range p.Routes {
		r = r.Masked()
		if connected[r] {
			continue
		}
		out = append(out, step{
			do:   command("ip", "route", "add", r.String(), "dev", iface),
			undo: undoOf("ip", "route", "del", r.String(), "dev", iface),
		})
	}
	return out
}
