package netcfg

import "strconv"

// command builds a Step; undo is a pointer so that "nothing to undo" is nil.
func command(name string, args ...string) Step { return Step{Name: name, Args: args} }

func undoOf(name string, args ...string) *Step {
	s := command(name, args...)
	return &s
}

// planDarwin: addresses are point-to-point on utun, routes point at the
// interface. Setting the first address marks the interface up. Default
// routes (0.0.0.0/0, ::/0) are left to the full-tunnel plan.
func planDarwin(p Plan) []step {
	iface := p.Iface
	var out []step
	for _, a := range p.Addresses {
		ip := a.Addr().String()
		if a.Addr().Is4() {
			out = append(out, step{
				do:   command("ifconfig", iface, "inet", ip, ip, "alias"),
				undo: undoOf("ifconfig", iface, "inet", ip, "-alias"),
			})
		} else {
			out = append(out, step{
				do:   command("ifconfig", iface, "inet6", ip, "prefixlen", strconv.Itoa(a.Bits()), "alias"),
				undo: undoOf("ifconfig", iface, "inet6", ip, "-alias"),
			})
		}
	}
	for _, r := range p.Routes {
		r = r.Masked()
		if r.Bits() == 0 {
			continue
		}
		out = append(out, step{
			do:   command("route", "-q", "-n", "add", family(r), r.String(), "-interface", iface),
			undo: undoOf("route", "-q", "-n", "delete", family(r), r.String(), "-interface", iface),
		})
	}
	return out
}
