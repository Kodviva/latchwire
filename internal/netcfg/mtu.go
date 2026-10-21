package netcfg

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// fallbackMTU is used when no path MTU can be found.
	fallbackMTU = 1420
	// minMTU is the smallest MTU a tunnel gets (the IPv6 minimum).
	minMTU = 1280
	// wgOverhead is the largest WireGuard encapsulation: IPv6 header (40),
	// UDP header (8) and WireGuard data header and tag (32).
	wgOverhead = 80
)

// tunnelMTU turns the smallest path MTU into the tunnel MTU, or returns
// fallbackMTU when none was found.
func tunnelMTU(path int) int {
	if path <= 0 {
		return fallbackMTU
	}
	return max(path-wgOverhead, minMTU)
}

// parseMTU returns the number after the first "mtu" word in out, skipping a
// "lock" word, or 0. It reads ifconfig (`... mtu 1500`), ip link
// (`... mtu 1500 qdisc ...`) and ip route (`cache mtu 1400`) output.
func parseMTU(out string) int {
	f := strings.Fields(out)
	for i := 0; i < len(f); i++ {
		if f[i] != "mtu" {
			continue
		}
		j := i + 1
		if j < len(f) && f[j] == "lock" {
			j++
		}
		if j < len(f) {
			if n, err := strconv.Atoi(f[j]); err == nil && n > 0 && n <= 65535 {
				return n
			}
		}
	}
	return 0
}

// wordAfter returns the word that follows the first occurrence of key in
// out, or "".
func wordAfter(out, key string) string {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == key {
			return f[i+1]
		}
	}
	return ""
}

// ifaceName reports whether s can be passed as an interface name argument.
func ifaceName(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '-' {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '-' || c == ':' || c == '@':
		default:
			return false
		}
	}
	return true
}

// ifaceMTU returns the MTU of the interface name, or 0.
func ifaceMTU(ctx context.Context, r Runner, cmd string, args ...string) int {
	out, err := r.Run(ctx, cmd, args, nil)
	if err != nil {
		return 0
	}
	return parseMTU(string(out))
}

// autoMTUDarwin finds the MTU of the default route's interface. The
// endpoints are not needed: macOS routes them through that interface.
func autoMTUDarwin(ctx context.Context, r Runner, _ []netip.AddrPort) int {
	out, err := r.Run(ctx, "route", []string{"-n", "get", "default"}, nil)
	if err != nil {
		return fallbackMTU
	}
	iface := wordAfter(string(out), "interface:")
	if !ifaceName(iface) {
		return fallbackMTU
	}
	return tunnelMTU(ifaceMTU(ctx, r, "ifconfig", iface))
}

// autoMTULinux finds, for each endpoint, the route's MTU (when the route
// sets one) or its interface's MTU, and uses the smallest.
func autoMTULinux(ctx context.Context, r Runner, endpoints []netip.AddrPort) int {
	path := 0
	for _, ep := range endpoints {
		out, err := r.Run(ctx, "ip", []string{"route", "get", ep.Addr().Unmap().String()}, nil)
		if err != nil {
			continue
		}
		n := parseMTU(string(out))
		if n == 0 {
			if dev := wordAfter(string(out), "dev"); ifaceName(dev) {
				n = ifaceMTU(ctx, r, "ip", "link", "show", dev)
			}
		}
		if n > 0 && (path == 0 || n < path) {
			path = n
		}
	}
	return tunnelMTU(path)
}
