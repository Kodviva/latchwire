package netmon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	"github.com/Kodviva/latchwire/internal/netcfg"
)

const (
	// NoNetwork is the identity of a machine without a usable default route.
	NoNetwork = "none"
	// UnknownNetwork is the identity when there is a default gateway but its
	// MAC address cannot be read. It names no particular network, so it
	// must never match a trusted network.
	UnknownNetwork = "unknown"
)

// NetworkID names the network the machine is on: the first 16 hex digits of
// SHA-256 over "<gateway IP>|<gateway MAC>", for the default gateway of the
// primary interface. The SSID is not used (a root service cannot read it on
// macOS).
//
// The result is NoNetwork ("none") when there is no default route, or when
// it has no gateway address (an on-link route, such as a point-to-point
// tunnel). It is UnknownNetwork ("unknown") when the gateway's MAC address
// cannot be read (no neighbour entry yet, an incomplete or failed entry, or
// the lookup failing). It is never a hash of the gateway address alone,
// because 192.168.1.1 is the gateway of countless home and hotspot networks.
// Callers must treat NoNetwork and UnknownNetwork as untrusted. Only the
// IPv4 default route is consulted on macOS and Windows; Linux uses the
// preferred (lowest metric) default route of either family.
//
// The identity is a convenience, not an authentication: anyone who controls
// a network can reuse its gateway's IP and MAC address and be recognised as
// that network. An error means the system could not be queried.
func NetworkID(ctx context.Context, r netcfg.Runner) (string, error) {
	return networkID(ctx, r, runtime.GOOS)
}

func networkID(ctx context.Context, r netcfg.Runner, goos string) (string, error) {
	var (
		gw         netip.Addr
		iface      string
		neighCmd   string
		neighArgs  []string
		neighField string
	)
	switch goos {
	case "darwin":
		out, err := r.Run(ctx, "route", []string{"-n", "get", "default"}, nil)
		if err != nil {
			if strings.Contains(err.Error(), "not in table") {
				return NoNetwork, nil
			}
			return "", fmt.Errorf("netmon: route get default: %w", err)
		}
		gw, iface = parseDefaultRouteDarwin(string(out))
		neighCmd, neighField = "arp", "at"
	case "linux":
		out, err := r.Run(ctx, "ip", []string{"route", "show", "default"}, nil)
		if err != nil {
			return "", fmt.Errorf("netmon: ip route show default: %w", err)
		}
		gw, iface = parseDefaultRouteLinux(string(out))
		neighCmd, neighField = "ip", "lladdr"
	case "windows":
		out, err := r.Run(ctx, "route", []string{"print", "-4"}, nil)
		if err != nil {
			return "", fmt.Errorf("netmon: route print: %w", err)
		}
		gw = netcfg.WindowsDefaultGateway(string(out))
	default:
		return "", fmt.Errorf("netmon: network identity on %s: %w", goos, errUnsupported)
	}
	if !gw.IsValid() {
		return NoNetwork, nil
	}

	switch goos {
	case "darwin":
		neighArgs = []string{"-n", gw.String()}
	case "windows":
		neighCmd, neighArgs = "arp", []string{"-a", gw.String()}
	default:
		neighArgs = []string{"neigh", "show", gw.String()}
	}
	out, err := r.Run(ctx, neighCmd, neighArgs, nil)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return UnknownNetwork, nil
	}
	var mac string
	if goos == "windows" {
		mac = macFromArpWindows(string(out), gw)
	} else {
		mac = macFromNeighbours(string(out), neighField, iface)
	}
	if mac == "" {
		return UnknownNetwork, nil
	}
	sum := sha256.Sum256([]byte(gw.String() + "|" + mac))
	return hex.EncodeToString(sum[:])[:16], nil
}

// parseDefaultRouteDarwin reads `route -n get default`: the "gateway:" and
// "interface:" lines. gw is invalid when the gateway is not an IP address
// (for example "link#14").
func parseDefaultRouteDarwin(out string) (gw netip.Addr, iface string) {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "gateway":
			gw = parseGateway(val)
		case "interface":
			iface = val
		}
	}
	return gw, iface
}

// parseDefaultRouteLinux reads `ip route show default` and returns the
// gateway and interface of the preferred default route: the lowest metric,
// the first of equals. gw is invalid when that route has no usable "via".
func parseDefaultRouteLinux(out string) (gw netip.Addr, iface string) {
	best := -1
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		metric := 0
		if m := fieldAfter(f, "metric"); m != "" {
			if n, err := strconv.Atoi(m); err == nil && n >= 0 {
				metric = n
			}
		}
		if best >= 0 && metric >= best {
			continue
		}
		best = metric
		gw = parseGateway(fieldAfter(f, "via"))
		iface = fieldAfter(f, "dev")
	}
	return gw, iface
}

func fieldAfter(f []string, key string) string {
	for i := 0; i+1 < len(f); i++ {
		if f[i] == key {
			return f[i+1]
		}
	}
	return ""
}

// parseGateway parses an IP address, dropping a zone ("fe80::1%en0"); it
// returns the zero Addr for anything else.
func parseGateway(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.WithZone("").Unmap()
}

// macFromNeighbours returns the normalised MAC address from arp (field "at")
// or `ip neigh` (field "lladdr") output, or "" if there is none. An entry
// that names the interface iface is preferred over the first one.
func macFromNeighbours(out, field, iface string) string {
	first := ""
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		mac := normalizeMAC(fieldAfter(f, field))
		if mac == "" {
			continue
		}
		if iface != "" && (fieldAfter(f, "on") == iface || fieldAfter(f, "dev") == iface) {
			return mac
		}
		if first == "" {
			first = mac
		}
	}
	return first
}

// macFromArpWindows reads `arp -a <ip>`: a row of the address, the MAC in
// dashes and a type in the system's language. Only the row that starts with
// the address counts.
func macFromArpWindows(out string, ip netip.Addr) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if a, err := netip.ParseAddr(f[0]); err != nil || a != ip {
			continue
		}
		if mac := normalizeMAC(strings.ReplaceAll(f[1], "-", ":")); mac != "" {
			return mac
		}
	}
	return ""
}

// normalizeMAC returns s as six lower-case two-digit hex octets separated by
// colons. macOS prints octets without leading zeros ("a4:2b:b0:1:2:3"). It
// returns "" for anything that is not a MAC address, such as "(incomplete)",
// and for the all-zero address.
func normalizeMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	var zero = true
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return ""
		}
		n, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return ""
		}
		if n != 0 {
			zero = false
		}
		parts[i] = fmt.Sprintf("%02x", n)
	}
	if zero {
		return ""
	}
	return strings.Join(parts, ":")
}
