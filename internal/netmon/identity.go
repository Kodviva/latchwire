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

// noNetwork is the identity of a machine without a usable default route.
const noNetwork = "none"

// NetworkID names the network the machine is on: the first 16 hex digits of
// SHA-256 over "<gateway IP>|<gateway MAC>", for the default gateway of the
// primary interface. The SSID is not used (a root service cannot read it on
// macOS).
//
// The result is "none" when there is no default route, or when it has no
// gateway address (an on-link route, such as a point-to-point tunnel). Only
// the IPv4 default route is consulted on macOS; Linux uses the preferred
// (lowest metric) default route of either family. If the gateway's MAC
// address is unknown (not in the neighbour table yet, or unresolvable) the
// gateway address alone is hashed, so the same network can have two
// identities depending on whether the neighbour entry was present.
//
// An error means the system could not be queried; it is never "none".
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
				return noNetwork, nil
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
	default:
		return "", fmt.Errorf("netmon: network identity on %s: %w", goos, errUnsupported)
	}
	if !gw.IsValid() {
		return noNetwork, nil
	}

	if goos == "darwin" {
		neighArgs = []string{"-n", gw.String()}
	} else {
		neighArgs = []string{"neigh", "show", gw.String()}
	}
	mac := ""
	out, err := r.Run(ctx, neighCmd, neighArgs, nil)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		// No MAC: fall back to the gateway address alone.
	} else {
		mac = macFromNeighbours(string(out), neighField, iface)
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
