package desktop

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Kodviva/latchwire/internal/msg"
)

// ServerPeer is one server the tunnel connects to, as the form collects it.
type ServerPeer struct {
	Endpoint     string // host:port
	PublicKey    string // base64
	PresharedKey string // base64, optional; a secret
	AllTraffic   bool   // send everything through this peer
	Networks     []string
	Keepalive    int // seconds, 0 = off
}

// ServerForm is the whole form: the tunnel address and its servers. The
// private key is never part of it; Bind adds the card's key reference.
type ServerForm struct {
	Address string // comma-separated, bare addresses get a host prefix
	DNS     []string
	MTU     int // 0 = automatic
	Peers   []ServerPeer
}

// FieldError names the form field that failed. Its text holds the field name
// and a message that never contains a value, because a value may be the
// preshared key.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Err.Error() }

func (e *FieldError) Unwrap() error { return e.Err }

func invalid(field, name string) error {
	return &FieldError{Field: field, Err: fmt.Errorf(msg.ConfigInvalidValueFmt, name)}
}

// Conf renders the form as tunnel configuration text for Bind. The checks
// match the daemon's parser, so text that Conf returns also parses.
func (f ServerForm) Conf() (string, error) {
	addrs, err := prefixList(strings.Split(f.Address, ","))
	if err != nil || len(addrs) == 0 {
		return "", invalid("address", "Address")
	}
	for _, d := range f.DNS {
		d = strings.TrimSpace(d)
		if _, err := netip.ParseAddr(d); err != nil && !validDNSName(d) {
			return "", invalid("dns", "DNS")
		}
	}
	if f.MTU != 0 && (f.MTU < 1280 || f.MTU > 9000) {
		return "", &FieldError{Field: "mtu", Err: fmt.Errorf("%s", msg.ConfigMTURange)}
	}
	if len(f.Peers) == 0 {
		return "", invalid("peers", "Peer")
	}

	var b strings.Builder
	b.WriteString("[Interface]\nAddress = " + strings.Join(addrs, ", ") + "\n")
	if dns := cleanList(f.DNS); len(dns) > 0 {
		b.WriteString("DNS = " + strings.Join(dns, ", ") + "\n")
	}
	if f.MTU != 0 {
		b.WriteString("MTU = " + strconv.Itoa(f.MTU) + "\n")
	}

	seen := map[string]bool{}
	for i, p := range f.Peers {
		field := func(name string) string { return fmt.Sprintf("peers[%d].%s", i, name) }
		if !validEndpoint(p.Endpoint) {
			return "", invalid(field("endpoint"), "Endpoint")
		}
		if !validKey(p.PublicKey) || seen[p.PublicKey] {
			return "", invalid(field("publickey"), "PublicKey")
		}
		seen[p.PublicKey] = true
		if p.PresharedKey != "" && !validKey(p.PresharedKey) {
			return "", invalid(field("presharedkey"), "PresharedKey")
		}
		allowed := "0.0.0.0/0, ::/0"
		if !p.AllTraffic {
			nets, err := prefixList(p.Networks)
			if err != nil || len(nets) == 0 {
				return "", invalid(field("networks"), "AllowedIPs")
			}
			allowed = strings.Join(nets, ", ")
		}
		if p.Keepalive < 0 || p.Keepalive > 65535 {
			return "", invalid(field("keepalive"), "PersistentKeepalive")
		}

		b.WriteString("\n[Peer]\nPublicKey = " + p.PublicKey + "\n")
		if p.PresharedKey != "" {
			b.WriteString("PresharedKey = " + p.PresharedKey + "\n")
		}
		b.WriteString("AllowedIPs = " + allowed + "\nEndpoint = " + p.Endpoint + "\n")
		if p.Keepalive > 0 {
			b.WriteString("PersistentKeepalive = " + strconv.Itoa(p.Keepalive) + "\n")
		}
	}
	return b.String(), nil
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// prefixList normalizes CIDR prefixes and bare addresses; a bare address
// becomes a host prefix. Items may themselves hold commas.
func prefixList(in []string) ([]string, error) {
	var out []string
	for _, s := range in {
		for _, item := range cleanList(strings.Split(s, ",")) {
			var p netip.Prefix
			if strings.Contains(item, "/") {
				var err error
				if p, err = netip.ParsePrefix(item); err != nil {
					return nil, err
				}
			} else {
				a, err := netip.ParseAddr(item)
				if err != nil {
					return nil, err
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			if p.Addr().Zone() != "" {
				return nil, fmt.Errorf("zone")
			}
			out = append(out, p.String())
		}
	}
	return out, nil
}

func validKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// validEndpoint wants host:port with a port in 1-65535 and no character that
// could end or split a config line.
func validEndpoint(s string) bool {
	for _, r := range s {
		if r <= ' ' || r == 0x7f || r == '#' {
			return false
		}
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n >= 1
}

// validDNSName accepts a search domain: dot-separated labels of letters,
// digits and hyphens, whose last label is not all digits.
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}
