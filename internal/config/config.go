// Package config parses Latchwire tunnel configurations.
//
// The syntax is wg-quick's .conf with one difference: the private key is
// replaced by a reference to a hardware slot (KeyRef). A PrivateKey line is an
// error, never silently ignored, because ignoring it would hide that the user
// still holds a software key.
//
// Hook keys (PreUp, PostUp, ...) are refused: Latchwire does not run commands
// from configuration files.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// maxConfigBytes bounds how much of a configuration is read.
const maxConfigBytes = 1 << 20

var (
	// ErrPrivateKeyNotAllowed is returned when a PrivateKey line appears anywhere.
	ErrPrivateKeyNotAllowed = errors.New(msg.ConfigPrivateKeyNotAllowed)
	// ErrNoIdentity is returned when no KeyRef is configured.
	ErrNoIdentity = errors.New(msg.ConfigNoIdentity)
)

// Identity is one hardware key and the addresses used while it is selected.
type Identity struct {
	Ref keyref.Ref
	// PublicKey is the key the slot must hold. It is configured, never
	// learned from the card, so an agent cannot substitute another key.
	PublicKey [32]byte
	Addresses []netip.Prefix
}

// Peer is a remote WireGuard endpoint.
type Peer struct {
	PublicKey           [32]byte
	PresharedKey        *[32]byte
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// Tunnel is a parsed tunnel configuration. Identities are in order of
// preference.
type Tunnel struct {
	Name       string
	ListenPort int
	MTU        int
	DNS        []netip.Addr // parsed, not applied yet
	DNSSearch  []string     // search domains from the DNS line, not applied yet
	Identities []Identity
	Peers      []Peer
}

type section int

const (
	secNone section = iota
	secInterface
	secIdentity
	secPeer
)

func (s section) String() string {
	switch s {
	case secInterface:
		return "Interface"
	case secIdentity:
		return "Identity"
	case secPeer:
		return "Peer"
	}
	return ""
}

// hookKeys are wg-quick [Interface] keys that Latchwire refuses. Lowercase
// map key, canonical spelling as value.
var hookKeys = map[string]string{
	"preup":      "PreUp",
	"postup":     "PostUp",
	"predown":    "PreDown",
	"postdown":   "PostDown",
	"table":      "Table",
	"saveconfig": "SaveConfig",
	"fwmark":     "FwMark",
}

type parser struct {
	t *Tunnel

	sec     section
	seenIf  bool
	ifRef   *keyref.Ref
	ifPub   *[32]byte
	ifAddrs []netip.Prefix

	cur      *Identity // identity being filled, nil unless sec == secIdentity
	curPeer  *Peer
	peerKeys map[string]bool
	seen     map[string]bool // once-only keys already set in the current section
}

// Parse reads a tunnel configuration. name is stored as Tunnel.Name.
func Parse(name string, r io.Reader) (*Tunnel, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf(msg.ConfigTooLargeFmt, maxConfigBytes)
	}

	p := &parser{t: &Tunnel{Name: name}, peerKeys: map[string]bool{}}
	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	for i, line := range strings.Split(text, "\n") {
		if err := p.line(line); err != nil {
			return nil, fmt.Errorf(msg.ConfigLineFmt, i+1, err)
		}
	}
	if err := p.endSection(); err != nil {
		return nil, err
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return p.t, nil
}

func (p *parser) line(raw string) error {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	if raw[0] == '[' {
		if raw[len(raw)-1] != ']' {
			return errors.New(msg.ConfigMalformedLine)
		}
		return p.beginSection(strings.ToLower(strings.TrimSpace(raw[1 : len(raw)-1])))
	}

	k, v, ok := strings.Cut(raw, "=")
	if !ok {
		return errors.New(msg.ConfigMalformedLine)
	}
	key := strings.ToLower(strings.TrimSpace(k))
	val := strings.TrimSpace(v)

	// Checked before anything else and without touching the value, which may
	// be a private key.
	if key == "privatekey" {
		return ErrPrivateKeyNotAllowed
	}
	if canon, ok := hookKeys[key]; ok {
		return fmt.Errorf(msg.ConfigHookNotSupportedFmt, canon)
	}
	return p.keyValue(key, val)
}

func (p *parser) beginSection(name string) error {
	if err := p.endSection(); err != nil {
		return err
	}
	p.seen = map[string]bool{}
	switch name {
	case "interface":
		if p.seenIf {
			return fmt.Errorf(msg.ConfigDuplicateSectionFmt, secInterface)
		}
		p.seenIf = true
		p.sec = secInterface
	case "identity":
		p.sec = secIdentity
		p.cur = &Identity{}
	case "peer":
		p.sec = secPeer
		p.curPeer = &Peer{}
	default:
		return fmt.Errorf(msg.ConfigUnknownSectionFmt, name)
	}
	return nil
}

// endSection validates and stores the section being closed.
func (p *parser) endSection() error {
	switch p.sec {
	case secIdentity:
		if !p.seen["keyref"] {
			return fmt.Errorf(msg.ConfigMissingKeyFmt, secIdentity, "KeyRef")
		}
		if !p.seen["publickey"] {
			return fmt.Errorf(msg.ConfigMissingKeyFmt, secIdentity, "PublicKey")
		}
		p.t.Identities = append(p.t.Identities, *p.cur)
		p.cur = nil
	case secPeer:
		if !p.seen["publickey"] {
			return fmt.Errorf(msg.ConfigMissingKeyFmt, secPeer, "PublicKey")
		}
		id := string(p.curPeer.PublicKey[:])
		if p.peerKeys[id] {
			return errors.New(msg.ConfigDuplicatePeer)
		}
		p.peerKeys[id] = true
		p.t.Peers = append(p.t.Peers, *p.curPeer)
		p.curPeer = nil
	}
	p.sec = secNone
	return nil
}

// finish decides the identity list once every section has been read.
func (p *parser) finish() error {
	shorthand := p.ifRef != nil
	if !shorthand && p.ifPub != nil {
		return errors.New(msg.ConfigPublicKeyWithoutKeyRef)
	}
	if shorthand {
		if len(p.t.Identities) > 0 {
			return errors.New(msg.ConfigMixedIdentities)
		}
		if p.ifPub == nil {
			return fmt.Errorf(msg.ConfigMissingKeyFmt, secInterface, "PublicKey")
		}
		p.t.Identities = []Identity{{Ref: *p.ifRef, PublicKey: *p.ifPub, Addresses: p.ifAddrs}}
	} else if len(p.ifAddrs) > 0 && len(p.t.Identities) > 0 {
		return errors.New(msg.ConfigMixedIdentities)
	}
	if len(p.t.Identities) == 0 {
		return ErrNoIdentity
	}
	return nil
}

// once reports a duplicate for keys that may appear only once per section.
func (p *parser) once(key, canon string) error {
	if p.seen[key] {
		return fmt.Errorf(msg.ConfigDuplicateKeyFmt, canon)
	}
	p.seen[key] = true
	return nil
}

func (p *parser) keyValue(key, val string) error {
	switch p.sec {
	case secNone:
		return errors.New(msg.ConfigKeyOutsideSection)
	case secInterface:
		return p.interfaceKey(key, val)
	case secIdentity:
		return p.identityKey(key, val)
	default:
		return p.peerKey(key, val)
	}
}

func (p *parser) interfaceKey(key, val string) error {
	switch key {
	case "keyref":
		if err := p.once(key, "KeyRef"); err != nil {
			return err
		}
		ref, err := keyref.Parse(val)
		if err != nil {
			return err
		}
		p.ifRef = &ref
	case "publickey":
		if err := p.once(key, "PublicKey"); err != nil {
			return err
		}
		k, err := parseIdentityKey(val)
		if err != nil {
			return err
		}
		p.ifPub = &k
	case "address":
		addrs, err := parsePrefixes(val, "Address")
		if err != nil {
			return err
		}
		p.ifAddrs = append(p.ifAddrs, addrs...)
	case "listenport":
		if err := p.once(key, "ListenPort"); err != nil {
			return err
		}
		n, err := parsePort(val, 0, "ListenPort")
		if err != nil {
			return err
		}
		p.t.ListenPort = n
	case "mtu":
		if err := p.once(key, "MTU"); err != nil {
			return err
		}
		n, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return fmt.Errorf(msg.ConfigInvalidValueFmt, "MTU")
		}
		p.t.MTU = int(n)
	case "dns":
		for _, item := range splitList(val) {
			if a, err := netip.ParseAddr(item); err == nil {
				p.t.DNS = append(p.t.DNS, a)
			} else if validHostname(item) {
				p.t.DNSSearch = append(p.t.DNSSearch, item)
			} else {
				return fmt.Errorf(msg.ConfigInvalidValueFmt, "DNS")
			}
		}
	default:
		return unknownKey(key, p.sec)
	}
	return nil
}

func (p *parser) identityKey(key, val string) error {
	switch key {
	case "keyref":
		if err := p.once(key, "KeyRef"); err != nil {
			return err
		}
		ref, err := keyref.Parse(val)
		if err != nil {
			return err
		}
		p.cur.Ref = ref
	case "publickey":
		if err := p.once(key, "PublicKey"); err != nil {
			return err
		}
		k, err := parseIdentityKey(val)
		if err != nil {
			return err
		}
		p.cur.PublicKey = k
	case "address":
		addrs, err := parsePrefixes(val, "Address")
		if err != nil {
			return err
		}
		p.cur.Addresses = append(p.cur.Addresses, addrs...)
	default:
		return unknownKey(key, p.sec)
	}
	return nil
}

func (p *parser) peerKey(key, val string) error {
	peer := p.curPeer
	switch key {
	case "publickey":
		if err := p.once(key, "PublicKey"); err != nil {
			return err
		}
		k, err := parseKey(val, "PublicKey")
		if err != nil {
			return err
		}
		peer.PublicKey = k
	case "presharedkey":
		if err := p.once(key, "PresharedKey"); err != nil {
			return err
		}
		k, err := parseKey(val, "PresharedKey")
		if err != nil {
			return err
		}
		peer.PresharedKey = &k
	case "endpoint":
		if err := p.once(key, "Endpoint"); err != nil {
			return err
		}
		if err := checkEndpoint(val); err != nil {
			return err
		}
		peer.Endpoint = val
	case "allowedips":
		ips, err := parsePrefixes(val, "AllowedIPs")
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, ips...)
	case "persistentkeepalive":
		if err := p.once(key, "PersistentKeepalive"); err != nil {
			return err
		}
		if strings.EqualFold(val, "off") {
			peer.PersistentKeepalive = 0
			return nil
		}
		n, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return fmt.Errorf(msg.ConfigInvalidValueFmt, "PersistentKeepalive")
		}
		peer.PersistentKeepalive = int(n)
	default:
		return unknownKey(key, p.sec)
	}
	return nil
}

func unknownKey(key string, s section) error {
	return fmt.Errorf(msg.ConfigUnknownKeyFmt, key, s)
}

// splitList splits a comma-separated list and drops empty items.
func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// parsePrefixes accepts CIDR prefixes and bare addresses (host prefixes).
func parsePrefixes(v, canon string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(v) {
		var pfx netip.Prefix
		if strings.Contains(item, "/") {
			var err error
			if pfx, err = netip.ParsePrefix(item); err != nil {
				return nil, fmt.Errorf(msg.ConfigInvalidValueFmt, canon)
			}
		} else {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf(msg.ConfigInvalidValueFmt, canon)
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, pfx)
	}
	return out, nil
}

func parsePort(v string, min int, canon string) (int, error) {
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil || int(n) < min {
		return 0, fmt.Errorf(msg.ConfigInvalidValueFmt, canon)
	}
	return int(n), nil
}

// parseKey decodes a base64 WireGuard public or preshared key. The value is
// never included in errors.
func parseKey(v, canon string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != len(k) {
		return k, fmt.Errorf(msg.ConfigInvalidValueFmt, canon)
	}
	copy(k[:], b)
	return k, nil
}

// parseIdentityKey decodes an identity's PublicKey; the all-zero key is
// refused.
func parseIdentityKey(v string) ([32]byte, error) {
	k, err := parseKey(v, "PublicKey")
	if err == nil && k == ([32]byte{}) {
		err = fmt.Errorf(msg.ConfigInvalidValueFmt, "PublicKey")
	}
	return k, err
}

// validHostname reports whether s is a plausible DNS name: at most 253 bytes,
// dot-separated labels of 1-63 letters, digits or hyphens, none starting or
// ending with a hyphen. A name whose last label is all digits is refused so
// that malformed IPv4 literals such as 10.0.0.256 are not taken for domains.
func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// checkEndpoint requires host:port with a port in 1-65535. The host may be a
// name; resolving it is the caller's job.
func checkEndpoint(v string) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil || host == "" {
		return fmt.Errorf(msg.ConfigInvalidValueFmt, "Endpoint")
	}
	if _, err := parsePort(port, 1, "Endpoint"); err != nil {
		return err
	}
	return nil
}

// UAPI renders the configuration in wireguard-go's UAPI set format: the
// listen port, then each peer. It never contains a private key; the key is
// supplied separately through the key provider.
//
// Every Peer.Endpoint must already be a literal IP:port. Parse accepts
// hostnames, so the daemon resolves them (and replaces Peer.Endpoint) before
// calling UAPI; wireguard-go does not resolve names itself.
func (t *Tunnel) UAPI() string {
	var b strings.Builder
	if t.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", t.ListenPort)
	}
	for _, p := range t.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
	}
	return b.String()
}
