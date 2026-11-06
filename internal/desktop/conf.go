package desktop

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/msg"
)

// PeerBlock is the [Peer] section the server needs for this client, in the
// same form latchwire keygen prints. An invalid addr leaves the placeholder.
func PeerBlock(lang string, k Key, addr netip.Addr) string {
	ip, bits := msg.Translate(lang, msg.KeygenTunnelIP), 32
	if addr.IsValid() {
		ip, bits = addr.String(), addr.BitLen()
	}
	return fmt.Sprintf(msg.KeygenPeerBlockFmt, k.PublicBase64(), ip, bits)
}

// Backup is a second card for a tunnel: its key and the tunnel address the
// server gave that peer (spec §5.7: WireGuard cannot give one AllowedIPs to
// two peers).
type Backup struct {
	Key     Key
	Address netip.Addr
}

// Sanitize drops every PrivateKey line of a server's .conf, and comments
// that mention one, since a commented-out key is still a key. had says that
// there was one: the user must be told, because that key is not the one on
// the card. Lines are handled as bytes, so no string ever holds such a line;
// the caller wipes data afterwards.
func Sanitize(data []byte) (clean string, had bool) {
	var b strings.Builder
	for _, raw := range bytes.Split(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), []byte("\n")) {
		if mentionsPrivateKey(bytes.TrimSpace(raw)) {
			had = true
			continue
		}
		b.Write(bytes.TrimRight(raw, "\r"))
		b.WriteByte('\n')
	}
	return b.String(), had
}

// Bind turns a sanitized .conf into a Latchwire configuration for key:
// KeyRef and PublicKey are written into [Interface]. With a backup each card
// gets an [Identity] section. The result is checked with the same parser the
// daemon uses, so hooks and other refused keys fail here with the daemon's
// message.
func Bind(text string, key Key, backup *Backup) (string, error) {
	var ifBody, rest, addresses []string
	sec := ""
	seenInterface := false
	for _, s := range strings.Split(text, "\n") {
		line := []byte(strings.TrimSpace(s))
		if bytes.HasPrefix(line, []byte("[")) {
			sec = strings.ToLower(string(line))
			if sec == "[interface]" && !seenInterface {
				seenInterface = true
				continue
			}
			rest = append(rest, s) // the parser reports a second [Interface]
			continue
		}
		switch {
		case sec != "[interface]":
			rest = append(rest, s)
		case backup != nil && isKey(line, "address"):
			addresses = append(addresses, s)
		default:
			ifBody = append(ifBody, s)
		}
	}
	if !seenInterface {
		return "", fmt.Errorf(msg.ConfigMissingKeyFmt, "Interface", "Address")
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	if backup == nil {
		fmt.Fprintf(&b, "KeyRef = %s\nPublicKey = %s\n", key.Ref, key.PublicBase64())
	}
	for _, l := range trimBlank(ifBody) {
		b.WriteString(l + "\n")
	}
	if backup != nil {
		fmt.Fprintf(&b, "\n[Identity]\nKeyRef = %s\nPublicKey = %s\n", key.Ref, key.PublicBase64())
		for _, l := range addresses {
			b.WriteString(l + "\n")
		}
		fmt.Fprintf(&b, "\n[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = %s/%d\n",
			backup.Key.Ref, backup.Key.PublicBase64(), backup.Address, backup.Address.BitLen())
	}
	if r := trimBlank(rest); len(r) > 0 {
		b.WriteString("\n" + strings.Join(r, "\n") + "\n")
	}
	if _, err := config.Parse("check", strings.NewReader(b.String())); err != nil {
		return "", err
	}
	return b.String(), nil
}

func trimBlank(l []string) []string {
	for len(l) > 0 && strings.TrimSpace(l[0]) == "" {
		l = l[1:]
	}
	for len(l) > 0 && strings.TrimSpace(l[len(l)-1]) == "" {
		l = l[:len(l)-1]
	}
	return l
}

// isKey reports whether a trimmed line sets key (lower case).
func isKey(line []byte, key string) bool {
	k, _, ok := bytes.Cut(line, []byte("="))
	return ok && strings.EqualFold(string(bytes.TrimSpace(k)), key)
}

// mentionsPrivateKey matches a PrivateKey setting and any comment naming one,
// since a commented-out key is still a key.
func mentionsPrivateKey(line []byte) bool {
	if isKey(line, "privatekey") {
		return true
	}
	if len(line) > 0 && (line[0] == '#' || line[0] == ';') {
		return bytes.Contains(bytes.ToLower(line), []byte("privatekey"))
	}
	return bytes.Contains(bytes.ToLower(line), []byte("privatekey")) && bytes.Contains(line, []byte("#"))
}
