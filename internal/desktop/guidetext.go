package desktop

import (
	"fmt"
	"net/netip"

	"github.com/Kodviva/latchwire/internal/msg"
)

// SyncConf reloads a wg-quick interface without dropping its other peers.
// The whole line runs as root: wg0.conf is readable by root only.
const SyncConf = "sudo bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'"

// GuideStep is one numbered step of a server guide. Values are the public
// values the user copies for it: nothing secret is among them.
type GuideStep struct {
	Text   string
	Values []string
}

type guideKind int

const (
	valuesNone guideKind = iota
	valuesPeer
	valuesPfSense
	valuesMikroTik
	valuesLinux
	valuesSync
)

type guideDef struct {
	product, version string
	steps            []struct {
		text   msg.ID
		values guideKind
	}
}

type defStep = struct {
	text   msg.ID
	values guideKind
}

var guideDefs = map[ServerKind]guideDef{
	ServerOPNsense: {"OPNsense", "26.x", []defStep{
		{msg.UIGuideOPNsense1, valuesNone},
		{msg.UIGuideOPNsense2, valuesPeer},
		{msg.UIGuideOPNsense3, valuesNone},
		{msg.UIGuideOPNsense4, valuesNone},
	}},
	ServerPfSense: {"pfSense", "CE 2.8 / Plus 25.x", []defStep{
		{msg.UIGuidePfSense1, valuesNone},
		{msg.UIGuidePfSense2, valuesPfSense},
		{msg.UIGuidePfSense3, valuesNone},
		{msg.UIGuidePfSense4, valuesNone},
	}},
	ServerMikroTik: {"MikroTik RouterOS", "7", []defStep{
		{msg.UIGuideMikroTik1, valuesMikroTik},
		{msg.UIGuideMikroTik2, valuesPeer},
		{msg.UIGuideMikroTik3, valuesNone},
	}},
	ServerLinux: {"Linux", "wg-quick", []defStep{
		{msg.UIGuideLinux1, valuesLinux},
		{msg.UIGuideLinux2, valuesSync},
		{msg.UIGuideLinux3, valuesNone},
	}},
	ServerOther: {"", "", []defStep{
		{msg.UIGuideOther1, valuesPeer},
		{msg.UIGuideOther2, valuesNone},
		{msg.UIGuideOther3, valuesNone},
	}},
}

// AllowedText is the AllowedIPs entry for a tunnel address, or the
// placeholder with ok false when the address is not valid.
func AllowedText(lang string, addr netip.Addr) (text string, ok bool) {
	if addr.IsValid() {
		return fmt.Sprintf("%s/%d", addr, addr.BitLen()), true
	}
	return msg.Translate(lang, msg.KeygenTunnelIP) + "/32", false
}

// MikroTikPeerCommand is the RouterOS command that adds the peer.
func MikroTikPeerCommand(k Key, allowed string) string {
	return fmt.Sprintf(`/interface/wireguard/peers/add interface=wireguard1 public-key="%s" allowed-address=%s`, k.PublicBase64(), allowed)
}

// GuideText is the written guide for adding the keys to a server of the
// given kind: the version note (empty for a general guide) and the steps
// with the values to copy. addrs[i] is the tunnel IP of keys[i]; a missing
// or invalid one leaves its address values out, since they would only be
// placeholders. An unknown kind gets the general guide.
func GuideText(lang string, kind ServerKind, keys []Key, addrs []netip.Addr) (version string, steps []GuideStep) {
	d, ok := guideDefs[kind]
	if !ok {
		d = guideDefs[ServerOther]
	}
	if d.product != "" {
		version = msg.Render(lang, msg.UIGuideVersionNote, msg.Args{"product": d.product, "version": d.version})
	}
	for _, s := range d.steps {
		st := GuideStep{Text: msg.Render(lang, s.text, nil)}
		for i, k := range keys {
			var addr netip.Addr
			if i < len(addrs) {
				addr = addrs[i]
			}
			allowed, valid := AllowedText(lang, addr)
			switch s.values {
			case valuesPeer:
				st.Values = append(st.Values, k.PublicBase64())
				if valid {
					st.Values = append(st.Values, allowed)
				}
			case valuesPfSense:
				st.Values = append(st.Values, k.PublicBase64())
				if valid {
					st.Values = append(st.Values, addr.String())
				}
			case valuesMikroTik:
				if valid {
					st.Values = append(st.Values, MikroTikPeerCommand(k, allowed))
				}
			case valuesLinux:
				if valid {
					st.Values = append(st.Values, PeerBlock(lang, k, addr))
				}
			}
		}
		if s.values == valuesSync {
			st.Values = []string{SyncConf}
		}
		steps = append(steps, st)
	}
	return version, steps
}
