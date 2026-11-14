package desktop

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

func guideKey() Key {
	k := Key{Ref: keyref.Ref{Serial: 40727512, Slot: 0x82}}
	for i := range k.Public {
		k.Public[i] = byte(i + 1)
	}
	return k
}

func TestGuideTextMatchesUI(t *testing.T) {
	k := guideKey()
	pub := k.PublicBase64()
	addrs := []netip.Addr{netip.MustParseAddr("10.8.0.2")}
	mikrotik := `/interface/wireguard/peers/add interface=wireguard1 public-key="` + pub + `" allowed-address=10.8.0.2/32`
	peer := PeerBlock("en", k, addrs[0])
	cases := []struct {
		kind    ServerKind
		version string
		texts   []msg.ID
		values  [][]string
	}{
		{ServerOPNsense, msg.Render("en", msg.UIGuideVersionNote, msg.Args{"product": "OPNsense", "version": "26.x"}),
			[]msg.ID{msg.UIGuideOPNsense1, msg.UIGuideOPNsense2, msg.UIGuideOPNsense3, msg.UIGuideOPNsense4},
			[][]string{nil, {pub, "10.8.0.2/32"}, nil, nil}},
		{ServerPfSense, msg.Render("en", msg.UIGuideVersionNote, msg.Args{"product": "pfSense", "version": "CE 2.8 / Plus 25.x"}),
			[]msg.ID{msg.UIGuidePfSense1, msg.UIGuidePfSense2, msg.UIGuidePfSense3, msg.UIGuidePfSense4},
			[][]string{nil, {pub, "10.8.0.2"}, nil, nil}},
		{ServerMikroTik, msg.Render("en", msg.UIGuideVersionNote, msg.Args{"product": "MikroTik RouterOS", "version": "7"}),
			[]msg.ID{msg.UIGuideMikroTik1, msg.UIGuideMikroTik2, msg.UIGuideMikroTik3},
			[][]string{{mikrotik}, {pub, "10.8.0.2/32"}, nil}},
		{ServerLinux, msg.Render("en", msg.UIGuideVersionNote, msg.Args{"product": "Linux", "version": "wg-quick"}),
			[]msg.ID{msg.UIGuideLinux1, msg.UIGuideLinux2, msg.UIGuideLinux3},
			[][]string{{peer}, {"sudo bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'"}, nil}},
		{ServerOther, "",
			[]msg.ID{msg.UIGuideOther1, msg.UIGuideOther2, msg.UIGuideOther3},
			[][]string{{pub, "10.8.0.2/32"}, nil, nil}},
		{"", "", []msg.ID{msg.UIGuideOther1, msg.UIGuideOther2, msg.UIGuideOther3},
			[][]string{{pub, "10.8.0.2/32"}, nil, nil}},
	}
	for _, c := range cases {
		version, steps := GuideText("en", c.kind, []Key{k}, addrs)
		if version != c.version {
			t.Errorf("%q: version %q, want %q", c.kind, version, c.version)
		}
		if len(steps) != len(c.texts) {
			t.Fatalf("%q: %d steps, want %d", c.kind, len(steps), len(c.texts))
		}
		for i, s := range steps {
			if want := msg.Render("en", c.texts[i], nil); s.Text != want {
				t.Errorf("%q step %d: text %q, want %q", c.kind, i, s.Text, want)
			}
			if !slices.Equal(s.Values, c.values[i]) {
				t.Errorf("%q step %d: values %q, want %q", c.kind, i, s.Values, c.values[i])
			}
		}
	}
}

func TestGuideTextWithoutAddress(t *testing.T) {
	k := guideKey()
	_, steps := GuideText("en", ServerOPNsense, []Key{k}, nil)
	if want := []string{k.PublicBase64()}; !slices.Equal(steps[1].Values, want) {
		t.Fatalf("values %q, want only the public key %q", steps[1].Values, want)
	}
}

func TestGuideTextHasNoPrivateRef(t *testing.T) {
	k := guideKey()
	addrs := []netip.Addr{netip.MustParseAddr("10.8.0.2")}
	for _, kind := range []ServerKind{ServerOPNsense, ServerPfSense, ServerMikroTik, ServerLinux, ServerOther} {
		for _, lang := range []string{"en", "tr"} {
			v, steps := GuideText(lang, kind, []Key{k}, addrs)
			all := v
			for _, s := range steps {
				all += s.Text + strings.Join(s.Values, "\n")
			}
			if strings.Contains(all, "piv://") {
				t.Errorf("%s/%s: guide text holds a private key reference", kind, lang)
			}
		}
	}
}

func TestGuideTextFieldsMarkPlaceholders(t *testing.T) {
	k := guideKey()
	_, steps := GuideText("en", ServerLinux, []Key{k}, nil)
	f := steps[0].Fields
	if len(f) != 1 || !f[0].Placeholder || f[0].Key != 0 || len(steps[0].Values) != 0 {
		t.Fatalf("fields %+v values %q", f, steps[0].Values)
	}
}
