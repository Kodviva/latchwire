package ui

import (
	"fmt"
	"net/netip"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// guideStep is the Fyne side of one numbered step of a server guide; its
// text comes from desktop.GuideText. values draws the copyable fields that
// follow the text; term adds a glossary button.
type guideStep struct {
	values func(u *UI) []fyne.CanvasObject
	term   msg.ID
}

var guides = map[desktop.ServerKind][]guideStep{
	desktop.ServerOPNsense: {
		{},
		{values: (*UI).peerValues, term: msg.UIGlossaryAllowedIPs},
		{},
		{term: msg.UIGlossaryEndpoint},
	},
	desktop.ServerPfSense: {
		{},
		{values: (*UI).pfSenseValues, term: msg.UIGlossaryAllowedIPs},
		{},
		{term: msg.UIGlossaryEndpoint},
	},
	desktop.ServerMikroTik: {
		{values: (*UI).mikrotikValues},
		{values: (*UI).peerValues, term: msg.UIGlossaryAllowedIPs},
		{term: msg.UIGlossaryEndpoint},
	},
	desktop.ServerLinux: {
		{values: (*UI).linuxValues, term: msg.UIGlossaryPeer},
		{values: func(u *UI) []fyne.CanvasObject {
			return []fyne.CanvasObject{u.copyField(desktop.SyncConf, true)}
		}},
		{term: msg.UIGlossaryEndpoint},
	},
	desktop.ServerOther: {
		{values: (*UI).peerValues, term: msg.UIGlossaryPeer},
		{},
		{term: msg.UIGlossaryEndpoint},
	},
}

// guideFor is the Fyne part of the guide of the server kind the survey
// named. Without an answer it is the general one.
func guideFor(k desktop.ServerKind) []guideStep {
	if g, ok := guides[k]; ok {
		return g
	}
	return guides[desktop.ServerOther]
}

// guideAddrs are the tunnel IPs typed for the keys; an invalid one stays
// the zero address.
func (u *UI) guideAddrs() []netip.Addr {
	out := make([]netip.Addr, len(u.session.keys))
	for i := range out {
		out[i], _ = u.tunnelAddr(i)
	}
	return out
}

// tunnelAddr is the tunnel IP typed for key i, if it is a valid address.
func (u *UI) tunnelAddr(i int) (netip.Addr, bool) {
	if i >= len(u.session.addrs) {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(u.session.addrs[i]))
	return a, err == nil
}

// allowedText is the AllowedIPs entry for key i, or a placeholder.
func (u *UI) allowedText(i int) (string, bool) {
	a, _ := u.tunnelAddr(i)
	return desktop.AllowedText(u.lang, a)
}

// copyField is a public value in mono with a Copy button. ok false shows
// the text without the button: it still holds a placeholder.
func (u *UI) copyField(text string, ok bool) fyne.CanvasObject {
	box := card(mono(text))
	if !ok {
		return box
	}
	return container.NewBorder(nil, nil, nil, container.NewCenter(u.copyButton(func() string { return text })), box)
}

// keyHeads labels the values of each key when there is a backup card.
func (u *UI) keyHead(i int) []fyne.CanvasObject {
	if len(u.session.keys) < 2 {
		return nil
	}
	return []fyne.CanvasObject{strong(u.tr(msg.UIDeviceName, msg.Args{"serial": u.session.keys[i].Ref.Serial}))}
}

// noIP tells the user where to enter a missing tunnel IP.
func (u *UI) noIP(ok bool) []fyne.CanvasObject {
	if ok {
		return nil
	}
	return []fyne.CanvasObject{small(u.t(msg.UIGuideNoIP))}
}

// peerValues are the public key and the AllowedIPs of every key: the only
// values a server needs for a peer. Nothing secret is among them.
func (u *UI) peerValues() []fyne.CanvasObject {
	var out []fyne.CanvasObject
	for i, k := range u.session.keys {
		allowed, ok := u.allowedText(i)
		out = append(out, u.keyHead(i)...)
		out = append(out,
			label(u.t(msg.UIPublicKey)), u.copyField(k.PublicBase64(), true),
			label(u.t(msg.UIGuideAllowedLabel)), u.copyField(allowed, ok))
		out = append(out, u.noIP(ok)...)
	}
	return out
}

// pfSenseValues are peerValues with the bare tunnel IP: the pfSense peer
// form takes the mask in a box of its own.
func (u *UI) pfSenseValues() []fyne.CanvasObject {
	var out []fyne.CanvasObject
	for i, k := range u.session.keys {
		ip, ok := msg.Translate(u.lang, msg.KeygenTunnelIP), false
		if a, valid := u.tunnelAddr(i); valid {
			ip, ok = a.String(), true
		}
		out = append(out, u.keyHead(i)...)
		out = append(out,
			label(u.t(msg.UIPublicKey)), u.copyField(k.PublicBase64(), true),
			label(u.t(msg.UIGuideAllowedLabel)), u.copyField(ip, ok))
		out = append(out, u.noIP(ok)...)
	}
	return out
}

func (u *UI) mikrotikValues() []fyne.CanvasObject {
	var out []fyne.CanvasObject
	for i, k := range u.session.keys {
		allowed, ok := u.allowedText(i)
		cmd := desktop.MikroTikPeerCommand(k, allowed)
		out = append(out, u.keyHead(i)...)
		out = append(out, label(u.t(msg.UIGuideCommandLabel)), u.copyField(cmd, ok))
		out = append(out, u.noIP(ok)...)
	}
	return out
}

func (u *UI) linuxValues() []fyne.CanvasObject {
	var out []fyne.CanvasObject
	for i, k := range u.session.keys {
		addr, ok := u.tunnelAddr(i)
		if !ok {
			addr = netip.Addr{}
		}
		out = append(out, u.keyHead(i)...)
		out = append(out, label(u.t(msg.UIPeerBlockLabel)), u.copyField(desktop.PeerBlock(u.lang, k, addr), ok))
		out = append(out, u.noIP(ok)...)
	}
	return out
}

// renderGuide draws the steps that add the user's public key to their
// server as a peer. Step by step shows them at once, hints behind a button.
func (u *UI) renderGuide() {
	s := &u.session
	if len(s.keys) == 0 {
		u.show(screenOnboard)
		return
	}
	version, texts := desktop.GuideText(u.lang, u.survey.Server, s.keys, u.guideAddrs())
	g := guideFor(u.survey.Server)
	rows := []fyne.CanvasObject{h1(u.t(msg.UIGuideTitle))}
	if e := u.explain(msg.UIExplainGuideLong, msg.UIExplainGuideShort); e != nil {
		rows = append(rows, e)
	}
	rows = append(rows, body(u.t(msg.UIGuideIntro)))
	if version != "" {
		rows = append(rows, small(version))
	}
	if u.survey.Help == desktop.HelpHints && !u.guideOpen {
		show := widget.NewButton(u.t(msg.UIGuideShow), func() {
			u.guideOpen = true
			u.renderGuide()
		})
		rows = append(rows, container.NewHBox(show))
	} else {
		for n, st := range g {
			var text fyne.CanvasObject = body(fmt.Sprintf("%d. %s", n+1, texts[n].Text))
			if st.term != "" {
				text = u.withTerm(text, st.term)
			}
			rows = append(rows, text)
			if st.values != nil {
				rows = append(rows, st.values(u)...)
			}
		}
		if len(s.keys) > 1 {
			rows = append(rows, warnBox(warnText(u.t(msg.UIGuideBackupNote))))
		}
	}

	other := widget.NewButton(u.t(msg.UIGuideSomeoneElse), func() {
		u.show(u.stepScreen(desktop.StepPubkeyShared))
	})
	done := widget.NewButton(u.t(msg.UIGuideDone), func() {
		u.markStep(desktop.StepServerAdded)
		u.show(screenRoadmap)
	})
	done.Importance = widget.HighImportance
	foot := container.NewHBox(other, layout.NewSpacer(), done)
	u.setMain(page(container.NewBorder(nil, foot, nil, nil, container.NewVScroll(container.NewVBox(rows...)))))
}
