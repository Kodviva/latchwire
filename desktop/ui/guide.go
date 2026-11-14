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

// guideTerms is the glossary term of each step of a guide, by server kind;
// an empty one has none. The steps themselves come from desktop.GuideText.
var guideTerms = map[desktop.ServerKind][]msg.ID{
	desktop.ServerOPNsense: {"", msg.UIGlossaryAllowedIPs, "", msg.UIGlossaryEndpoint},
	desktop.ServerPfSense:  {"", msg.UIGlossaryAllowedIPs, "", msg.UIGlossaryEndpoint},
	desktop.ServerMikroTik: {"", msg.UIGlossaryAllowedIPs, msg.UIGlossaryEndpoint},
	desktop.ServerLinux:    {msg.UIGlossaryPeer, "", msg.UIGlossaryEndpoint},
	desktop.ServerOther:    {msg.UIGlossaryPeer, "", msg.UIGlossaryEndpoint},
}

// termOf is the glossary term of step n of the guide for kind k.
func termOf(k desktop.ServerKind, n int) msg.ID {
	t, ok := guideTerms[k]
	if !ok {
		t = guideTerms[desktop.ServerOther]
	}
	if n < len(t) {
		return t[n]
	}
	return ""
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

// guideFields draws the fields of a guide step: for each key its device
// name when there are several, then each value under its label, and a hint
// where a tunnel IP is still missing. Placeholders get no Copy button.
func (u *UI) guideFields(fields []desktop.GuideField) []fyne.CanvasObject {
	var out []fyne.CanvasObject
	for i := 0; i < len(fields); {
		key, missing := fields[i].Key, false
		if key >= 0 {
			out = append(out, u.keyHead(key)...)
		}
		for ; i < len(fields) && fields[i].Key == key; i++ {
			f := fields[i]
			if f.Label != "" {
				out = append(out, label(u.t(f.Label)))
			}
			out = append(out, u.copyField(f.Text, !f.Placeholder))
			missing = missing || f.Placeholder
		}
		out = append(out, u.noIP(!missing)...)
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
		for n, st := range texts {
			var text fyne.CanvasObject = body(fmt.Sprintf("%d. %s", n+1, st.Text))
			if term := termOf(u.survey.Server, n); term != "" {
				text = u.withTerm(text, term)
			}
			rows = append(rows, text)
			rows = append(rows, u.guideFields(st.Fields)...)
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
