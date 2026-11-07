package ui

import (
	"net/netip"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// adminMessage is the message for the administrator, in the app's language,
// from the session's keys and the tunnel IPs typed so far.
func (u *UI) adminMessage() (subject, body string) {
	s := &u.session
	addrs := make([]netip.Addr, len(s.keys))
	for i := range s.keys {
		if a, ok := u.tunnelAddr(i); ok {
			addrs[i] = a
		}
	}
	return desktop.AdminMessage(u.lang, s.keys, addrs)
}

// peerBlocks is the [Peer] block of every key: what the administrator
// needs, and short enough for a QR code.
func (u *UI) peerBlocks() string {
	var blocks []string
	for i, k := range u.session.keys {
		a, _ := u.tunnelAddr(i)
		blocks = append(blocks, desktop.PeerBlock(u.lang, k, a))
	}
	return strings.Join(blocks, "\n\n")
}

// renderShare is the step where the user sends the public key to whoever
// runs the server.
func (u *UI) renderShare() {
	if len(u.session.keys) == 0 {
		u.show(screenOnboard)
		return
	}
	subject, text := u.adminMessage()
	rows := []fyne.CanvasObject{h1(u.t(msg.UIShareTitle))}
	if e := u.explain(msg.UIExplainShareLong, msg.UIExplainShareShort); e != nil {
		rows = append(rows, e)
	}
	rows = append(rows, body(u.t(msg.UIShareBody)), card(mono(strings.TrimSpace(text))))

	mail := widget.NewButton(u.t(msg.UIShareMail), func() {
		if err := u.app.OpenURL(desktop.MailtoURL(subject, text)); err != nil {
			u.setNotice(u.t(msg.UIShareMailFailed))
		}
	})
	qrBtn := widget.NewButton(u.t(msg.UIShowQR), func() { u.showQRText(u.peerBlocks()) })
	sent := widget.NewButton(u.t(msg.UIShareSent), func() {
		u.markStep(desktop.StepPubkeyShared)
		u.show(screenRoadmap)
	})
	sent.Importance = widget.HighImportance
	foot := container.NewHBox(u.copyButton(func() string { return text }), mail, qrBtn, layout.NewSpacer(), sent)
	u.setMain(page(container.NewBorder(nil, foot, nil, nil, container.NewVScroll(container.NewVBox(rows...)))))
}
