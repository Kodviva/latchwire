package ui

import (
	"context"
	"image"
	"image/color"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"rsc.io/qr"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// maxConfBytes matches the parser's limit.
const maxConfBytes = 1 << 20

type pubkeyState struct {
	keys    []desktop.Key // the first card and, later, its backup
	addrs   []string      // tunnel IP typed for each key
	shown   int           // key on screen
	created bool          // the first key was created just now

	backupBox *fyne.Container
	peer      *widget.RichText
}

func (u *UI) currentKey() desktop.Key { return u.session.keys[u.session.shown] }

func (u *UI) peerText() string {
	addr, err := netip.ParseAddr(strings.TrimSpace(u.session.addrs[u.session.shown]))
	if err != nil {
		addr = netip.Addr{}
	}
	return desktop.PeerBlock(u.lang, u.currentKey(), addr)
}

func (u *UI) copyButton(text func() string) fyne.CanvasObject {
	var b *widget.Button
	b = widget.NewButton(u.t(msg.UICopy), func() {
		u.app.Clipboard().SetContent(text())
		b.SetText(u.t(msg.UICopied))
	})
	return b
}

func (u *UI) renderPubkey() {
	s := &u.session
	if len(s.keys) == 0 {
		u.show(screenOnboard)
		return
	}
	k := u.currentKey()
	title := msg.UIPubTitleExisting
	if s.created {
		title = msg.UIPubTitleNew
	}
	left := []fyne.CanvasObject{
		eyebrow(u.tr(msg.UIStep, msg.Args{"step": 2})),
		h1(u.t(title)),
		body(u.tr(msg.UIPubBody, msg.Args{"serial": k.Ref.Serial})),
	}
	left = prependExplain(left, 2, u.explain(msg.UIExplainPubkeyLong, msg.UIExplainPubkeyShort))
	if len(s.keys) > 1 {
		var names []string
		for _, key := range s.keys {
			names = append(names, u.tr(msg.UIDeviceName, msg.Args{"serial": key.Ref.Serial}))
		}
		sel := widget.NewSelect(names, nil)
		sel.SetSelectedIndex(s.shown)
		sel.OnChanged = func(string) {
			if sel.SelectedIndex() != s.shown {
				s.shown = sel.SelectedIndex()
				u.renderPubkey()
			}
		}
		left = append(left, sel)
	}

	pub := card(mono(k.PublicBase64()))
	left = append(left, label(u.t(msg.UIPublicKey)),
		container.NewBorder(nil, nil, nil, container.NewCenter(u.copyButton(k.PublicBase64)), pub))

	ip := widget.NewEntry()
	ip.SetPlaceHolder(u.t(msg.UITunnelIPHint))
	ip.SetText(s.addrs[s.shown])
	s.peer = mono(u.peerText()).(*widget.RichText)
	ip.OnChanged = func(v string) {
		s.addrs[s.shown] = v
		s.peer.Segments[0].(*widget.TextSegment).Text = u.peerText()
		s.peer.Refresh()
	}
	peerHead := container.NewBorder(nil, nil, nil,
		container.NewHBox(u.copyButton(u.peerText), widget.NewButton(u.t(msg.UIShowQR), u.showQR)),
		u.withTerm(label(u.t(msg.UIPeerBlockLabel)), msg.UIGlossaryPeer))
	left = append(left, u.withTerm(label(u.t(msg.UITunnelIPLabel)), msg.UIGlossaryAllowedIPs), ip, peerHead, card(s.peer))

	s.backupBox = container.NewStack()
	u.fillBackup()
	form := widget.NewButton(u.t(msg.UIEnterServerInfo), u.showServerForm)
	imp := widget.NewButton(u.t(msg.UIImportConf), u.pickConf)
	imp.Importance = widget.HighImportance
	finish := widget.NewButton(u.t(msg.UIFinish), func() { u.show(screenTunnels) })
	buttons := container.NewVBox(form, imp, finish)
	if u.helping() && u.survey.Path == desktop.PathOwner {
		buttons.Objects = append([]fyne.CanvasObject{widget.NewButton(u.t(msg.UIGuideOpen), func() { u.show(screenGuide) })}, buttons.Objects...)
	}
	right := container.NewBorder(s.backupBox, buttons, nil, nil)
	u.setMain(page(split(270, 24, container.NewVScroll(container.NewVBox(left...)), right)))
}

func (u *UI) renderBackup() {
	if u.session.backupBox != nil {
		u.fillBackup()
	}
}

// otherDevice is a usable card that is not the session's first.
func (u *UI) otherDevice() (desktop.Device, bool) {
	for _, d := range u.devices {
		if d.Supported && d.Serial != u.session.keys[0].Ref.Serial {
			return d, true
		}
	}
	return desktop.Device{}, false
}

// fillBackup draws the backup offer (spec goal 4).
func (u *UI) fillBackup() {
	s := &u.session
	u.markStep(desktop.StepBackupOffered)
	rows := []fyne.CanvasObject{rich(u.t(msg.UIBackupTitle), nameAmber, "", fyne.TextStyle{Bold: true})}
	if len(s.keys) > 1 {
		rows = append(rows, warnText(u.tr(msg.UIBackupReady, msg.Args{"serial": s.keys[1].Ref.Serial})))
	} else {
		rows = append(rows, warnText(u.t(msg.UIBackupBody)))
		if d, ok := u.otherDevice(); ok {
			b := widget.NewButton(u.tr(msg.UIBackupCreate, msg.Args{"serial": d.Serial}), func() {
				u.card.serial, u.card.slot, u.card.backup = d.Serial, 0, true
				u.show(screenOnboard)
			})
			b.Importance = widget.HighImportance
			rows = append(rows, b)
		} else {
			rows = append(rows, rich(u.t(msg.UIBackupPlugIn), nameWarnText, sizeSmall, fyne.TextStyle{}))
		}
	}
	s.backupBox.Objects = []fyne.CanvasObject{warnBox(container.NewVBox(rows...))}
	s.backupBox.Refresh()
}

func (u *UI) showQR() {
	code, err := qr.Encode(u.peerText(), qr.M)
	if err != nil {
		u.setNotice(u.translate(err))
		return
	}
	img := canvas.NewImageFromImage(qrImage(code))
	img.ScaleMode = canvas.ImageScalePixels
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(300, 300))
	var pop *widget.PopUp
	closeBtn := widget.NewButton(u.t(msg.UIClose), func() { pop.Hide() })
	pop = modal(u.win, 400, container.NewVBox(
		h2(u.t(msg.UIQRTitle)), small(u.t(msg.UIQRBody)), container.NewCenter(img),
		container.NewHBox(layout.NewSpacer(), closeBtn)))
	pop.Show()
}

// qrImage draws the code on white with the quiet zone scanners need.
func qrImage(c *qr.Code) image.Image {
	const scale, quiet = 8, 4
	side := (c.Size + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for y := range side {
		for x := range side {
			mx, my := x/scale-quiet, y/scale-quiet
			if mx >= 0 && my >= 0 && mx < c.Size && my < c.Size && c.Black(mx, my) {
				img.SetGray(x, y, color.Gray{})
			} else {
				img.SetGray(x, y, color.Gray{Y: 0xFF})
			}
		}
	}
	return img
}

// tunnelNameFrom suggests a tunnel name from a file name.
func tunnelNameFrom(file string) string {
	s := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	var b strings.Builder
	for _, r := range s {
		if b.Len() == 15 {
			break
		}
		if r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_=+.-", r)) {
			b.WriteRune(r)
		}
	}
	return strings.TrimLeft(b.String(), ".")
}

// importConf shows the form that turns a file into a tunnel. The caller
// wipes data: only the sanitized text outlives this call.
func (u *UI) importConf(file string, data []byte) {
	text, hadKey := desktop.Sanitize(data)
	s := &u.session
	name := widget.NewEntry()
	name.SetText(tunnelNameFrom(file))
	rows := []fyne.CanvasObject{h2(u.t(msg.UIImportTitle))}
	if hadKey {
		rows = append(rows, warnBox(warnText(u.t(msg.UIImportPrivateKey))))
	}
	if u.helping() {
		rows = append(rows, small(u.t(msg.UIImportDeleteHint)))
	}
	rows = append(rows, label(u.t(msg.UITunnelName)), name)
	var backupIP *widget.Entry
	if len(s.keys) > 1 {
		backupIP = widget.NewEntry()
		backupIP.SetPlaceHolder(u.t(msg.UITunnelIPHint))
		backupIP.SetText(s.addrs[1])
		rows = append(rows, label(u.t(msg.UIBackupAddressLabel)), backupIP)
	}
	errText := rich("", nameAmber, sizeSmall, fyne.TextStyle{})
	showErr := func(m string) {
		errText.Segments[0].(*widget.TextSegment).Text = m
		errText.Refresh()
	}
	var pop *widget.PopUp
	add := widget.NewButton(u.t(msg.UIImportAdd), nil)
	add.Importance = widget.HighImportance
	add.OnTapped = func() {
		u.addTunnel(text, strings.TrimSpace(name.Text), backupIP, add, func() { pop.Hide() }, showErr, showErr)
	}
	cancel := widget.NewButton(u.t(msg.UICancel), func() { pop.Hide() })
	rows = append(rows, errText, container.NewHBox(layout.NewSpacer(), cancel, add))
	pop = modal(u.win, 480, container.NewVBox(rows...))
	pop.Show()
}

// addTunnel is the step both ways of adding a tunnel end in: it reads the
// backup card's tunnel IP from backupIP (nil when there is no backup card),
// binds text to the session's keys, adds the tunnel and, on success, closes
// the form and shows the tunnel list. The caller shows errors its own way:
// ipErr for a bad backup IP, showErr for everything else. add is disabled
// while the daemon works.
func (u *UI) addTunnel(text, tunnel string, backupIP *widget.Entry, add *widget.Button, closeForm func(), ipErr, showErr func(string)) {
	s := &u.session
	var backup *desktop.Backup
	if backupIP != nil {
		ip, err := netip.ParseAddr(strings.TrimSpace(backupIP.Text))
		if err != nil {
			ipErr(u.t(msg.UITunnelIPInvalid))
			return
		}
		backup = &desktop.Backup{Key: s.keys[1], Address: ip}
	}
	cfg, err := desktop.Bind(text, s.keys[0], backup)
	if err != nil {
		showErr(u.translate(err))
		return
	}
	add.Disable()
	go func() {
		err := u.b.Add(context.Background(), tunnel, cfg)
		fyne.Do(func() {
			add.Enable()
			if err != nil {
				showErr(u.translate(err))
				return
			}
			closeForm()
			u.markStep(desktop.StepServerInfo)
			u.notice = u.tr(msg.UIImportAdded, msg.Args{"name": tunnel})
			u.selected = tunnel
			u.show(screenTunnels)
		})
		u.pollOnce(context.Background())
	}()
}
