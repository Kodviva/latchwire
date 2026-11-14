//go:build demo

package ui

import (
	"image/png"
	"log"
	"os"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
)

var (
	tourDesc = keyprovider.Description{Serial: 40727512, Slot: 0x82}
	tourKeys = []desktop.Key{{Ref: keyref.Ref{Serial: 40727512, Slot: 0x82}, Public: [32]byte{0x12, 0x34, 0x56}}}
)

const tourConf = "[Interface]\nPrivateKey = cFJ1c3RPbmx5QVRlc3RWYWx1ZU5vdEFSZWFsS2V5MDA=\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"

func (u *UI) closeOverlays() {
	for u.win.Canvas().Overlays().Top() != nil {
		u.win.Canvas().Overlays().Top().Hide()
		u.win.Canvas().Overlays().Remove(u.win.Canvas().Overlays().Top())
	}
}

// Tour walks the screens of the demo build and writes what the real driver
// rendered to dir, for checking the look without a person at the machine.
func (u *UI) Tour(dir string, setCard func(bool)) {
	shot := func(name string) {
		time.Sleep(600 * time.Millisecond)
		fyne.DoAndWait(func() {
			img := u.win.Canvas().Capture()
			f, err := os.Create(filepath.Join(dir, name+".png"))
			if err != nil {
				log.Print(err)
				return
			}
			defer f.Close()
			if err := png.Encode(f, img); err != nil {
				log.Print(err)
			}
		})
	}
	do := func(fn func()) { fyne.DoAndWait(fn) }
	for _, lang := range []string{"en", "tr"} {
		do(func() { u.setLanguage(lang); u.selected = "office"; u.show(screenTunnels) })
		shot(lang + "-1-tunnels")
		setCard(false)
		time.Sleep(2500 * time.Millisecond)
		shot(lang + "-2-card-removed")
		setCard(true)
		time.Sleep(2500 * time.Millisecond)
		do(func() { u.show(screenOnboard) })
		shot(lang + "-3-onboard")
		go u.Prompter().PIN(tourDesc, 1)
		shot(lang + "-4-pin")
		do(u.tourCancel)
		go asker{u: u}.Fresh(0)
		shot(lang + "-5-fresh")
		do(u.tourCancel)
		do(func() {
			u.session = pubkeyState{keys: tourKeys, addrs: []string{"10.8.0.2"}, created: true}
			u.show(screenPubkey)
		})
		shot(lang + "-6-pubkey")
		do(u.showQR)
		shot(lang + "-7-qr")
		do(func() { u.closeOverlays() })
		do(func() { u.importConf("office.conf", []byte(tourConf)) })
		shot(lang + "-8-import")
		do(func() { u.closeOverlays() })
	}
	do(u.app.Quit)
}

// tourCancel presses Cancel on the open secret form.
func (u *UI) tourCancel() {
	if u.cancelForm != nil {
		u.cancelForm()
	}
}
