package ui

import (
	"context"
	"reflect"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

func (u *UI) selectedStatus() (ipc.TunnelStatus, bool) {
	for _, st := range u.statuses {
		if st.Name == u.selected {
			return st, true
		}
	}
	if len(u.statuses) > 0 {
		u.selected = u.statuses[0].Name
		return u.statuses[0], true
	}
	return ipc.TunnelStatus{}, false
}

// renderTunnels draws the tunnel screen. onlyIfChanged skips the redraw when
// nothing the user can see differs.
func (u *UI) renderTunnels(onlyIfChanged bool) {
	if u.survey.Help == "" && !u.known && u.daemonErr == "" {
		// The first reading decides between this screen and the survey.
		u.shownView = nil
		u.setMain(container.NewStack())
		return
	}
	st, ok := u.selectedStatus()
	if !ok {
		u.shownView = nil
		cta := widget.NewButton(u.t(msg.UICreateKey), func() { u.show(screenOnboard) })
		cta.Importance = widget.HighImportance
		u.setMain(page(container.NewVBox(h1(u.t(msg.UINavTunnels)), body(u.t(msg.UITunnelsEmpty)),
			container.NewHBox(cta))))
		return
	}
	v := desktop.NewTunnelView(u.lang, st, u.present, time.Now())
	if onlyIfChanged && u.shownView != nil && reflect.DeepEqual(*u.shownView, v) {
		return
	}
	u.shownView = &v

	head := container.NewBorder(nil, nil, nil, container.NewVBox(pill(v.Label, v.Lit)), h1(v.Name))
	keyBox := card(container.NewVBox(label(u.t(msg.UIKeyLabel)), strong(v.Key), keyNote(v)))
	shake := card(container.NewVBox(label(u.t(msg.UILastHandshake)), strong(v.Handshake), small(u.t(msg.UIHandshakeNote))))
	rows := []fyne.CanvasObject{head, container.NewGridWithColumns(2, keyBox, shake)}
	for _, s := range []string{v.Banner, v.Blocking, v.Warning} {
		if s != "" {
			rows = append(rows, warnBox(warnText(s)))
		}
	}
	act := widget.NewButton(v.Action, func() { u.toggle(v.Name, v.Connects) })
	act.Importance = widget.HighImportance
	if u.pending[v.Name] {
		act.Disable()
	}
	foot := []fyne.CanvasObject{act}
	for _, d := range u.opts.Actions {
		foot = append(foot, widget.NewButton(d.Label, d.Run))
	}
	u.setMain(page(container.NewBorder(container.NewVBox(rows...), container.NewHBox(foot...), nil, nil)))
}

func keyNote(v desktop.TunnelView) fyne.CanvasObject {
	if v.KeyWarn {
		return rich(v.KeyNote, nameAmber, sizeSmall, fyne.TextStyle{})
	}
	return small(v.KeyNote)
}

// page pads a screen.
func page(o fyne.CanvasObject) fyne.CanvasObject {
	return container.New(layout.NewCustomPaddedLayout(28, 24, 32, 32), o)
}

// toggle connects or disconnects a tunnel. A connect returns when the tunnel
// is up, which includes the PIN window.
func (u *UI) toggle(name string, connect bool) {
	if u.pending[name] {
		return
	}
	u.pending[name] = true
	u.shownView = nil
	u.renderTunnels(false)
	u.updateTray()
	go func() {
		ctx := context.Background()
		var err error
		if connect {
			_, err = u.b.Connect(ctx, name)
		} else {
			err = u.b.Disconnect(ctx, name)
		}
		fyne.Do(func() {
			delete(u.pending, name)
			if err != nil {
				u.setNotice(u.translate(err))
			}
			u.shownView = nil
		})
		u.pollOnce(ctx)
		fyne.Do(func() {
			if u.screen == screenTunnels {
				u.renderTunnels(false)
			}
		})
	}()
}
