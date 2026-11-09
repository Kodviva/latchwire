package ui

import (
	"errors"
	"slices"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

type onboardState struct {
	serial  uint32 // chosen card
	slot    uint8  // chosen slot; 0 = the first free one
	working bool
	backup  bool // the next key is the backup of the session's first key
}

// inspectNew reads each new card once. Inspection sends card commands, so it
// does not run on every poll.
func (u *UI) inspectNew() {
	for serial := range u.infos {
		if !u.present(serial) {
			delete(u.infos, serial)
		}
	}
	for _, d := range u.devices {
		if _, ok := u.infos[d.Serial]; ok || !d.Supported {
			continue
		}
		u.inspect(d.Serial)
	}
}

func (u *UI) inspect(serial uint32) {
	u.infos[serial] = desktop.CardInfo{} // not again until it is read
	go func() {
		info, err := u.b.Inspect(serial)
		fyne.Do(func() {
			if err != nil {
				u.setNotice(u.translate(err))
				return
			}
			u.infos[serial] = info
			switch u.screen {
			case screenOnboard:
				u.renderOnboard()
			case screenPubkey:
				u.renderBackup()
			}
		})
	}()
}

func (u *UI) chosenDevice() (desktop.Device, bool) {
	i := slices.IndexFunc(u.devices, func(d desktop.Device) bool { return d.Serial == u.card.serial })
	if i < 0 {
		i = slices.IndexFunc(u.devices, func(d desktop.Device) bool { return d.Supported })
	}
	if i < 0 {
		if len(u.devices) > 0 {
			return u.devices[0], true
		}
		return desktop.Device{}, false
	}
	u.card.serial = u.devices[i].Serial
	return u.devices[i], true
}

func (u *UI) renderOnboard() {
	left := []fyne.CanvasObject{
		eyebrow(u.tr(msg.UIStep, msg.Args{"step": 1})),
		h1(u.tr(msg.UIOnboardTitle, msg.Args{"count": len(u.devices)})),
		body(u.t(msg.UIOnboardBody)),
	}
	left = prependExplain(left, 2, u.explain(msg.UIExplainOnboardLong, msg.UIExplainOnboardShort))
	if len(u.devices) == 0 {
		left = append(left, card(small(u.t(msg.UIOnboardEmpty))))
	}
	dev, ok := u.chosenDevice()
	for _, d := range u.devices {
		left = append(left, u.deviceRow(d, ok && d.Serial == dev.Serial))
	}
	if ok {
		if keys := u.infos[dev.Serial].Keys; len(keys) > 0 {
			left = append(left, section(u.t(msg.UIExistingKeys)))
			for _, k := range keys {
				left = append(left, u.keyRow(k))
			}
		}
	}
	right := []fyne.CanvasObject{u.settingsCard(dev, ok)}
	create := widget.NewButton(u.t(msg.UICreateKey), func() { u.startKeygen() })
	create.Importance = widget.HighImportance
	if !ok || !dev.Supported || u.card.working || len(u.infos[dev.Serial].FreeSlots) == 0 {
		create.Disable()
	}
	note := u.t(msg.UIPINWillBeAsked)
	if u.card.working {
		note = u.t(msg.UIWorking)
	}
	right = append(right, create, u.withTerm(small(note), msg.UIGlossaryPIN))
	u.setMain(page(split(290, 28, container.NewVScroll(container.NewVBox(left...)), container.NewVBox(right...))))
}

func (u *UI) deviceRow(d desktop.Device, selected bool) fyne.CanvasObject {
	tag := pill(u.t(msg.UIIncompatible), false)
	if d.Supported {
		tag = pill(u.t(msg.UICompatible), true)
	}
	text := container.NewVBox(strong(u.tr(msg.UIDeviceName, msg.Args{"serial": d.Serial})),
		small(u.tr(msg.UIDeviceLine, msg.Args{"serial": d.Serial, "firmware": d.Firmware})))
	row := container.NewBorder(nil, nil, nil, container.NewCenter(tag), text)
	serial := d.Serial
	return newTapCard(row, selected, false, func() {
		u.card.serial, u.card.slot = serial, 0
		u.renderOnboard()
	})
}

func (u *UI) keyRow(k desktop.Key) fyne.CanvasObject {
	use := widget.NewButton(u.t(msg.UIUseKey), func() { u.useKey(k, false) })
	text := mono(u.tr(msg.UIExistingKey, msg.Args{"slot": k.Ref.Slot, "key": k.PublicBase64()}))
	return card(container.NewVBox(text, container.NewHBox(layout.NewSpacer(), use)))
}

// settingsCard offers only empty slots: a slot with a key is never offered,
// so nothing here can replace a key (spec §5.4).
func (u *UI) settingsCard(dev desktop.Device, ok bool) fyne.CanvasObject {
	free := u.infos[dev.Serial].FreeSlots
	var names []string
	for i, s := range free {
		id := msg.UISlotOption
		if i == 0 {
			id = msg.UISlotRecommended
		}
		names = append(names, u.tr(id, msg.Args{"slot": s}))
	}
	sel := widget.NewSelect(names, nil)
	sel.PlaceHolder = u.t(msg.UISlotNoneFree)
	if i := slices.Index(free, u.card.slot); i >= 0 {
		sel.SetSelectedIndex(i)
	} else if len(free) > 0 {
		sel.SetSelectedIndex(0)
		u.card.slot = free[0]
	}
	sel.OnChanged = func(string) {
		if i := sel.SelectedIndex(); i >= 0 {
			u.card.slot = free[i]
		}
	}
	if !ok {
		sel.Disable()
	}
	return card(container.NewVBox(section(u.t(msg.UISettings)),
		u.withTerm(label(u.t(msg.UISlotLabel)), msg.UIGlossarySlot), sel, small(u.t(msg.UISlotHint)),
		label(u.t(msg.UITouchLabel)), small(u.t(msg.UITouchNever))))
}

func (u *UI) startKeygen() {
	dev, ok := u.chosenDevice()
	if !ok || u.card.working {
		return
	}
	u.card.working = true
	u.renderOnboard()
	serial, slot := dev.Serial, u.card.slot
	go func() {
		key, err := u.b.Keygen(serial, slot, asker{u})
		fyne.Do(func() {
			u.card.working = false
			u.inspect(serial)
			switch {
			case err == nil:
				u.useKey(key, true)
			case errors.Is(err, desktop.ErrCancelled):
				u.renderOnboard()
			default:
				u.renderOnboard()
				u.setNotice(u.translate(err))
			}
		})
	}()
}

// useKey opens the public key screen for a key. With backup set on the
// session the key joins it as the second card.
func (u *UI) useKey(k desktop.Key, created bool) {
	u.markStep(desktop.StepCardReady)
	u.markStep(desktop.StepKeyCreated)
	if u.card.backup && len(u.session.keys) > 0 && u.session.keys[0].Ref.Serial != k.Ref.Serial {
		u.session.keys = append(u.session.keys[:1], k)
		u.session.shown = 1
		u.session.addrs = append(u.session.addrs[:1], "")
	} else {
		u.session = pubkeyState{keys: []desktop.Key{k}, addrs: []string{""}, created: created}
	}
	u.card.backup = false
	u.show(screenPubkey)
}
