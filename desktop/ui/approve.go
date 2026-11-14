package ui

import (
	"context"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// approveTimeout is how long an approval window waits (spec §8); no answer
// is a refusal. A variable so tests can shorten it.
var approveTimeout = 2 * time.Minute

// approveTools names the tools that ask for approval.
var approveTools = map[string]msg.ID{
	ipc.ToolCreateKey:  msg.UIApproveToolCreateKey,
	ipc.ToolAddTunnel:  msg.UIApproveToolAddTunnel,
	ipc.ToolConnect:    msg.UIApproveToolConnect,
	ipc.ToolDisconnect: msg.UIApproveToolDisconnect,
}

// Approve shows the approval window for an agent's request and reports
// whether the user allowed it. Only the Allow button allows: the window
// closes as refused when ctx ends (the daemon stopped waiting), after
// approveTimeout, and when access is turned off. While access is off or
// has run out in the app, it refuses at once without a window. It must not
// run on the UI goroutine. The client name and summary come from the
// daemon, which made them printable; they are shown as text, never as
// markup.
func (u *UI) Approve(ctx context.Context, r ipc.ApproveRequest) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, approveTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return false, nil
	}
	answer := make(chan bool, 1)
	reply := func(allow bool) {
		select {
		case answer <- allow:
		default:
		}
	}
	var pop *widget.PopUp
	var key *struct{}
	fyne.DoAndWait(func() {
		if !u.accessOpen() {
			return
		}
		key = new(struct{})
		u.access.approvals[key] = cancel
		tool := r.Tool
		if id, ok := approveTools[tool]; ok {
			tool = u.t(id) + " (" + r.Tool + ")"
		}
		client := r.Client
		if client == "" {
			client = "unknown"
		}
		rows := []fyne.CanvasObject{h2(u.t(msg.UIApproveTitle)),
			strong(u.tr(msg.UIApproveClient, msg.Args{"client": client})),
			body(u.tr(msg.UIApproveTool, msg.Args{"tool": tool}))}
		if r.Summary != "" {
			rows = append(rows, card(body(msg.Translate(u.lang, r.Summary))))
		}
		if r.Fresh {
			rows = append(rows, warnBox(warnText(u.t(msg.UIApproveFresh))))
		}
		rows = append(rows, small(u.t(msg.UIApproveTimeout)))
		deny := widget.NewButton(u.t(msg.UIApproveDeny), func() { reply(false) })
		allow := widget.NewButton(u.t(msg.UIApproveAllow), func() { reply(true) })
		rows = append(rows, container.NewHBox(layout.NewSpacer(), deny, allow))
		u.showWindow()
		pop = modal(u.win, 480, container.NewVBox(rows...))
		pop.Show()
	})
	if pop == nil {
		return false, nil
	}
	allowed := false
	select {
	case allowed = <-answer:
	case <-ctx.Done():
	}
	fyne.DoAndWait(func() {
		pop.Hide()
		delete(u.access.approvals, key)
	})
	return allowed && ctx.Err() == nil, nil
}

// accessOpen reports whether access is on in the app and has not run out.
// Call on the UI goroutine.
func (u *UI) accessOpen() bool {
	a := &u.access
	return a.on && (a.until.IsZero() || time.Now().Before(a.until))
}

// closeApprovals closes every open approval window as refused. Call on the
// UI goroutine.
func (u *UI) closeApprovals() {
	for _, cancel := range u.access.approvals {
		cancel()
	}
}

// Notice marks a guided step the daemon reports done (a desktop.StepID); an
// unknown one is ignored. A key made for the agent also means the card was
// ready.
func (u *UI) Notice(step string) {
	id := desktop.StepID(step)
	if _, ok := stepTexts[id]; !ok {
		return
	}
	fyne.Do(func() {
		if id == desktop.StepKeyCreated {
			u.markStep(desktop.StepCardReady)
		}
		u.markStep(id)
	})
}

// CardList lists the plugged-in cards for the daemon's card.list: what
// the onboarding screen shows, read afresh.
func (u *UI) CardList() ([]ipc.CardEntry, error) {
	devs, err := u.b.Devices()
	if err != nil {
		return nil, err
	}
	out := make([]ipc.CardEntry, 0, len(devs))
	for _, d := range devs {
		e := ipc.CardEntry{Serial: d.Serial, Firmware: d.Firmware, Supported: d.Supported}
		if d.Supported {
			info, err := u.b.Inspect(d.Serial)
			if err != nil {
				return nil, err
			}
			e.Fresh, e.FreeSlots = info.Fresh, ipc.Slots(info.FreeSlots)
			for _, k := range info.Keys {
				e.Keys = append(e.Keys, k.Ref.String())
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// KeygenFor makes a key for the daemon's card.keygen with the same forms
// as the app's own key creation. When ctx ends the forms close and the
// result is desktop.ErrCancelled. It must not run on the UI goroutine.
func (u *UI) KeygenFor(ctx context.Context, serial uint32, slot uint8) (desktop.Key, error) {
	if ctx.Err() != nil {
		return desktop.Key{}, desktop.ErrCancelled
	}
	k, err := u.b.Keygen(serial, slot, asker{u: u, ctx: ctx})
	fyne.Do(func() { u.inspect(serial) })
	if err != nil && ctx.Err() != nil {
		return desktop.Key{}, desktop.ErrCancelled
	}
	return k, err
}
