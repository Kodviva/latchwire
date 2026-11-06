package ui

import (
	"errors"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
)

// pinTimeout is how long a PIN window waits; the same bound and reason as
// the system dialogs' (internal/agent: below the daemon's two-minute wait, a
// PIN typed after the daemon gave up would reach the card for nothing).
var pinTimeout = 100 * time.Second

var errTimeout = errors.New("timeout")

// secretForm is a modal form of secret fields.
type secretForm struct {
	title   string
	text    string
	warning string
	fields  []string
	// check validates the values (the slices stay valid only during the
	// call) and returns what to show instead of closing.
	check   func(vals [][]byte) string
	timeout time.Duration
}

// askSecrets shows the form and blocks until it is answered, so it must not
// run on the UI goroutine. The caller wipes the returned slices.
func (u *UI) askSecrets(form secretForm) ([][]byte, error) {
	type answer struct {
		vals [][]byte
		err  error
	}
	done := make(chan answer, 1)
	var pop *widget.PopUp
	var fields []*SecretField
	finished := false
	wipe := func() {
		for _, f := range fields {
			f.Wipe()
		}
	}
	finish := func(a answer) {
		if finished {
			return
		}
		finished = true
		wipe()
		pop.Hide()
		u.cancelForm = nil
		done <- a
	}
	fyne.DoAndWait(func() {
		errText := rich("", nameAmber, sizeSmall, fyne.TextStyle{})
		submit := func() {
			vals := make([][]byte, len(fields))
			for i, f := range fields {
				vals[i] = f.Take()
			}
			if form.check != nil {
				if e := form.check(vals); e != "" {
					for _, v := range vals {
						clear(v)
					}
					errText.Segments[0].(*widget.TextSegment).Text = e
					errText.Refresh()
					return
				}
			}
			finish(answer{vals: vals})
		}
		rows := []fyne.CanvasObject{h2(form.title)}
		if form.text != "" {
			rows = append(rows, body(form.text))
		}
		if form.warning != "" {
			rows = append(rows, warnBox(warnText(form.warning)))
		}
		for i, name := range form.fields {
			f := NewSecretField()
			if i == len(form.fields)-1 {
				f.OnSubmit = submit
			}
			fields = append(fields, f)
			rows = append(rows, label(name), f)
		}
		rows = append(rows, errText)
		ok := widget.NewButton(u.t(msg.UIOK), submit)
		ok.Importance = widget.HighImportance
		cancel := widget.NewButton(u.t(msg.UICancel), func() { finish(answer{err: desktop.ErrCancelled}) })
		rows = append(rows, container.NewHBox(layout.NewSpacer(), cancel, ok))
		u.cancelForm = func() { finish(answer{err: desktop.ErrCancelled}) }
		u.showWindow()
		pop = modal(u.win, 460, container.NewVBox(rows...))
		pop.Show()
		u.win.Canvas().Focus(fields[0])
	})
	var expire <-chan time.Time
	if form.timeout > 0 {
		t := time.NewTimer(form.timeout)
		defer t.Stop()
		expire = t.C
	}
	select {
	case a := <-done:
		return a.vals, a.err
	case <-expire:
		fyne.DoAndWait(func() { finish(answer{err: errTimeout}) })
		a := <-done
		return a.vals, a.err
	}
}

// prompter is the agent's Prompter: the PIN goes from the form straight to
// the return value and nothing here keeps it. internal/agent's PIN rules
// are unchanged and decide when this is called.
type prompter struct{ u *UI }

// Prompter returns the agent.Prompter of this app.
func (u *UI) Prompter() *prompter { return &prompter{u} }

func (p *prompter) PIN(d keyprovider.Description, retriesLeft int) (string, error) {
	u := p.u
	form := secretForm{
		title:   u.tr(msg.UIPINForSlot, msg.Args{"serial": d.Serial, "slot": d.Slot}),
		text:    u.t(msg.UIPINReason),
		fields:  []string{u.tr(msg.UIPINRetries, msg.Args{"retries": retriesLeft})},
		timeout: pinTimeout,
	}
	if retriesLeft == 1 {
		form.warning = msg.Translate(u.lang, msg.LastPINRetry)
	}
	vals, err := u.askSecrets(form)
	if err != nil {
		return "", keyprovider.ErrPINRequired
	}
	defer clear(vals[0])
	return string(vals[0]), nil
}

// Warn shows the agent's warnings. The last-retry warning is already in the
// PIN form that follows it.
func (p *prompter) Warn(m string) {
	if m == msg.LastPINRetry {
		return
	}
	fyne.Do(func() { p.u.setNotice(msg.Translate(p.u.lang, m)) })
}

// asker is desktop.Asker on top of secret forms.
type asker struct{ u *UI }

func (a asker) PIN(serial uint32, retries int) ([]byte, error) {
	u := a.u
	form := secretForm{
		title:  u.tr(msg.UIPINForKey, msg.Args{"serial": serial}),
		fields: []string{u.tr(msg.UIPINRetries, msg.Args{"retries": retries})},
	}
	if retries == 1 {
		form.warning = msg.Translate(u.lang, msg.LastPINRetry)
	}
	vals, err := u.askSecrets(form)
	if err != nil {
		return nil, err
	}
	return vals[0], nil
}

func (a asker) Fresh(uint32) (desktop.FreshSecrets, error) {
	u := a.u
	vals, err := u.askSecrets(secretForm{
		title: u.t(msg.UIFreshTitle),
		text:  reflow(msg.Translate(u.lang, msg.FreshCardExplain)),
		fields: []string{u.t(msg.UICurrentPUK), u.t(msg.UINewPIN), u.t(msg.UINewPINAgain),
			u.t(msg.UINewPUK), u.t(msg.UINewPUKAgain)},
		check: func(v [][]byte) string { return checkFresh(u.lang, v) },
	})
	if err != nil {
		return desktop.FreshSecrets{}, err
	}
	clear(vals[2])
	clear(vals[4])
	return desktop.FreshSecrets{CurrentPUK: vals[0], NewPIN: vals[1], NewPUK: vals[3]}, nil
}

// checkFresh compares the repeated entries in place: no string is made.
func checkFresh(lang string, v [][]byte) string {
	for _, i := range []int{1, 3} {
		if string(v[i]) != string(v[i+1]) { // the comparison allocates nothing
			return msg.Translate(lang, msg.KeygenSecretMismatch)
		}
		if len(v[i]) < 6 || len(v[i]) > 8 {
			return msg.Translate(lang, msg.KeygenSecretRules)
		}
	}
	return ""
}

func (a asker) ManagementKey(uint32) ([]byte, error) {
	u := a.u
	vals, err := u.askSecrets(secretForm{
		title:  u.t(msg.UIManagementTitle),
		text:   u.t(msg.UIManagementBody),
		fields: []string{u.t(msg.UIManagementTitle)},
	})
	if err != nil {
		return nil, err
	}
	return vals[0], nil
}
