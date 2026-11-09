package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// helping reports whether the user asked for explanations: step by step or
// short hints. Expert mode, and no answer at all, get none.
func (u *UI) helping() bool {
	return u.survey.Help == desktop.HelpGuided || u.survey.Help == desktop.HelpHints
}

// explain is the "what happens here" text of a screen: long in a box for
// step by step, short on one line for hints, nil in expert mode. Callers
// add nothing for nil, so expert screens stay as they were.
func (u *UI) explain(long, short msg.ID) fyne.CanvasObject {
	switch u.survey.Help {
	case desktop.HelpGuided:
		return card(body(u.t(long)))
	case desktop.HelpHints:
		return small(u.t(short))
	}
	return nil
}

// glossaryTerms maps a term's text to its title.
var glossaryTerms = map[msg.ID]msg.ID{
	msg.UIGlossaryPeer:       msg.UIGlossaryPeerTitle,
	msg.UIGlossaryEndpoint:   msg.UIGlossaryEndpointTitle,
	msg.UIGlossaryAllowedIPs: msg.UIGlossaryAllowedIPsTitle,
	msg.UIGlossaryPIN:        msg.UIGlossaryPINTitle,
	msg.UIGlossarySlot:       msg.UIGlossarySlotTitle,
}

// glossary is a small "?" button that explains term, or nil in expert mode.
func (u *UI) glossary(term msg.ID) fyne.CanvasObject {
	if !u.helping() {
		return nil
	}
	b := widget.NewButton("?", func() { u.showTerm(term) })
	b.Importance = widget.LowImportance
	return b
}

func (u *UI) showTerm(term msg.ID) {
	var pop *widget.PopUp
	closeBtn := widget.NewButton(u.t(msg.UIClose), func() { pop.Hide() })
	pop = modal(u.win, 420, container.NewVBox(
		h2(u.t(glossaryTerms[term])), body(u.t(term)),
		container.NewHBox(layout.NewSpacer(), closeBtn)))
	pop.Show()
}

// withTerm puts the glossary button of term after o. Without one, o comes
// back as it is.
func (u *UI) withTerm(o fyne.CanvasObject, term msg.ID) fyne.CanvasObject {
	g := u.glossary(term)
	if g == nil {
		return o
	}
	return container.NewBorder(nil, nil, nil, g, o)
}

// prependExplain adds the explanation, when there is one, after the first
// head objects of rows.
func prependExplain(rows []fyne.CanvasObject, head int, e fyne.CanvasObject) []fyne.CanvasObject {
	if e == nil {
		return rows
	}
	out := append([]fyne.CanvasObject{}, rows[:head]...)
	out = append(out, e)
	return append(out, rows[head:]...)
}
