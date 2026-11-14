package ui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// steps returns the user's roadmap: empty in expert mode and for explorers.
func (u *UI) steps() []desktop.StepID { return desktop.Roadmap(u.survey) }

// roadmapOpen reports whether the sidebar offers the roadmap: there are
// steps and the last one is not reached yet.
func (u *UI) roadmapOpen() bool {
	return len(u.steps()) > 0 && !u.progress[desktop.StepConnected]
}

// markStep records a finished step. It does nothing for a step that is
// already done.
func (u *UI) markStep(id desktop.StepID) {
	if u.progress[id] {
		return
	}
	if u.progress == nil {
		u.progress = desktop.Progress{}
	}
	u.progress[id] = true
	u.app.Preferences().SetString(prefProgress, u.progress.Encode())
	u.renderSidebar()
	if u.screen == screenRoadmap {
		u.renderRoadmap()
	}
}

// markHandshake finishes the roadmap once a tunnel has had a handshake: a
// connect that returned proves nothing until the server has answered.
func (u *UI) markHandshake() {
	if len(u.steps()) == 0 {
		return
	}
	for _, st := range u.statuses {
		if st.LastHandshake != "" {
			u.markStep(desktop.StepConnected)
			return
		}
	}
}

// setHelp changes the help level and redraws the open screen in place.
func (u *UI) setHelp(h desktop.HelpLevel) {
	if h == u.survey.Help || u.survey.Help == "" {
		return
	}
	s := u.survey
	s.Help = h
	u.saveSurvey(s)
	if u.screen == screenRoadmap && len(u.steps()) == 0 {
		u.show(screenTunnels)
		return
	}
	if h == desktop.HelpExpert && (u.screen == screenGuide || u.screen == screenShare) {
		u.show(screenPubkey) // expert mode has no guides
		return
	}
	u.render()
}

// openStep opens the screen a step is done on.
func (u *UI) openStep(id desktop.StepID) {
	switch id {
	case desktop.StepServerInfo:
		u.showServerForm()
	case desktop.StepConnected:
		u.show(screenTunnels)
	default:
		u.show(u.stepScreen(id))
	}
}

// stepScreen is the screen of every step that has one of its own.
func (u *UI) stepScreen(id desktop.StepID) screen {
	switch id {
	case desktop.StepBackupOffered:
		return screenPubkey
	case desktop.StepPubkeyShared:
		return screenShare
	case desktop.StepServerAdded:
		return screenGuide
	case desktop.StepConnected:
		return screenTunnels
	}
	return screenOnboard
}

type stepText struct{ title, done msg.ID }

var stepTexts = map[desktop.StepID]stepText{
	desktop.StepCardReady:     {msg.UIRoadmapCardReady, msg.UIRoadmapDoneCardReady},
	desktop.StepKeyCreated:    {msg.UIRoadmapKeyCreated, msg.UIRoadmapDoneKeyCreated},
	desktop.StepBackupOffered: {msg.UIRoadmapBackupOffered, msg.UIRoadmapDoneBackupOffered},
	desktop.StepPubkeyShared:  {msg.UIRoadmapPubkeyShared, msg.UIRoadmapDonePubkeyShared},
	desktop.StepServerAdded:   {msg.UIRoadmapServerAdded, msg.UIRoadmapDoneServerAdded},
	desktop.StepServerInfo:    {msg.UIRoadmapServerInfo, msg.UIRoadmapDoneServerInfo},
	desktop.StepConnected:     {msg.UIRoadmapConnected, msg.UIRoadmapDoneConnected},
}

func (u *UI) renderRoadmap() {
	steps := u.steps()
	if len(steps) == 0 {
		u.show(screenTunnels)
		return
	}
	cur, _ := u.progress.Current(steps)
	rows := []fyne.CanvasObject{h1(u.t(msg.UIRoadmapTitle))}
	if u.survey.Card == desktop.CardNone {
		rows = append(rows, u.waitCard())
	}
	for i, id := range steps {
		rows = append(rows, u.stepRow(i+1, id, id == cur))
	}
	// The one line guided and hints users get about agent access; expert
	// mode has no roadmap.
	rows = append(rows, newTapCard(label(u.t(msg.UIRoadmapAgentLink)), false, true, func() { u.show(screenAccess) }))
	u.setMain(page(container.NewVScroll(container.NewVBox(rows...))))
}

func (u *UI) stepRow(n int, id desktop.StepID, current bool) fyne.CanvasObject {
	txt := stepTexts[id]
	done := u.progress[id]
	text := []fyne.CanvasObject{strong(fmt.Sprintf("%d. %s", n, u.t(txt.title)))}
	if done {
		text = append(text, small(u.t(txt.done)))
	} else if id == desktop.StepCardReady && u.survey.Card == desktop.CardUnsure {
		text = append(text, small(u.t(msg.UIRoadmapUnsure)))
	}
	var side fyne.CanvasObject = container.NewCenter(dot(done))
	if current {
		btn := widget.NewButton(u.t(msg.UIRoadmapContinue), func() { u.openStep(id) })
		btn.Importance = widget.HighImportance
		side = container.NewHBox(pill(u.t(msg.UIRoadmapNow), true), btn)
	}
	row := container.NewBorder(nil, nil, nil, side, container.NewVBox(text...))
	if current {
		return warnBox(row)
	}
	return card(row)
}

var helpLevels = []struct {
	level desktop.HelpLevel
	label msg.ID
}{
	{desktop.HelpGuided, msg.UIHelpGuided},
	{desktop.HelpHints, msg.UIHelpHints},
	{desktop.HelpExpert, msg.UIHelpExpert},
}

// helpSelect is the help level switch of the sidebar.
func (u *UI) helpSelect() fyne.CanvasObject {
	var names []string
	cur := -1
	for i, h := range helpLevels {
		names = append(names, u.t(h.label))
		if h.level == u.survey.Help {
			cur = i
		}
	}
	sel := widget.NewSelect(names, nil)
	if cur >= 0 {
		sel.SetSelectedIndex(cur)
	}
	sel.OnChanged = func(string) {
		if i := sel.SelectedIndex(); i >= 0 {
			u.setHelp(helpLevels[i].level)
		}
	}
	return container.NewVBox(small(u.t(msg.UIHelpLevel)), sel)
}
