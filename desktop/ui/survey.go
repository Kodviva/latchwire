package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// The questions of the survey, in the order they are asked. The server kind
// is asked only of owners.
const (
	askWhy = iota
	askCard
	askHelp
	askServer
)

// option is one answer of a question.
type option struct {
	label msg.ID
	pick  func(*desktop.Survey)
}

// needsSurvey reports whether the first-run survey is due: nothing is stored
// (or the user stopped on the explore pages last time), the first reading
// of the daemon is in and shows no tunnel, and the user has not been asked
// yet. Until that reading the answer is no, so the survey does not flash up
// for someone who has tunnels.
func (u *UI) needsSurvey() bool {
	return u.surveyOpen() && u.known && !u.asked && len(u.statuses) == 0
}

// surveyOpen reports whether the survey is still to be answered.
func (u *UI) surveyOpen() bool { return u.survey.Help == "" || u.reask }

// decideFirstRun runs after each reading until the survey question is
// settled. A user with tunnels is an existing user: they get expert mode
// and no questions. An explorer with tunnels keeps their answers.
func (u *UI) decideFirstRun() {
	if !u.surveyOpen() || !u.known || u.asked {
		return
	}
	switch {
	case len(u.statuses) > 0 && u.reask:
		u.reask = false
	case len(u.statuses) > 0:
		u.saveSurvey(expertSurvey())
	case u.screen == screenTunnels:
		u.asked = true
		u.draft, u.step = desktop.Survey{}, askWhy
		u.show(screenSurvey)
	}
}

// expertSurvey is what skipping stores. DecodeSurvey wants a path, and the
// expert roadmap is empty for every path.
func expertSurvey() desktop.Survey {
	return desktop.Survey{Path: desktop.PathOwner, Help: desktop.HelpExpert}
}

func (u *UI) saveSurvey(s desktop.Survey) {
	u.survey, u.reask = s, false
	u.app.Preferences().SetString(prefSurvey, s.Encode())
}

// finishSurvey stores the answers and opens the screen they lead to.
func (u *UI) finishSurvey(s desktop.Survey) {
	u.saveSurvey(s)
	switch {
	case s.Help == desktop.HelpExpert:
		u.show(screenTunnels)
	case s.Path == desktop.PathExplore:
		u.explorePage = 0
		u.show(screenExplore)
	default:
		u.show(screenRoadmap)
	}
}

func (u *UI) loadGuide() {
	if s, ok := desktop.DecodeSurvey(u.app.Preferences().String(prefSurvey)); ok {
		u.survey = s
		u.reask = s.Path == desktop.PathExplore && s.Help != desktop.HelpExpert
	}
	u.progress = desktop.DecodeProgress(u.app.Preferences().String(prefProgress))
}

func (u *UI) questionTitle() (msg.ID, []option) {
	switch u.step {
	case askWhy:
		return msg.UISurveyWhyTitle, []option{
			{msg.UISurveyWhyInvited, func(s *desktop.Survey) { s.Path = desktop.PathInvited }},
			{msg.UISurveyWhyOwner, func(s *desktop.Survey) { s.Path = desktop.PathOwner }},
			{msg.UISurveyWhyExplore, func(s *desktop.Survey) { s.Path = desktop.PathExplore }},
		}
	case askCard:
		return msg.UISurveyCardTitle, []option{
			{msg.UISurveyCardPlugged, func(s *desktop.Survey) { s.Card = desktop.CardPlugged }},
			{msg.UISurveyCardUnsure, func(s *desktop.Survey) { s.Card = desktop.CardUnsure }},
			{msg.UISurveyCardNone, func(s *desktop.Survey) { s.Card = desktop.CardNone }},
		}
	case askHelp:
		return msg.UISurveyHelpTitle, []option{
			{msg.UISurveyHelpGuided, func(s *desktop.Survey) { s.Help = desktop.HelpGuided }},
			{msg.UISurveyHelpHints, func(s *desktop.Survey) { s.Help = desktop.HelpHints }},
			{msg.UISurveyHelpExpert, func(s *desktop.Survey) { s.Help = desktop.HelpExpert }},
		}
	}
	return msg.UISurveyServerTitle, []option{
		{msg.UISurveyServerOPNsense, func(s *desktop.Survey) { s.Server = desktop.ServerOPNsense }},
		{msg.UISurveyServerPfSense, func(s *desktop.Survey) { s.Server = desktop.ServerPfSense }},
		{msg.UISurveyServerMikroTik, func(s *desktop.Survey) { s.Server = desktop.ServerMikroTik }},
		{msg.UISurveyServerLinux, func(s *desktop.Survey) { s.Server = desktop.ServerLinux }},
		{msg.UISurveyServerOther, func(s *desktop.Survey) { s.Server = desktop.ServerOther }},
	}
}

// answer records the choice of the current question and moves on.
func (u *UI) answer(o option) {
	o.pick(&u.draft)
	switch {
	case u.step == askWhy && u.draft.Path == desktop.PathExplore:
		u.finishSurvey(desktop.Survey{Path: desktop.PathExplore, Help: desktop.HelpGuided})
	case u.step == askHelp && u.draft.Path == desktop.PathOwner && u.draft.Help != desktop.HelpExpert:
		u.step = askServer
		u.render()
	case u.step < askHelp:
		u.step++
		u.render()
	default:
		u.finishSurvey(u.draft)
	}
}

func (u *UI) renderSurvey() {
	title, opts := u.questionTitle()
	rows := []fyne.CanvasObject{h1(u.t(title))}
	for _, o := range opts {
		b := widget.NewButton(u.t(o.label), func() { u.answer(o) })
		b.Alignment = widget.ButtonAlignLeading
		rows = append(rows, b)
	}
	skip := widget.NewButton(u.t(msg.UISurveySkip), func() { u.finishSurvey(expertSurvey()) })
	skip.Importance = widget.LowImportance
	rows = append(rows, container.NewHBox(skip))
	u.setMain(page(container.NewVBox(rows...)))
}
