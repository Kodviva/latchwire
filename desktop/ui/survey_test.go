package ui

import (
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/Kodviva/latchwire/desktop/demo"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

func en(id msg.ID) string { return msg.Render("en", id, nil) }

func storedSurvey(t *testing.T, u *UI) desktop.Survey {
	t.Helper()
	s, ok := desktop.DecodeSurvey(u.app.Preferences().String(prefSurvey))
	if !ok {
		t.Fatalf("no valid survey stored: %q", u.app.Preferences().String(prefSurvey))
	}
	return s
}

func TestSurveyOnFirstRun(t *testing.T) {
	u, _ := startFirstRun(t, "en")
	if u.screen != screenSurvey {
		t.Fatalf("screen = %v, want survey", u.screen)
	}
	wantText(t, u, en(msg.UISurveyWhyTitle))
	wantText(t, u, en(msg.UISurveySkip))
	if got := u.app.Preferences().String(prefSurvey); got != "" {
		t.Fatalf("survey stored before it was answered: %q", got)
	}
}

func TestSurveyNotShownWithTunnels(t *testing.T) {
	u, _ := startWith(t, "en", demo.New(), false)
	if u.screen != screenTunnels {
		t.Fatalf("screen = %v, want tunnels", u.screen)
	}
	if s := storedSurvey(t, u); s.Help != desktop.HelpExpert {
		t.Fatalf("stored %+v, want expert", s)
	}
}

func TestSurveyWaitsForFirstPoll(t *testing.T) {
	t.Setenv("LATCHWIRE_LANG", "en")
	a := test.NewApp()
	t.Cleanup(func() { a.Quit() })
	u := New(a, Options{Backend: demo.New()})
	noText(t, u, en(msg.UISurveyWhyTitle))
	if u.needsSurvey() {
		t.Fatal("survey wanted before tunnels are known")
	}
}

func TestSurveySkipIsExpert(t *testing.T) {
	u, _ := startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveySkip))
	if u.screen != screenTunnels {
		t.Fatalf("screen = %v, want tunnels", u.screen)
	}
	if s := storedSurvey(t, u); s.Help != desktop.HelpExpert || s.Path != desktop.PathOwner {
		t.Fatalf("stored %+v", s)
	}
}

func TestSurveySkipOnLaterQuestion(t *testing.T) {
	u, _ := startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveyWhyInvited))
	wantText(t, u, en(msg.UISurveyCardTitle))
	tap(t, u, en(msg.UISurveySkip))
	if u.screen != screenTunnels || storedSurvey(t, u).Help != desktop.HelpExpert {
		t.Fatalf("screen %v, stored %q", u.screen, u.app.Preferences().String(prefSurvey))
	}
}

func TestSurveyOwnerAsksServerKind(t *testing.T) {
	u, _ := startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveyWhyOwner))
	tap(t, u, en(msg.UISurveyCardPlugged))
	tap(t, u, en(msg.UISurveyHelpGuided))
	wantText(t, u, en(msg.UISurveyServerTitle))
	tap(t, u, en(msg.UISurveyServerOPNsense))
	if u.screen != screenRoadmap {
		t.Fatalf("screen = %v, want roadmap", u.screen)
	}
	want := desktop.Survey{Path: desktop.PathOwner, Card: desktop.CardPlugged, Help: desktop.HelpGuided, Server: desktop.ServerOPNsense}
	if got := storedSurvey(t, u); got != want {
		t.Fatalf("stored %+v, want %+v", got, want)
	}
	if u.survey != want {
		t.Fatalf("u.survey = %+v", u.survey)
	}
}

func TestSurveyInvitedSkipsServerKind(t *testing.T) {
	u, _ := startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveyWhyInvited))
	tap(t, u, en(msg.UISurveyCardNone))
	tap(t, u, en(msg.UISurveyHelpHints))
	if u.screen != screenRoadmap {
		t.Fatalf("screen = %v, want roadmap", u.screen)
	}
	want := desktop.Survey{Path: desktop.PathInvited, Card: desktop.CardNone, Help: desktop.HelpHints}
	if got := storedSurvey(t, u); got != want {
		t.Fatalf("stored %+v, want %+v", got, want)
	}
}

func TestSurveyExploreAndExpertRouting(t *testing.T) {
	u, _ := startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveyWhyExplore))
	if u.screen != screenExplore {
		t.Fatalf("screen = %v, want explore", u.screen)
	}

	u, _ = startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveyWhyInvited))
	tap(t, u, en(msg.UISurveyCardPlugged))
	tap(t, u, en(msg.UISurveyHelpExpert))
	if u.screen != screenTunnels {
		t.Fatalf("expert screen = %v, want tunnels", u.screen)
	}
}

func TestSurveyNotShownTwice(t *testing.T) {
	u, b := startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveySkip))
	u2 := New(u.app, Options{Backend: b})
	sync(u2)
	if u2.screen == screenSurvey || u2.needsSurvey() {
		t.Fatalf("survey shown again, screen %v", u2.screen)
	}
}

func TestSurveyTurkish(t *testing.T) {
	u, _ := startFirstRun(t, "tr")
	wantText(t, u, msg.Render("tr", msg.UISurveyWhyTitle, nil))
}
