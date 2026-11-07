package ui

import (
	"testing"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

func TestExploreWalksAndReturns(t *testing.T) {
	u, _ := startFirstRun(t, "en")
	tap(t, u, en(msg.UISurveyWhyExplore))
	if u.screen != screenExplore {
		t.Fatalf("screen = %v, want explore", u.screen)
	}
	want := desktop.Survey{Path: desktop.PathExplore, Help: desktop.HelpGuided}
	if got := storedSurvey(t, u); got != want {
		t.Fatalf("stored %+v, want %+v", got, want)
	}
	wantText(t, u, en(msg.UIExploreWhatTitle))
	tap(t, u, en(msg.UIExploreNext))
	wantText(t, u, en(msg.UIExploreWhyTitle))
	wantText(t, u, "stops copying, not using")
	tap(t, u, en(msg.UIExploreBack))
	wantText(t, u, en(msg.UIExploreWhatTitle))
	tap(t, u, en(msg.UIExploreNext))
	tap(t, u, en(msg.UIExploreNext))
	wantText(t, u, en(msg.UIExploreNeedTitle))
	wantText(t, u, "5.7")
	button(t, u, en(msg.UIExploreSite))
	tap(t, u, en(msg.UIExploreSite))
	tap(t, u, en(msg.UIExploreReady))
	if u.screen != screenSurvey {
		t.Fatalf("screen = %v, want survey", u.screen)
	}
	wantText(t, u, en(msg.UISurveyWhyTitle))
	if u.step != askWhy {
		t.Fatalf("step = %d, want first question", u.step)
	}
}

func TestNoCardWaits(t *testing.T) {
	s := ownerSurvey(desktop.HelpGuided)
	s.Card = desktop.CardNone
	u, _ := startGuided(t, s)
	u.show(screenRoadmap)
	wantText(t, u, en(msg.UIRoadmapWaitTitle))
	wantText(t, u, "5.7")
	button(t, u, en(msg.UIRoadmapWaitLink))
	tap(t, u, en(msg.UIRoadmapWaitLink))
	for _, bad := range []string{"Amazon", "Buy", "YubiKey 5C", "YubiKey 5 NFC", "Bio"} {
		noText(t, u, bad)
	}
	tap(t, u, en(msg.UIRoadmapWaitHave))
	if got := storedSurvey(t, u).Card; got != desktop.CardPlugged {
		t.Fatalf("card = %q after the key arrived", got)
	}
	noText(t, u, en(msg.UIRoadmapWaitTitle))
	wantText(t, u, en(msg.UIRoadmapCardReady))
}

func TestUnsureCardExplains(t *testing.T) {
	s := ownerSurvey(desktop.HelpGuided)
	s.Card = desktop.CardUnsure
	u, _ := startGuided(t, s)
	u.show(screenRoadmap)
	wantText(t, u, en(msg.UIRoadmapUnsure))
	wantText(t, u, "5.7")
	noText(t, u, en(msg.UIRoadmapWaitTitle))

	u.markStep(desktop.StepCardReady)
	noText(t, u, en(msg.UIRoadmapUnsure))
}

func TestPluggedCardHasNoExtra(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	u.show(screenRoadmap)
	noText(t, u, en(msg.UIRoadmapWaitTitle))
	noText(t, u, en(msg.UIRoadmapUnsure))
}

func TestExploreTurkishIsPolite(t *testing.T) {
	for _, id := range []msg.ID{msg.UIExploreWhat, msg.UIExploreWhy, msg.UIExploreNeed, msg.UIRoadmapWait, msg.UIRoadmapUnsure, msg.UISurveySkip} {
		if s := msg.Render("tr", id, nil); s == "" || s == msg.Render("en", id, nil) {
			t.Fatalf("%v not translated: %q", id, s)
		}
	}
}
