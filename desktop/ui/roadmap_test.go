package ui

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"github.com/Kodviva/latchwire/desktop/demo"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// startGuided starts the app with a stored survey and no tunnels.
func startGuided(t *testing.T, s desktop.Survey) (*UI, *demo.Backend) {
	t.Helper()
	t.Setenv("LATCHWIRE_LANG", "en")
	a := test.NewApp()
	t.Cleanup(func() { a.Quit() })
	a.Preferences().SetString(prefSurvey, s.Encode())
	b := demo.NewEmpty()
	u := New(a, Options{Backend: b})
	u.win.Resize(fyne.NewSize(1000, 680))
	sync(u)
	return u, b
}

func ownerSurvey(h desktop.HelpLevel) desktop.Survey {
	return desktop.Survey{Path: desktop.PathOwner, Card: desktop.CardPlugged, Help: h, Server: desktop.ServerOPNsense}
}

func storedProgress(u *UI) desktop.Progress {
	return desktop.DecodeProgress(u.app.Preferences().String(prefProgress))
}

func TestRoadmapShowsStepsForOwner(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	u.show(screenRoadmap)
	for _, id := range []msg.ID{msg.UIRoadmapCardReady, msg.UIRoadmapKeyCreated, msg.UIRoadmapBackupOffered,
		msg.UIRoadmapServerAdded, msg.UIRoadmapServerInfo, msg.UIRoadmapConnected} {
		wantText(t, u, en(id))
	}
	noText(t, u, en(msg.UIRoadmapPubkeyShared))
	wantText(t, u, en(msg.UIRoadmapNow))
	button(t, u, en(msg.UIRoadmapContinue))
	tap(t, u, en(msg.UIRoadmapContinue))
	if u.screen != screenOnboard {
		t.Fatalf("screen = %v, want onboard", u.screen)
	}
}

func TestRoadmapAdvancesOnKeygen(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	for _, id := range []desktop.StepID{desktop.StepCardReady, desktop.StepKeyCreated, desktop.StepBackupOffered} {
		if !u.progress[id] || !storedProgress(u)[id] {
			t.Fatalf("step %s not recorded: %v / %v", id, u.progress, storedProgress(u))
		}
	}
	if u.progress[desktop.StepConnected] {
		t.Fatal("connected marked too early")
	}
}

func TestMarkStepIsIdempotent(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	u.markStep(desktop.StepKeyCreated)
	u.markStep(desktop.StepKeyCreated)
	if got := u.app.Preferences().String(prefProgress); got != "key_created=1" {
		t.Fatalf("stored %q", got)
	}
}

func TestHelpLevelSwitchKeepsStep(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	keys := len(u.session.keys)
	u.setHelp(desktop.HelpHints)
	if u.screen != screenPubkey || len(u.session.keys) != keys || keys == 0 {
		t.Fatalf("screen %v, keys %d (was %d)", u.screen, len(u.session.keys), keys)
	}
	if s := storedSurvey(t, u); s.Help != desktop.HelpHints || s.Server != desktop.ServerOPNsense {
		t.Fatalf("stored %+v", s)
	}
	wantText(t, u, en(msg.UIRoadmapTitle))
}

func TestHelpLevelSelectorInSidebar(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	wantText(t, u, en(msg.UIHelpLevel))
	wantText(t, u, en(msg.UIHelpGuided))
}

func TestExpertHasNoRoadmapEntry(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpExpert))
	noText(t, u, en(msg.UIRoadmapTitle))
	wantText(t, u, en(msg.UIHelpExpert))
	u.setHelp(desktop.HelpGuided)
	wantText(t, u, en(msg.UIRoadmapTitle))
	u.setHelp(desktop.HelpExpert)
	noText(t, u, en(msg.UIRoadmapTitle))
}

func TestRoadmapGoneWhenConnected(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	wantText(t, u, en(msg.UIRoadmapTitle))
	u.markStep(desktop.StepConnected)
	noText(t, u, en(msg.UIRoadmapTitle))
	wantText(t, u, en(msg.UIHelpLevel))
}

func TestStepScreens(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	for id, want := range map[desktop.StepID]screen{
		desktop.StepCardReady:     screenOnboard,
		desktop.StepKeyCreated:    screenOnboard,
		desktop.StepBackupOffered: screenOnboard, // no session yet: pubkey falls back
		desktop.StepPubkeyShared:  screenOnboard,
		desktop.StepServerAdded:   screenOnboard,
		desktop.StepServerInfo:    screenOnboard, // keys are gone after a restart
		desktop.StepConnected:     screenTunnels,
	} {
		u.show(screenRoadmap)
		u.openStep(id)
		if u.screen != want {
			t.Errorf("%s: screen %v, want %v", id, u.screen, want)
		}
	}
}

// shakeless hides the handshake from Status until shake is set, like a
// tunnel that is up but has not heard from its server yet.
type shakeless struct {
	*demo.Backend
	shake atomic.Bool
}

func (s *shakeless) Status(ctx context.Context) ([]ipc.TunnelStatus, error) {
	sts, err := s.Backend.Status(ctx)
	if !s.shake.Load() {
		for i := range sts {
			sts[i].LastHandshake = ""
		}
	}
	return sts, err
}

func TestConnectedNeedsHandshake(t *testing.T) {
	t.Setenv("LATCHWIRE_LANG", "en")
	a := test.NewApp()
	t.Cleanup(func() { a.Quit() })
	a.Preferences().SetString(prefSurvey, ownerSurvey(desktop.HelpGuided).Encode())
	b := &shakeless{Backend: demo.NewEmpty()}
	if err := b.Add(context.Background(), "office", "x"); err != nil {
		t.Fatal(err)
	}
	u := New(a, Options{Backend: b})
	u.win.Resize(fyne.NewSize(1000, 680))
	sync(u)
	u.selected = "office"
	u.show(screenTunnels)
	tap(t, u, "Connect")
	eventually(t, "connected", func() bool { return strings.Contains(screenText(u), "Disconnect") })
	sync(u)
	if u.progress[desktop.StepConnected] || storedProgress(u)[desktop.StepConnected] {
		t.Fatal("connected marked before the first handshake")
	}
	b.shake.Store(true)
	sync(u)
	if !u.progress[desktop.StepConnected] || !storedProgress(u)[desktop.StepConnected] {
		t.Fatalf("handshake not recorded: %v", u.progress)
	}
}

func TestExpertSwitchLeavesGuideAndShare(t *testing.T) {
	for _, sc := range []screen{screenGuide, screenShare} {
		u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
		openFixedPubkey(u, "10.8.0.2")
		u.show(sc)
		u.setHelp(desktop.HelpExpert)
		if u.screen != screenPubkey {
			t.Fatalf("from %v: screen %v, want pubkey", sc, u.screen)
		}
		noText(t, u, en(msg.UIGuideTitle))
		noText(t, u, en(msg.UIShareTitle))
	}
}
