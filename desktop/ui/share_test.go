package ui

import (
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

func invitedSurvey() desktop.Survey {
	return desktop.Survey{Path: desktop.PathInvited, Card: desktop.CardPlugged, Help: desktop.HelpGuided}
}

func TestShareMarksStep(t *testing.T) {
	u, _ := startGuided(t, invitedSurvey())
	u.session.keys = []desktop.Key{fixedKey()}
	u.session.addrs = []string{"10.8.0.2"}
	if u.stepScreen(desktop.StepPubkeyShared) != screenShare {
		t.Fatal("step does not open the share screen")
	}
	u.show(screenShare)
	wantText(t, u, "AllowedIPs = 10.8.0.2/32")
	wantText(t, u, en(msg.UIShareTitle))
	if u.progress[desktop.StepPubkeyShared] {
		t.Fatal("marked before the user said so")
	}
	tap(t, u, en(msg.UIShareSent))
	if !u.progress[desktop.StepPubkeyShared] || !storedProgress(u)[desktop.StepPubkeyShared] {
		t.Fatalf("not recorded: %v", u.progress)
	}
}

func TestShareCopiesPublicValuesOnly(t *testing.T) {
	u, _ := startGuided(t, invitedSurvey())
	k := fixedKey()
	u.session.keys = []desktop.Key{k}
	u.session.addrs = []string{""}
	u.show(screenShare)
	tap(t, u, en(msg.UICopy))
	got := u.app.Clipboard().Content()
	if !strings.Contains(got, k.PublicBase64()) || strings.Contains(got, "piv://") {
		t.Fatal(got)
	}
}
