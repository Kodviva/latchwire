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

func TestShareQRTwoKeysAndShortAddrs(t *testing.T) {
	u, _ := startGuided(t, invitedSurvey())
	k2 := fixedKey()
	k2.Public[0] = 99
	u.session.keys = []desktop.Key{fixedKey(), k2}
	u.session.addrs = []string{"10.8.0.2"} // shorter than keys
	u.show(screenShare)
	if strings.Contains(u.peerBlocks(), "piv://") || strings.Count(u.peerBlocks(), "[Peer]") != 2 {
		t.Fatal(u.peerBlocks())
	}
	u.notice = ""
	tap(t, u, en(msg.UIShowQR))
	if u.notice != "" && u.notice != en(msg.UIShareQRTooLong) {
		t.Fatalf("raw or wrong notice: %q", u.notice)
	}
	u.showQRText(strings.Repeat("x", 5000))
	if u.notice != en(msg.UIShareQRTooLong) {
		t.Fatalf("notice %q", u.notice)
	}
}
