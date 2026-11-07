package ui

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// fixedKey is a key whose text does not change between runs, unlike the
// demo backend's random ones.
func fixedKey() desktop.Key {
	k := desktop.Key{Ref: keyref.Ref{Serial: 40727512, Slot: 0x82}}
	for i := range k.Public {
		k.Public[i] = byte(i + 1)
	}
	return k
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s changed:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// TestExpertScreensUnchanged holds expert mode to the screens it had before
// the explanations existed.
func TestExpertScreensUnchanged(t *testing.T) {
	u, _ := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	eventually(t, "cards read", func() bool { return len(u.infos[40727512].FreeSlots) > 0 && len(u.infos[40727513].FreeSlots) > 0 })
	u.renderOnboard()
	golden(t, "expert_onboard.txt", screenText(u))

	u.session = pubkeyState{keys: []desktop.Key{fixedKey()}, addrs: []string{"10.8.0.2"}}
	u.show(screenPubkey)
	golden(t, "expert_pubkey.txt", screenText(u))
}

// openFixedPubkey puts a known key on the public key screen.
func openFixedPubkey(u *UI, addr string) {
	u.session = pubkeyState{keys: []desktop.Key{fixedKey()}, addrs: []string{addr}}
	u.show(screenPubkey)
}

func TestGuidedShowsExplanation(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	openFixedPubkey(u, "")
	wantText(t, u, en(msg.UIExplainPubkeyLong))
	noText(t, u, en(msg.UIExplainPubkeyShort))
	u.show(screenOnboard)
	wantText(t, u, en(msg.UIExplainOnboardLong))
}

func TestHintsShowsOneLine(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpHints))
	openFixedPubkey(u, "")
	wantText(t, u, en(msg.UIExplainPubkeyShort))
	noText(t, u, en(msg.UIExplainPubkeyLong))
	u.show(screenOnboard)
	wantText(t, u, en(msg.UIExplainOnboardShort))
	noText(t, u, en(msg.UIExplainOnboardLong))
}

func TestImportWarnsToDeleteConf(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	openFixedPubkey(u, "")
	u.importConf("vpn.conf", []byte(conf))
	wantText(t, u, en(msg.UIImportDeleteHint))

	u, _ = start(t, "en")
	openFixedPubkey(u, "")
	u.importConf("vpn.conf", []byte(conf))
	noText(t, u, en(msg.UIImportDeleteHint))
}

func TestGlossaryOnlyWithHelp(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpHints))
	openFixedPubkey(u, "")
	tap(t, u, "?")
	wantText(t, u, en(msg.UIGlossaryPeer))

	u, _ = start(t, "en")
	openFixedPubkey(u, "")
	walk(u, func(o fyne.CanvasObject) {
		if b, ok := o.(*widget.Button); ok && b.Text == "?" {
			t.Fatal("expert mode shows a glossary button")
		}
	})
}

func TestGuideHasKeyAndVersion(t *testing.T) {
	versions := map[desktop.ServerKind][2]string{
		desktop.ServerOPNsense: {"OPNsense", "26.x"},
		desktop.ServerPfSense:  {"pfSense", "CE 2.8 / Plus 25.x"},
		desktop.ServerMikroTik: {"MikroTik RouterOS", "7"},
		desktop.ServerLinux:    {"Linux", "wg-quick"},
	}
	for _, k := range []desktop.ServerKind{desktop.ServerOPNsense, desktop.ServerPfSense, desktop.ServerMikroTik, desktop.ServerLinux, desktop.ServerOther} {
		s := ownerSurvey(desktop.HelpGuided)
		s.Server = k
		u, _ := startGuided(t, s)
		openFixedPubkey(u, "10.8.0.2")
		u.show(screenGuide)
		key := fixedKey().PublicBase64()
		wantText(t, u, key)
		wantText(t, u, "10.8.0.2/32")
		if v, ok := versions[k]; ok {
			wantText(t, u, msg.Render("en", msg.UIGuideVersionNote, msg.Args{"product": v[0], "version": v[1]}))
		} else {
			noText(t, u, "Written for")
		}
		wantText(t, u, en(msg.UIGuideSomeoneElse))
		wantText(t, u, en(msg.UIGuideDone))
	}
}

func TestGuideCommands(t *testing.T) {
	s := ownerSurvey(desktop.HelpGuided)
	s.Server = desktop.ServerLinux
	u, _ := startGuided(t, s)
	openFixedPubkey(u, "10.8.0.2")
	u.show(screenGuide)
	wantText(t, u, "sudo wg syncconf wg0 <(wg-quick strip wg0)")
	wantText(t, u, desktop.PeerBlock("en", fixedKey(), netip.MustParseAddr("10.8.0.2")))

	s.Server = desktop.ServerMikroTik
	u, _ = startGuided(t, s)
	openFixedPubkey(u, "10.8.0.2")
	u.show(screenGuide)
	wantText(t, u, `/interface/wireguard/peers/add interface=wireguard1 public-key="`+fixedKey().PublicBase64()+`" allowed-address=10.8.0.2/32`)
}

func TestGuideCopiesOnlyPublicValues(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	openFixedPubkey(u, "10.8.0.2")
	u.show(screenGuide)
	var copied []string
	walk(u, func(o fyne.CanvasObject) {
		if b, ok := o.(*widget.Button); ok && b.Text == en(msg.UICopy) {
			test.Tap(b)
			copied = append(copied, u.app.Clipboard().Content())
		}
	})
	want := []string{fixedKey().PublicBase64(), "10.8.0.2/32"}
	if !slices.Equal(copied, want) {
		t.Fatalf("copied %q, want %q", copied, want)
	}
}

func TestGuideDoneAndSomeoneElse(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	openFixedPubkey(u, "10.8.0.2")
	u.openStep(desktop.StepServerAdded)
	if u.screen != screenGuide {
		t.Fatalf("screen %v, want guide", u.screen)
	}
	tap(t, u, en(msg.UIGuideSomeoneElse))
	if u.screen != screenPubkey || u.progress[desktop.StepServerAdded] {
		t.Fatalf("screen %v, progress %v", u.screen, u.progress)
	}
	u.show(screenGuide)
	tap(t, u, en(msg.UIGuideDone))
	if !storedProgress(u)[desktop.StepServerAdded] || u.screen != screenRoadmap {
		t.Fatalf("screen %v, stored %v", u.screen, storedProgress(u))
	}
}

func TestPubkeyOffersGuide(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpHints))
	openFixedPubkey(u, "")
	tap(t, u, en(msg.UIGuideOpen))
	if u.screen != screenGuide {
		t.Fatalf("screen %v", u.screen)
	}
	// Hints: the steps wait behind a button.
	noText(t, u, en(msg.UIGuideOPNsense1))
	tap(t, u, en(msg.UIGuideShow))
	wantText(t, u, en(msg.UIGuideOPNsense1))
}

func TestGuideTurkish(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	u.setLanguage("tr")
	openFixedPubkey(u, "10.8.0.2")
	u.show(screenGuide)
	wantText(t, u, msg.Render("tr", msg.UIGuideOPNsense1, nil))
	wantText(t, u, "VPN → WireGuard → Peers")
}
