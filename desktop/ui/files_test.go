package ui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"

	"github.com/Kodviva/latchwire/internal/msg"
)

func TestPickerOpensImport(t *testing.T) {
	u, _ := start(t, "en")
	p := filepath.Join(t.TempDir(), "office.conf")
	os.WriteFile(p, []byte(conf), 0o600)
	u.pick = func(string) (string, error) { return p, nil }
	openPubkey(t, u)
	u.pickConf()
	eventually(t, "import form", func() bool {
		return strings.Contains(screenText(u), msg.Render("en", msg.UIImportTitle, nil))
	})
}

func TestPickerCancelDoesNothing(t *testing.T) {
	u, _ := start(t, "en")
	asked := make(chan struct{})
	u.pick = func(string) (string, error) { close(asked); return "", nil }
	openPubkey(t, u)
	u.pickConf()
	<-asked
	time.Sleep(50 * time.Millisecond)
	noText(t, u, msg.Render("en", msg.UIImportTitle, nil))
	if len(u.win.Canvas().Overlays().List()) != 0 {
		t.Fatal("a dialog opened after cancel")
	}
}

func TestPickerFallsBack(t *testing.T) {
	u, _ := start(t, "en")
	u.pick = func(string) (string, error) { return "", errors.New("no zenity") }
	openPubkey(t, u)
	u.pickConf()
	eventually(t, "Fyne file dialog", func() bool { return len(u.win.Canvas().Overlays().List()) > 0 })
}

func TestDropRejectsNonConfAndLarge(t *testing.T) {
	u, _ := start(t, "en")
	openPubkey(t, u)
	dir := t.TempDir()
	txt := filepath.Join(dir, "notes.txt")
	os.WriteFile(txt, []byte("x"), 0o600)
	big := filepath.Join(dir, "big.conf")
	os.WriteFile(big, make([]byte, maxConfBytes+1), 0o600)
	u.dropped([]fyne.URI{storage.NewFileURI(txt)})
	if u.notice != msg.Render("en", msg.UIDropNotConf, nil) {
		t.Fatalf("notice %q", u.notice)
	}
	u.dropped([]fyne.URI{storage.NewFileURI(big)})
	if !strings.Contains(u.notice, fmt.Sprint(maxConfBytes)) {
		t.Fatalf("notice %q", u.notice)
	}
}

func TestDropImportsConf(t *testing.T) {
	u, _ := start(t, "en")
	openPubkey(t, u)
	p := filepath.Join(t.TempDir(), "Office.CONF")
	os.WriteFile(p, []byte(conf), 0o600)
	u.dropped([]fyne.URI{storage.NewFileURI(filepath.Join(filepath.Dir(p), "a.txt")), storage.NewFileURI(p)})
	wantText(t, u, msg.Render("en", msg.UIImportTitle, nil))
}

func TestDropIgnoredOffPubkeyScreen(t *testing.T) {
	u, _ := start(t, "en")
	p := filepath.Join(t.TempDir(), "office.conf")
	os.WriteFile(p, []byte(conf), 0o600)
	u.dropped([]fyne.URI{storage.NewFileURI(p)})
	noText(t, u, msg.Render("en", msg.UIImportTitle, nil))
	if u.notice != "" {
		t.Fatal(u.notice)
	}
}

func TestReadConfLimit(t *testing.T) {
	u, _ := start(t, "en")
	openPubkey(t, u)
	u.readConf("x.conf", strings.NewReader(strings.Repeat("a", maxConfBytes+1)))
	if !strings.Contains(u.notice, fmt.Sprint(maxConfBytes)) {
		t.Fatal(u.notice)
	}
}

func TestDropIgnoredWhilePopupOpen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "office.conf")
	os.WriteFile(p, []byte(conf), 0o600)
	for name, open := range map[string]func(u *UI){
		"server form": func(u *UI) { u.showServerForm() },
		"import":      func(u *UI) { u.importConf("vpn.conf", []byte(conf)) },
		"glossary":    func(u *UI) { u.showTerm(msg.UIGlossaryPeer) },
	} {
		u, _ := start(t, "en")
		openPubkey(t, u)
		open(u)
		n := len(u.win.Canvas().Overlays().List())
		u.dropped([]fyne.URI{storage.NewFileURI(p)})
		u.dropped([]fyne.URI{storage.NewFileURI(filepath.Join(filepath.Dir(p), "a.txt"))})
		if got := len(u.win.Canvas().Overlays().List()); got != n || u.notice != "" {
			t.Fatalf("%s: overlays %d (was %d), notice %q", name, got, n, u.notice)
		}
	}
}
