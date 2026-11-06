package ui

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
	"rsc.io/qr"

	"github.com/Kodviva/latchwire/desktop/demo"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

func start(t *testing.T, lang string) (*UI, *demo.Backend) {
	t.Helper()
	t.Setenv("LATCHWIRE_LANG", lang)
	a := test.NewApp()
	t.Cleanup(func() { a.Quit() })
	b := demo.New()
	u := New(a, Options{Backend: b})
	u.win.Resize(fyne.NewSize(1000, 680))
	sync(u)
	return u, b
}

// sync runs one poll and waits for inspections to land.
func sync(u *UI) {
	u.pollOnce(context.Background())
	time.Sleep(20 * time.Millisecond)
}

// walk visits the window content and every overlay.
func walk(u *UI, fn func(fyne.CanvasObject)) {
	var visit func(o fyne.CanvasObject)
	visit = func(o fyne.CanvasObject) {
		if !o.Visible() {
			return
		}
		fn(o)
		switch w := o.(type) {
		case *fyne.Container:
			for _, c := range w.Objects {
				visit(c)
			}
		case fyne.Widget:
			for _, c := range test.WidgetRenderer(w).Objects() {
				visit(c)
			}
		}
	}
	visit(u.win.Canvas().Content())
	for _, o := range u.win.Canvas().Overlays().List() {
		visit(o)
	}
}

func screenText(u *UI) string {
	var b strings.Builder
	walk(u, func(o fyne.CanvasObject) {
		switch w := o.(type) {
		case *widget.RichText:
			b.WriteString(w.String() + "\n")
		case *canvas.Text:
			b.WriteString(w.Text + "\n")
		case *widget.Button:
			b.WriteString(w.Text + "\n")
		}
	})
	return b.String()
}

func wantText(t *testing.T, u *UI, s string) {
	t.Helper()
	if !strings.Contains(screenText(u), s) {
		t.Fatalf("%q not on screen:\n%s", s, screenText(u))
	}
}

func noText(t *testing.T, u *UI, s string) {
	t.Helper()
	if strings.Contains(screenText(u), s) {
		t.Fatalf("%q on screen:\n%s", s, screenText(u))
	}
}

func button(t *testing.T, u *UI, label string) *widget.Button {
	t.Helper()
	var found *widget.Button
	walk(u, func(o fyne.CanvasObject) {
		if b, ok := o.(*widget.Button); ok && b.Text == label {
			found = b
		}
	})
	if found == nil {
		t.Fatalf("no button %q on:\n%s", label, screenText(u))
	}
	return found
}

func tap(t *testing.T, u *UI, label string) {
	t.Helper()
	test.Tap(button(t, u, label))
}

func fields(u *UI) []*SecretField {
	var out []*SecretField
	walk(u, func(o fyne.CanvasObject) {
		if f, ok := o.(*SecretField); ok {
			out = append(out, f)
		}
	})
	return out
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 400 {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

func TestTunnelsScreen(t *testing.T) {
	u, _ := start(t, "en")
	wantText(t, u, "office")
	wantText(t, u, "Connected")
	wantText(t, u, "YubiKey 40727512")
	wantText(t, u, "Plugged in · private key in hardware")
	wantText(t, u, "48 seconds ago")
	wantText(t, u, "Disconnect")
}

func TestTunnelsCardRemoved(t *testing.T) {
	u, b := start(t, "en")
	b.SetCard(demo.CardA, false)
	sync(u)
	wantText(t, u, "No card · disconnected")
	wantText(t, u, "Not plugged in")
	wantText(t, u, "The card was removed")
	noText(t, u, "48 seconds ago")
	b.SetCard(demo.CardA, true)
	sync(u)
	noText(t, u, "The card was removed")
	wantText(t, u, "Connected")
}

func TestDisconnectAndConnect(t *testing.T) {
	u, _ := start(t, "en")
	tap(t, u, "Disconnect")
	eventually(t, "disconnected", func() bool { return strings.Contains(screenText(u), "Not connected") })
	eventually(t, "connect button", func() bool { return strings.Contains(screenText(u), "\nConnect\n") })
	eventually(t, "button enabled", func() bool { return !button(t, u, "Connect").Disabled() })
	tap(t, u, "Connect")
	eventually(t, "connected", func() bool { return strings.Contains(screenText(u), "Disconnect") })
}

func TestConnectErrorIsShownTranslated(t *testing.T) {
	u, b := start(t, "tr")
	u.selected = "servers"
	u.show(screenTunnels)
	b.SetCard(demo.CardA, false)
	tap(t, u, "Bağlan")
	eventually(t, "error", func() bool {
		return strings.Contains(screenText(u), msg.Render("tr", "DaemonNoCard", nil))
	})
}

func TestDaemonDownBanner(t *testing.T) {
	u, b := start(t, "tr")
	b.DaemonDown = true
	sync(u)
	wantText(t, u, msg.Render("tr", "CLIDaemonNotRunning", nil))
}

func TestEmptyStateOffersKeyCreation(t *testing.T) {
	u, b := start(t, "en")
	b.DaemonDown = true
	sync(u)
	wantText(t, u, "No tunnels yet")
	tap(t, u, "Create key on the card")
	wantText(t, u, "2 hardware keys found")
}

func TestOnboardShowsCardsAndSlots(t *testing.T) {
	u, _ := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	wantText(t, u, "STEP 1 / 2")
	wantText(t, u, "YubiKey 40727512")
	wantText(t, u, "Serial 40727513 · Firmware 5.8.0 · PIV")
	wantText(t, u, "Compatible")
	wantText(t, u, "The PIV PIN will be asked")
	var sel *widget.Select
	walk(u, func(o fyne.CanvasObject) {
		if s, ok := o.(*widget.Select); ok && s.Selected != "English" {
			sel = s
		}
	})
	if sel == nil || sel.Selected != "Retired slot 82 (recommended)" || len(sel.Options) != 20 {
		t.Fatalf("%+v", sel)
	}
}

func TestOccupiedSlotIsNotOffered(t *testing.T) {
	u, b := start(t, "en")
	if _, err := b.Keygen(demo.CardA, 0x82, stubAsker{}); err != nil {
		t.Fatal(err)
	}
	delete(u.infos, demo.CardA)
	u.inspect(demo.CardA)
	u.show(screenOnboard)
	time.Sleep(20 * time.Millisecond)
	found := false
	walk(u, func(o fyne.CanvasObject) {
		if s, ok := o.(*widget.Select); ok && s.Selected != "English" {
			found = true
			if slices.Contains(s.Options, "Retired slot 82 (recommended)") || len(s.Options) != 19 {
				t.Fatalf("offers %v", s.Options)
			}
		}
	})
	if !found {
		t.Fatal("no slot picker")
	}
	wantText(t, u, "Use this key")
}

type stubAsker struct{}

func (stubAsker) PIN(uint32, int) ([]byte, error) { return []byte("123456"), nil }
func (stubAsker) Fresh(uint32) (desktop.FreshSecrets, error) {
	return desktop.FreshSecrets{}, nil
}
func (stubAsker) ManagementKey(uint32) ([]byte, error) { return nil, nil }

func typeInto(f *SecretField, s string) {
	test.Type(f, s)
}

func generate(t *testing.T, u *UI) {
	t.Helper()
	tap(t, u, "Create key on the card")
	eventually(t, "PIN form", func() bool { return len(fields(u)) == 1 })
	wantText(t, u, "3 attempts left")
	typeInto(fields(u)[0], "123456")
	tap(t, u, "OK")
	eventually(t, "public key screen", func() bool { return u.screen == screenPubkey })
}

func TestKeygenThenPublicKey(t *testing.T) {
	u, _ := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	wantText(t, u, "STEP 2 / 2")
	wantText(t, u, "Key created on the card")
	wantText(t, u, "stays inside YubiKey 40727512")
	wantText(t, u, "AllowedIPs = <tunnel IP>/32")
	wantText(t, u, "Add a backup card")
	wantText(t, u, "Create for 40727513 too")
	if len(fields(u)) != 0 {
		t.Fatal("the PIN form is still up")
	}
}

func TestTunnelIPFillsPeerBlock(t *testing.T) {
	u, _ := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	var ip *widget.Entry
	walk(u, func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok {
			ip = e
		}
	})
	ip.SetText("10.8.0.2")
	wantText(t, u, "AllowedIPs = 10.8.0.2/32")
	tap(t, u, "Show QR")
	wantText(t, u, "There is nothing secret in it")
}

func TestCopyPublicKeyOnly(t *testing.T) {
	u, _ := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	tap(t, u, "Copy")
	got := u.app.Clipboard().Content()
	if len(got) != 44 && !strings.Contains(got, "[Peer]") {
		t.Fatalf("clipboard: %q", got)
	}
	if got == u.session.keys[0].PublicBase64() {
		return
	}
	if !strings.Contains(got, u.session.keys[0].PublicBase64()) {
		t.Fatalf("clipboard: %q", got)
	}
}

func TestBackupCardFlow(t *testing.T) {
	u, _ := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	tap(t, u, "Create for 40727513 too")
	if u.screen != screenOnboard || u.card.serial != demo.CardB {
		t.Fatal(u.screen, u.card.serial)
	}
	generate(t, u)
	if len(u.session.keys) != 2 || u.session.keys[1].Ref.Serial != demo.CardB {
		t.Fatalf("%+v", u.session.keys)
	}
	wantText(t, u, "Backup key on YubiKey 40727513 is ready")
}

const conf = "[Interface]\nPrivateKey = cFJ1c3RPbmx5QVRlc3RWYWx1ZU5vdEFSZWFsS2V5MDA=\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"

func TestImportConf(t *testing.T) {
	u, b := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	data := []byte(conf)
	u.importConf("my office!.conf", data)
	clear(data)
	wantText(t, u, "This file contained a PrivateKey line")
	var name *widget.Entry
	walk(u, func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok && e.Text == "myoffice" {
			name = e
		}
	})
	if name == nil {
		t.Fatal("no name field")
	}
	tap(t, u, "Add tunnel")
	eventually(t, "tunnel added", func() bool { return u.screen == screenTunnels })
	cfg := b.Added["myoffice"]
	if strings.Contains(strings.ToLower(cfg), "privatekey") || !strings.Contains(cfg, "KeyRef = piv://40727512/82") {
		t.Fatalf("%s", cfg)
	}
	wantText(t, u, "Tunnel myoffice added.")
}

func TestImportTwoCardsAsksBackupAddress(t *testing.T) {
	u, b := start(t, "en")
	u.show(screenOnboard)
	sync(u)
	generate(t, u)
	tap(t, u, "Create for 40727513 too")
	generate(t, u)
	u.importConf("vpn.conf", []byte(conf))
	tap(t, u, "Add tunnel")
	eventually(t, "error", func() bool { return strings.Contains(screenText(u), "This is not an IP address.") })
	var ip *widget.Entry
	walk(u, func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok && e.PlaceHolder != "" && e.Text == "" {
			ip = e
		}
	})
	ip.SetText("10.8.0.3")
	tap(t, u, "Add tunnel")
	eventually(t, "added", func() bool { return b.Added["vpn"] != "" })
	if !strings.Contains(b.Added["vpn"], "[Identity]") || !strings.Contains(b.Added["vpn"], "Address = 10.8.0.3/32") {
		t.Fatal(b.Added["vpn"])
	}
}

func TestImportRefusesHooks(t *testing.T) {
	u, _ := start(t, "tr")
	u.show(screenOnboard)
	sync(u)
	u.session = pubkeyState{keys: []desktop.Key{{Ref: keyref.Ref{Serial: 1, Slot: 0x82}, Public: [32]byte{1}}}, addrs: []string{""}}
	u.show(screenPubkey)
	u.importConf("x.conf", []byte(strings.Replace(conf, "Address", "PostUp = rm\nAddress", 1)))
	tap(t, u, "Tünel ekle")
	eventually(t, "error", func() bool { return strings.Contains(screenText(u), "PostUp") })
	wantText(t, u, "komutları asla çalıştırmaz")
}

func TestFormFitsItsButtons(t *testing.T) {
	u, _ := start(t, "tr")
	ok := widget.NewButton("Tamam", nil)
	text := rich(strings.Repeat("uzun bir uyarı metni ", 30), "", "", fyne.TextStyle{})
	pop := modal(u.win, 460, container.NewVBox(text, ok))
	pop.Show()
	defer pop.Hide()
	drv := fyne.CurrentApp().Driver()
	bottom := drv.AbsolutePositionForObject(ok).Y + ok.Size().Height
	if limit := drv.AbsolutePositionForObject(pop.Content).Y + pop.Content.Size().Height + 1; bottom > limit {
		t.Fatalf("the button ends at %v, the form at %v", bottom, limit)
	}
}

func TestReflow(t *testing.T) {
	got := reflow("one line\ncontinues.\nLatchwire will:\n  1. first\n     still first,\n  2. second.\nEnd")
	want := "one line continues.\nLatchwire will:\n1. first still first,\n2. second.\nEnd"
	if got != want {
		t.Fatalf("%q", got)
	}
}

func TestQRImageScans(t *testing.T) {
	c, err := qr.Encode("[Peer]", qr.M)
	if err != nil {
		t.Fatal(err)
	}
	img := qrImage(c)
	if w := img.Bounds().Dx(); w != (c.Size+8)*8 {
		t.Fatal(w)
	}
	if r, _, _, _ := img.At(0, 0).RGBA(); r != 0xFFFF {
		t.Fatal("no quiet zone")
	}
	if r, _, _, _ := img.At(4*8, 4*8).RGBA(); r != 0 {
		t.Fatal("the finder pattern is not black")
	}
}

func TestTunnelName(t *testing.T) {
	cases := map[string]string{"office.conf": "office", "a b/c d.conf": "cd", ".hidden.conf": "hidden",
		"çok-uzun-bir-tünel-adı-burada.conf": "ok-uzun-bir-tne"}
	for in, want := range cases {
		if got := tunnelNameFrom(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestTurkishScreens(t *testing.T) {
	u, _ := start(t, "tr")
	wantText(t, u, "Bağlı")
	wantText(t, u, "Son el sıkışma")
	u.show(screenOnboard)
	sync(u)
	wantText(t, u, "2 donanım anahtarı bulundu")
	wantText(t, u, "Anahtarı kartta oluştur")
	noText(t, u, "Compatible")
}

func TestLanguageSwitch(t *testing.T) {
	u, _ := start(t, "en")
	u.setLanguage("tr")
	wantText(t, u, "Bağlantıyı kes")
	if u.app.Preferences().String(prefLang) != "tr" {
		t.Fatal("not remembered")
	}
}

func TestTrayMenu(t *testing.T) {
	u, _ := start(t, "en")
	m := u.trayMenu()
	var labels []string
	for _, it := range m.Items {
		labels = append(labels, it.Label)
	}
	got := strings.Join(labels, "|")
	if !strings.HasPrefix(got, "1 tunnel connected|Disconnect office|Connect servers||Open Latchwire|Quit Latchwire") {
		t.Fatal(got)
	}
}

func TestQuitAsksWhileConnected(t *testing.T) {
	u, _ := start(t, "en")
	u.askQuit()
	wantText(t, u, "1 tunnel is connected.")
	wantText(t, u, "close about 10 seconds later")
}

// ---- secrets ----

func TestSecretFieldWipes(t *testing.T) {
	test.NewApp()
	f := NewSecretField()
	w := test.NewWindow(f)
	defer w.Close()
	test.Type(f, "1234")
	f.TypedKey(&fyne.KeyEvent{Name: fyne.KeyBackspace})
	f.TypedRune('ş')
	got := f.Take()
	if string(got) != "123ş" {
		t.Fatalf("%q", got)
	}
	for _, b := range f.buf {
		if b != 0 {
			t.Fatal("the field kept input")
		}
	}
	if f.Len() != 0 {
		t.Fatal(f.Len())
	}
}

func TestSecretFieldShowsDotsOnly(t *testing.T) {
	test.NewApp()
	f := NewSecretField()
	w := test.NewWindow(f)
	defer w.Close()
	test.Type(f, "9876")
	test.WidgetRenderer(f)
	if f.dots.Text != "••••" {
		t.Fatalf("%q", f.dots.Text)
	}
}

func TestSecretFieldLimit(t *testing.T) {
	test.NewApp()
	f := NewSecretField()
	test.NewWindow(f)
	test.Type(f, strings.Repeat("a", maxSecret+10))
	if f.Len() != maxSecret {
		t.Fatal(f.Len())
	}
}

func TestSecretFieldTakesNoPaste(t *testing.T) {
	if _, ok := any(&SecretField{}).(fyne.Shortcutable); ok {
		t.Fatal("the field handles shortcuts, so paste could reach it")
	}
}

func desc() keyprovider.Description {
	return keyprovider.Description{Serial: demo.CardA, Slot: 0x82}
}

func TestPromptReturnsPIN(t *testing.T) {
	u, _ := start(t, "en")
	got := make(chan string, 1)
	go func() {
		s, err := u.Prompter().PIN(desc(), 2)
		if err != nil {
			t.Error(err)
		}
		got <- s
	}()
	eventually(t, "form", func() bool { return len(fields(u)) == 1 })
	wantText(t, u, "PIN for YubiKey 40727512, slot 82")
	wantText(t, u, "2 attempts left")
	f := fields(u)[0]
	test.Type(f, "123456")
	tap(t, u, "OK")
	if s := <-got; s != "123456" {
		t.Fatal(s)
	}
	for _, b := range f.buf {
		if b != 0 {
			t.Fatal("the field kept the PIN")
		}
	}
}

func TestPromptLastRetryWarns(t *testing.T) {
	u, _ := start(t, "en")
	go u.Prompter().PIN(desc(), 1)
	eventually(t, "form", func() bool { return len(fields(u)) == 1 })
	wantText(t, u, "only one PIN attempt is left")
	tap(t, u, "Cancel")
}

func TestPromptCancelAndTimeout(t *testing.T) {
	u, _ := start(t, "en")
	res := make(chan error, 1)
	go func() {
		_, err := u.Prompter().PIN(desc(), 3)
		res <- err
	}()
	eventually(t, "form", func() bool { return len(fields(u)) == 1 })
	test.Type(fields(u)[0], "1234")
	f := fields(u)[0]
	tap(t, u, "Cancel")
	if err := <-res; !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatal(err)
	}
	if f.Len() != 0 {
		t.Fatal("cancel left the input")
	}

	old := pinTimeout
	pinTimeout = 30 * time.Millisecond
	defer func() { pinTimeout = old }()
	go func() {
		_, err := u.Prompter().PIN(desc(), 3)
		res <- err
	}()
	if err := <-res; !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatal(err)
	}
	if len(fields(u)) != 0 {
		t.Fatal("the form stayed up after the timeout")
	}
}

func TestPromptWarnShowsTranslated(t *testing.T) {
	u, _ := start(t, "tr")
	u.Prompter().Warn("wrong PIN, 2 attempts left")
	eventually(t, "notice", func() bool { return strings.Contains(screenText(u), "yanlış PIN, 2 deneme hakkı kaldı") })
}

func TestFreshChecks(t *testing.T) {
	v := func(a, b, c, d, e string) [][]byte {
		return [][]byte{[]byte(a), []byte(b), []byte(c), []byte(d), []byte(e)}
	}
	if s := checkFresh("en", v("1", "123456", "123456", "87654321", "87654321")); s != "" {
		t.Fatal(s)
	}
	if s := checkFresh("en", v("1", "123456", "123457", "87654321", "87654321")); s != msg.KeygenSecretMismatch {
		t.Fatal(s)
	}
	if s := checkFresh("en", v("1", "123", "123", "87654321", "87654321")); s != msg.KeygenSecretRules {
		t.Fatal(s)
	}
}
