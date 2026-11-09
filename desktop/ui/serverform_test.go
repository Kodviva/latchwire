package ui

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/msg"
)

const serverKeyA = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func rendered(id msg.ID) string { return msg.Render("en", id, nil) }

// fill types value into the entry whose placeholder is the given label.
func fill(t *testing.T, u *UI, label msg.ID, value string) {
	t.Helper()
	want := rendered(label)
	var found *widget.Entry
	walk(u, func(o fyne.CanvasObject) {
		// The form is an overlay, so it is visited after the page below
		// it: the last match wins, and an empty one beats a prefilled one.
		if e, ok := o.(*widget.Entry); ok && e.PlaceHolder == want && (found == nil || found.Text != "" || e.Text == "") {
			found = e
		}
	})
	if found == nil {
		t.Fatalf("no field %q on:\n%s", want, screenText(u))
	}
	found.SetText(value)
}

func openAdvanced(t *testing.T, u *UI) {
	t.Helper()
	want := rendered(msg.UIAdvanced)
	var acc *widget.Accordion
	walk(u, func(o fyne.CanvasObject) {
		if a, ok := o.(*widget.Accordion); ok {
			acc = a
		}
	})
	if acc == nil || len(acc.Items) == 0 || acc.Items[0].Title != want {
		t.Fatal("no Advanced section")
	}
	acc.Open(0)
}

func TestServerFormAddsTunnel(t *testing.T) {
	u, b := start(t, "en")
	openPubkey(t, u)
	u.session.addrs[0] = "10.8.0.2"
	u.showServerForm()
	fill(t, u, msg.UIServerEndpoint, "vpn.example.com:51820")
	fill(t, u, msg.UIServerPublicKey, serverKeyA)
	tap(t, u, rendered(msg.UIImportAdd))
	eventually(t, "tunnel added", func() bool { return u.screen == screenTunnels && len(b.Added) > 0 })
	var cfg string
	for _, c := range b.Added {
		cfg = c
	}
	if !strings.Contains(cfg, "KeyRef = ") || !strings.Contains(cfg, "Endpoint = vpn.example.com:51820") ||
		!strings.Contains(cfg, "AllowedIPs = 0.0.0.0/0, ::/0") || !strings.Contains(cfg, "Address = 10.8.0.2/32") {
		t.Fatal(cfg)
	}
}

func TestServerFormOnlyNetworks(t *testing.T) {
	u, b := start(t, "en")
	openPubkey(t, u)
	u.session.addrs[0] = "10.8.0.2"
	u.showServerForm()
	fill(t, u, msg.UIServerEndpoint, "vpn.example.com:51820")
	fill(t, u, msg.UIServerPublicKey, serverKeyA)
	var radio *widget.RadioGroup
	walk(u, func(o fyne.CanvasObject) {
		if r, ok := o.(*widget.RadioGroup); ok {
			radio = r
		}
	})
	radio.SetSelected(rendered(msg.UIOnlyNetworks))
	fill(t, u, msg.UINetworksHint, "10.0.0.0/24")
	tap(t, u, rendered(msg.UIImportAdd))
	eventually(t, "tunnel added", func() bool { return len(b.Added) > 0 })
	for _, c := range b.Added {
		if !strings.Contains(c, "AllowedIPs = 10.0.0.0/24") {
			t.Fatal(c)
		}
	}
}

func TestServerFormShowsFieldError(t *testing.T) {
	u, _ := start(t, "en")
	openPubkey(t, u)
	u.session.addrs[0] = "10.8.0.2"
	u.showServerForm()
	fill(t, u, msg.UIServerEndpoint, "no-port")
	tap(t, u, rendered(msg.UIImportAdd))
	wantText(t, u, rendered(msg.UIServerEndpointInvalid))
	if u.screen != screenPubkey {
		t.Fatal(u.screen)
	}
}

func TestServerFormErrorNamesNoValue(t *testing.T) {
	u, _ := start(t, "en")
	openPubkey(t, u)
	u.session.addrs[0] = "10.8.0.2"
	u.showServerForm()
	fill(t, u, msg.UIServerEndpoint, "vpn.example.com:51820")
	fill(t, u, msg.UIServerPublicKey, serverKeyA)
	openAdvanced(t, u)
	f := findSecretField(u)
	test.Type(f, "not-base64-psk")
	tap(t, u, rendered(msg.UIImportAdd))
	wantText(t, u, rendered(msg.UIServerPresharedKeyInvalid))
	noText(t, u, "not-base64-psk")
}

func TestServerFormPSKIsSecret(t *testing.T) {
	u, b := start(t, "en")
	openPubkey(t, u)
	u.session.addrs[0] = "10.8.0.2"
	u.showServerForm()
	openAdvanced(t, u)
	f := findSecretField(u)
	if f == nil {
		t.Fatal("PSK is not a SecretField")
	}
	fill(t, u, msg.UIServerEndpoint, "vpn.example.com:51820")
	fill(t, u, msg.UIServerPublicKey, serverKeyA)
	test.Type(f, serverKeyA)
	tap(t, u, rendered(msg.UIImportAdd))
	eventually(t, "tunnel added", func() bool { return len(b.Added) > 0 })
	for _, c := range b.Added {
		if !strings.Contains(c, "PresharedKey = "+serverKeyA) {
			t.Fatal(c)
		}
	}
	if f.Len() != 0 {
		t.Fatal("PSK buffer not wiped")
	}
}

func findSecretField(u *UI) *SecretField {
	if f := fields(u); len(f) > 0 {
		return f[0]
	}
	return nil
}

func TestServerFormAsksBackupAddress(t *testing.T) {
	u, b := start(t, "en")
	openPubkey(t, u)
	tap(t, u, "Create for 40727513 too")
	generate(t, u)
	u.session.addrs[0] = "10.8.0.2"
	u.showServerForm()
	fill(t, u, msg.UIServerEndpoint, "vpn.example.com:51820")
	fill(t, u, msg.UIServerPublicKey, serverKeyA)
	tap(t, u, rendered(msg.UIImportAdd))
	wantText(t, u, rendered(msg.UITunnelIPInvalid))
	fill(t, u, msg.UITunnelIPHint, "10.8.0.3")
	tap(t, u, rendered(msg.UIImportAdd))
	eventually(t, "added", func() bool { return len(b.Added) > 0 })
	for _, c := range b.Added {
		if !strings.Contains(c, "[Identity]") || !strings.Contains(c, "Address = 10.8.0.3/32") {
			t.Fatal(c)
		}
	}
}

func TestServerFormSecondServer(t *testing.T) {
	u, _ := start(t, "en")
	openPubkey(t, u)
	u.session.addrs[0] = "10.8.0.2"
	u.showServerForm()
	openAdvanced(t, u)
	tap(t, u, rendered(msg.UIAddSecondServer))
	n := 0
	walk(u, func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok && e.PlaceHolder == rendered(msg.UIServerEndpoint) {
			n++
		}
	})
	if n != 2 {
		t.Fatalf("%d server rows", n)
	}
}
