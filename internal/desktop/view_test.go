package desktop

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

var (
	t0      = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	plugged = func(uint32) bool { return true }
	pulled  = func(uint32) bool { return false }
)

func TestConnectedView(t *testing.T) {
	v := NewTunnelView("en", ipc.TunnelStatus{Name: "office", State: daemon.StateConnected,
		Identity: "piv://40727512/82", LastHandshake: t0.Add(-48 * time.Second).Format(time.RFC3339)}, plugged, t0)
	if !v.Lit || v.Label != "Connected" || v.Key != "YubiKey 40727512" || v.KeyWarn {
		t.Fatalf("%+v", v)
	}
	if v.Handshake != "48 seconds ago" || v.Connects || v.Action != "Disconnect" {
		t.Fatalf("%+v", v)
	}
}

func TestTurkishView(t *testing.T) {
	v := NewTunnelView("tr", ipc.TunnelStatus{Name: "ofis", State: daemon.StateConnected,
		Identity: "piv://40727512/82", LastHandshake: t0.Add(-48 * time.Second).Format(time.RFC3339)}, plugged, t0)
	if v.Label != "Bağlı" || v.Handshake != "48 saniye önce" || v.Action != "Bağlantıyı kes" {
		t.Fatalf("%+v", v)
	}
}

func TestCardRemovedView(t *testing.T) {
	for _, lang := range []string{"en", "tr"} {
		v := NewTunnelView(lang, ipc.TunnelStatus{Name: "office", State: daemon.StateCardRemoved,
			Identity: "piv://40727512/82"}, pulled, t0)
		if v.Banner != msg.Render(lang, msg.UICardRemoved, nil) || !v.KeyWarn || v.Lit {
			t.Fatalf("%+v", v)
		}
		if v.Handshake != "—" || v.Connects {
			t.Fatalf("%+v", v)
		}
	}
}

func TestDisconnectedView(t *testing.T) {
	v := NewTunnelView("en", ipc.TunnelStatus{Name: "x", State: daemon.StateDisconnected}, plugged, t0)
	if !v.Connects || v.Action != "Connect" || v.Key != "No card in use" || v.KeyNote != "" {
		t.Fatalf("%+v", v)
	}
}

func TestErrorKeepsDisconnect(t *testing.T) {
	// Only a down lifts a failed tunnel's kill switch.
	v := NewTunnelView("en", ipc.TunnelStatus{Name: "x", State: daemon.StateError,
		KillSwitch: ipc.KillSwitchStatusBlocking}, plugged, t0)
	if v.Connects || v.Blocking == "" || v.Label != "Error" {
		t.Fatalf("%+v", v)
	}
}

func TestWarningTranslated(t *testing.T) {
	v := NewTunnelView("tr", ipc.TunnelStatus{Name: "x", State: daemon.StateConnected,
		Warning: msg.DaemonWarnDNSBusy}, plugged, t0)
	if strings.Contains(v.Warning, "tunnel") {
		t.Fatal(v.Warning)
	}
}

func TestAgo(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0 seconds ago"}, {time.Second, "1 second ago"}, {59 * time.Second, "59 seconds ago"},
		{time.Minute, "1 minute ago"}, {90 * time.Minute, "1 hour ago"}, {3 * time.Hour, "3 hours ago"},
		{-time.Second, "0 seconds ago"},
	}
	for _, c := range cases {
		if got := Ago("en", c.d); got != c.want {
			t.Error(fmt.Sprint(c.d), got)
		}
	}
}

// A disconnected tunnel names the card that holds its key: ready when it is
// plugged in, a warning when none of its cards is.
func TestDisconnectedViewNamesItsCard(t *testing.T) {
	st := ipc.TunnelStatus{Name: "office", State: daemon.StateDisconnected,
		Keys: []string{"piv://40727512/82", "piv://40727513/82"}}
	only := func(s uint32) func(uint32) bool { return func(x uint32) bool { return x == s } }

	v := NewTunnelView("en", st, only(40727513), t0)
	if v.Key != "YubiKey 40727513" || v.KeyNote != "Plugged in · ready to connect" || v.KeyWarn {
		t.Fatalf("backup plugged in: %+v", v)
	}
	v = NewTunnelView("tr", st, only(40727512), t0)
	if v.Key != "YubiKey 40727512" || v.KeyNote != "Takılı · bağlanmaya hazır" || v.KeyWarn {
		t.Fatalf("tr: %+v", v)
	}
	v = NewTunnelView("en", st, pulled, t0)
	if v.Key != "YubiKey 40727512" || v.KeyNote != "Not plugged in" || !v.KeyWarn {
		t.Fatalf("none plugged in: %+v", v)
	}
	// An old daemon reports no keys: the old wording stays.
	v = NewTunnelView("en", ipc.TunnelStatus{Name: "office", State: daemon.StateDisconnected}, plugged, t0)
	if v.Key != "No card in use" || v.KeyNote != "" {
		t.Fatalf("no keys: %+v", v)
	}
}
