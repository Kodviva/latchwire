package desktop

import (
	"time"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// TunnelView is one tunnel as the tunnels screen shows it, in one language.
type TunnelView struct {
	Name  string
	State string // a daemon.State* value
	Label string // the state, for people
	Lit   bool   // the state pill and dot are amber

	Key     string // "YubiKey 40727512", or a note that no card is in use
	KeyNote string
	KeyWarn bool

	Handshake string

	// Banner explains a removed card; Blocking a kill switch that blocks
	// traffic; Warning is the daemon's warning, translated.
	Banner   string
	Blocking string
	Warning  string

	Action   string // label of the main button
	Connects bool   // the button connects (otherwise it disconnects)
}

// NewTunnelView builds the view of st. present says whether a card is
// plugged in right now.
func NewTunnelView(lang string, st ipc.TunnelStatus, present func(serial uint32) bool, now time.Time) TunnelView {
	v := TunnelView{Name: st.Name, State: st.State, Handshake: msg.Render(lang, msg.UIHandshakeNone, nil)}
	switch st.State {
	case daemon.StateConnected:
		v.Label, v.Lit = msg.Render(lang, msg.UIStateConnected, nil), true
	case daemon.StateConnecting:
		v.Label = msg.Render(lang, msg.UIStateConnecting, nil)
	case daemon.StateCardRemoved:
		v.Label = msg.Render(lang, msg.UIStateCardRemoved, nil)
		v.Banner = msg.Render(lang, msg.UICardRemoved, nil)
	case daemon.StateError:
		v.Label = msg.Render(lang, msg.UIStateError, nil)
	default:
		v.Label = msg.Render(lang, msg.UIStateDisconnected, nil)
	}

	v.Key = msg.Render(lang, msg.UIKeyNone, nil)
	if st.Identity == "" {
		v.idleKey(lang, st.Keys, present)
	}
	if ref, err := keyref.Parse(st.Identity); err == nil {
		v.Key = msg.Render(lang, msg.UIDeviceName, msg.Args{"serial": ref.Serial})
		if present(ref.Serial) {
			v.KeyNote = msg.Render(lang, msg.UIKeyPresent, nil)
		} else {
			v.KeyNote, v.KeyWarn = msg.Render(lang, msg.UIKeyAbsent, nil), true
		}
	}

	if t, err := time.Parse(time.RFC3339, st.LastHandshake); err == nil && st.State == daemon.StateConnected {
		v.Handshake = Ago(lang, now.Sub(t))
	}
	if st.KillSwitch == ipc.KillSwitchStatusBlocking {
		v.Blocking = msg.Render(lang, msg.UIBlocking, nil)
	}
	v.Warning = msg.Translate(lang, st.Warning)

	v.Connects = st.State == daemon.StateDisconnected
	if v.Connects {
		v.Action = msg.Render(lang, msg.UIConnect, nil)
	} else {
		v.Action = msg.Render(lang, msg.UIDisconnect, nil)
	}
	return v
}

// idleKey names the card a tunnel that is not bound would use: the first of
// its keys whose card is plugged in, else the first key, marked absent.
func (v *TunnelView) idleKey(lang string, keys []string, present func(uint32) bool) {
	var first *keyref.Ref
	for _, k := range keys {
		ref, err := keyref.Parse(k)
		if err != nil {
			continue
		}
		if present(ref.Serial) {
			v.Key = msg.Render(lang, msg.UIDeviceName, msg.Args{"serial": ref.Serial})
			v.KeyNote = msg.Render(lang, msg.UIKeyReady, nil)
			return
		}
		if first == nil {
			first = &ref
		}
	}
	if first != nil {
		v.Key = msg.Render(lang, msg.UIDeviceName, msg.Args{"serial": first.Serial})
		v.KeyNote, v.KeyWarn = msg.Render(lang, msg.UIKeyAbsent, nil), true
	}
}

// Ago says how long ago something happened.
func Ago(lang string, d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return msg.Render(lang, msg.UIAgoSeconds, msg.Args{"n": int(d / time.Second)})
	case d < time.Hour:
		return msg.Render(lang, msg.UIAgoMinutes, msg.Args{"n": int(d / time.Minute)})
	}
	return msg.Render(lang, msg.UIAgoHours, msg.Args{"n": int(d / time.Hour)})
}
