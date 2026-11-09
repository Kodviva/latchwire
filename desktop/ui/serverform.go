package ui

import (
	"errors"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// serverFormErrors maps the field a desktop.FieldError names, without any
// peer index, to the message that is shown under that field.
var serverFormErrors = map[string]msg.ID{
	"address":      msg.UIServerAddressInvalid,
	"dns":          msg.UIServerDNSInvalid,
	"mtu":          msg.UIServerMTUInvalid,
	"peers":        msg.UIServerPeersInvalid,
	"endpoint":     msg.UIServerEndpointInvalid,
	"publickey":    msg.UIServerPublicKeyInvalid,
	"presharedkey": msg.UIServerPresharedKeyInvalid,
	"networks":     msg.UIServerNetworksInvalid,
	"keepalive":    msg.UIServerKeepaliveInvalid,
}

// fieldKey returns "peers[1].endpoint" as peer 1 and "endpoint".
func fieldKey(field string) (peer int, key string) {
	rest, ok := strings.CutPrefix(field, "peers[")
	if !ok {
		return -1, field
	}
	i, key, ok := strings.Cut(rest, "].")
	n, err := strconv.Atoi(i)
	if !ok || err != nil {
		return -1, field
	}
	return n, key
}

// peerRow holds the inputs of one server.
type peerRow struct {
	endpoint, pubkey, networks, keepalive *widget.Entry
	psk                                   *SecretField
	mode                                  *widget.RadioGroup
	errs                                  map[string]*widget.RichText
	box                                   *fyne.Container
}

// errText makes the line under a field that shows one error.
func (r *peerRow) errText(key string) fyne.CanvasObject {
	t := rich("", nameAmber, sizeSmall, fyne.TextStyle{})
	r.errs[key] = t
	return t
}

func setErr(t *widget.RichText, s string) {
	t.Segments[0].(*widget.TextSegment).Text = s
	t.Refresh()
}

// showServerForm asks for the server's details and builds the tunnel from
// them, for users who cannot write a .conf. The keys live only in memory:
// after a restart there are none, and the key screen, whose "Use this key"
// leads back here, opens instead.
func (u *UI) showServerForm() {
	s := &u.session
	if len(s.keys) == 0 {
		u.show(screenOnboard)
		return
	}
	allText, onlyText := u.t(msg.UIAllTraffic), u.t(msg.UIOnlyNetworks)

	newRow := func() *peerRow {
		r := &peerRow{errs: map[string]*widget.RichText{}}
		r.endpoint = widget.NewEntry()
		r.endpoint.SetPlaceHolder(u.t(msg.UIServerEndpoint))
		r.pubkey = widget.NewEntry()
		r.pubkey.SetPlaceHolder(u.t(msg.UIServerPublicKey))
		r.networks = widget.NewEntry()
		r.networks.SetPlaceHolder(u.t(msg.UINetworksHint))
		r.networks.Hide()
		r.mode = widget.NewRadioGroup([]string{allText, onlyText}, func(v string) {
			if v == onlyText {
				r.networks.Show()
			} else {
				r.networks.Hide()
			}
		})
		r.mode.SetSelected(allText)
		r.keepalive = widget.NewEntry()
		r.keepalive.SetPlaceHolder(u.t(msg.UIServerKeepalive))
		r.psk = NewSecretField()
		r.box = container.NewVBox(
			label(u.t(msg.UIServerEndpoint)), r.endpoint, r.errText("endpoint"),
			label(u.t(msg.UIServerPublicKey)), r.pubkey, r.errText("publickey"),
			r.mode, r.networks, r.errText("networks"))
		return r
	}
	first := newRow()
	rows := []*peerRow{first}

	name := widget.NewEntry()
	name.SetPlaceHolder(u.t(msg.UITunnelName))
	addr := widget.NewEntry()
	addr.SetPlaceHolder(u.t(msg.UITunnelIPHint))
	addr.SetText(s.addrs[0])
	addrErr := rich("", nameAmber, sizeSmall, fyne.TextStyle{})

	var backupIP *widget.Entry
	backupErr := rich("", nameAmber, sizeSmall, fyne.TextStyle{})

	dns := widget.NewEntry()
	dns.SetPlaceHolder(u.t(msg.UIServerDNS))
	dnsErr := rich("", nameAmber, sizeSmall, fyne.TextStyle{})
	mtu := widget.NewEntry()
	mtu.SetPlaceHolder(u.t(msg.UIServerMTU))
	mtuErr := rich("", nameAmber, sizeSmall, fyne.TextStyle{})
	general := map[string]*widget.RichText{"address": addrErr, "dns": dnsErr, "mtu": mtuErr}

	// Per-peer advanced inputs live in the Advanced section, one block each.
	adv := container.NewVBox()
	advBlock := func(r *peerRow) fyne.CanvasObject {
		return container.NewVBox(
			label(u.t(msg.UIPresharedKey)), r.psk, r.errText("presharedkey"),
			r.keepalive, r.errText("keepalive"))
	}
	adv.Add(label(u.t(msg.UIServerDNS)))
	adv.Add(dns)
	adv.Add(dnsErr)
	adv.Add(mtu)
	adv.Add(mtuErr)
	adv.Add(advBlock(first))

	servers := container.NewVBox(first.box)
	var second *widget.Button
	second = widget.NewButton(u.t(msg.UIAddSecondServer), func() {
		r := newRow()
		rows = append(rows, r)
		servers.Add(container.NewVBox(widget.NewSeparator(), r.box))
		adv.Add(widget.NewSeparator())
		adv.Add(advBlock(r))
		second.Hide()
		servers.Refresh()
		adv.Refresh()
	})
	adv.Add(second)
	accordion := widget.NewAccordion(widget.NewAccordionItem(u.t(msg.UIAdvanced), adv))

	content := []fyne.CanvasObject{h2(u.t(msg.UIServerFormTitle)),
		label(u.t(msg.UITunnelName)), name,
		label(u.t(msg.UITunnelIPLabel)), addr, addrErr}
	if len(s.keys) > 1 {
		backupIP = widget.NewEntry()
		backupIP.SetPlaceHolder(u.t(msg.UITunnelIPHint))
		backupIP.SetText(s.addrs[1])
		content = append(content, label(u.t(msg.UIBackupAddressLabel)), backupIP, backupErr)
	}
	content = append(content, servers, accordion)
	errText := rich("", nameAmber, sizeSmall, fyne.TextStyle{})

	// wipe erases every preshared key field.
	wipe := func() {
		for _, r := range rows {
			r.psk.Wipe()
		}
	}
	var pop *widget.PopUp
	hide := func() { wipe(); pop.Hide() }

	clearErrors := func() {
		setErr(errText, "")
		setErr(backupErr, "")
		for _, t := range general {
			setErr(t, "")
		}
		for _, r := range rows {
			for _, t := range r.errs {
				setErr(t, "")
			}
		}
	}
	// fail shows err under the field it names. Only the message for the
	// field is shown, never a value: the field may be the preshared key.
	fail := func(err error) {
		var fe *desktop.FieldError
		if !errors.As(err, &fe) {
			setErr(errText, u.translate(err))
			return
		}
		peer, key := fieldKey(fe.Field)
		id, known := serverFormErrors[key]
		if !known {
			setErr(errText, u.translate(fe.Err))
			return
		}
		text := u.t(id)
		switch {
		case peer >= 0 && peer < len(rows):
			setErr(rows[peer].errs[key], text)
			if key == "presharedkey" || key == "keepalive" {
				accordion.Open(0)
			}
		case general[key] != nil:
			setErr(general[key], text)
			if key != "address" {
				accordion.Open(0)
			}
		default:
			setErr(errText, text)
		}
	}

	add := widget.NewButton(u.t(msg.UIImportAdd), nil)
	add.Importance = widget.HighImportance
	add.OnTapped = func() {
		clearErrors()
		form := desktop.ServerForm{Address: addr.Text, DNS: strings.Split(dns.Text, ",")}
		if v := strings.TrimSpace(mtu.Text); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				setErr(mtuErr, u.t(msg.UIServerMTUInvalid))
				accordion.Open(0)
				return
			}
			form.MTU = n
		}
		var psks [][]byte
		wiped := false
		defer func() {
			wiped = true
			for _, k := range psks {
				clear(k)
			}
		}()
		for i, r := range rows {
			p := desktop.ServerPeer{
				Endpoint:   strings.TrimSpace(r.endpoint.Text),
				PublicKey:  strings.TrimSpace(r.pubkey.Text),
				AllTraffic: r.mode.Selected != onlyText,
				Networks:   strings.Split(r.networks.Text, ","),
			}
			if v := strings.TrimSpace(r.keepalive.Text); v != "" {
				n, err := strconv.Atoi(v)
				if err != nil {
					setErr(r.errs["keepalive"], u.t(msg.UIServerKeepaliveInvalid))
					accordion.Open(0)
					return
				}
				p.Keepalive = n
			}
			// Take empties the field; the bytes go back on failure so the
			// user need not retype them, and are wiped on every path.
			psk := rows[i].psk.Take()
			psks = append(psks, psk)
			p.PresharedKey = string(psk)
			form.Peers = append(form.Peers, p)
		}
		restore := func() {
			if wiped {
				return // an error that arrives after the form call returned
			}
			for i, k := range psks {
				for _, r := range string(k) {
					rows[i].psk.TypedRune(r)
				}
			}
		}
		conf, err := form.Conf()
		if err != nil {
			restore()
			fail(err)
			return
		}
		tunnel := strings.TrimSpace(name.Text)
		if tunnel == "" {
			host := form.Peers[0].Endpoint
			if h, _, ok := strings.Cut(host, ":"); ok {
				host = h
			}
			if tunnel = tunnelNameFrom(host + ".conf"); tunnel == "" {
				tunnel = "vpn"
			}
		}
		u.addTunnel(conf, tunnel, backupIP, add, pop.Hide,
			func(m string) { restore(); setErr(backupErr, m) }, func(m string) { restore(); setErr(errText, m) })
	}
	cancel := widget.NewButton(u.t(msg.UICancel), hide)
	content = append(content, errText, container.NewHBox(layout.NewSpacer(), cancel, add))

	// The Advanced section grows the form, so it always scrolls inside a
	// fixed box instead of being measured once like a short modal.
	const width = 520
	body := container.NewVScroll(container.New(layout.NewCustomPaddedLayout(16, 16, 16, 16), container.NewVBox(content...)))
	height := float32(620)
	if limit := u.win.Canvas().Size().Height - 48; limit > 0 && limit < height {
		height = limit
	}
	pop = widget.NewModalPopUp(container.NewGridWrap(fyne.NewSize(width, height), body), u.win.Canvas())
	pop.Show()
}
