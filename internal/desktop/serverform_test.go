package desktop

import (
	"errors"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/config"
)

// Test values only: 32 bytes of 0x02 and 0x03.
const (
	serverKeyB = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	testPSK    = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
)

func onePeer(p ServerPeer) ServerForm {
	return ServerForm{Address: "10.8.0.2/32", Peers: []ServerPeer{p}}
}

func TestServerFormSinglePeerAllTraffic(t *testing.T) {
	f := ServerForm{Address: "10.8.0.2/32", Peers: []ServerPeer{{Endpoint: "vpn.example.com:51820", PublicKey: srvPub, AllTraffic: true}}}
	text, err := f.Conf()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.8.0.2/32", "Endpoint = vpn.example.com:51820", "AllowedIPs = 0.0.0.0/0, ::/0"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "privatekey") {
		t.Fatal("PrivateKey written")
	}
	if _, err := Bind(text, keyA, nil); err != nil {
		t.Fatal(err)
	}
}

func TestServerFormTwoPeersWithPSK(t *testing.T) {
	f := ServerForm{
		Address: "10.20.20.10/32, 10.77.50.10/32",
		DNS:     []string{"10.20.20.1", "corp.example.com"},
		MTU:     1380,
		Peers: []ServerPeer{
			{Endpoint: "195.26.87.141:51820", PublicKey: srvPub, Networks: []string{"10.10.10.0/24", "10.20.20.0/24"}},
			{Endpoint: "185.111.244.91:51820", PublicKey: serverKeyB, PresharedKey: testPSK, Networks: []string{"10.77.0.0/16", "192.168.1.5"}, Keepalive: 25},
		},
	}
	text, err := f.Conf()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(text, "[Peer]") != 2 || strings.Count(text, "PresharedKey") != 1 || !strings.Contains(text, "PersistentKeepalive = 25") {
		t.Fatal(text)
	}
	out, err := Bind(text, keyA, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse("t", strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != 1380 || len(cfg.DNS) != 1 || len(cfg.DNSSearch) != 1 || len(cfg.Peers) != 2 || len(cfg.Identities[0].Addresses) != 2 {
		t.Fatalf("%+v", cfg)
	}
}

func TestServerFormFieldErrors(t *testing.T) {
	ok := ServerPeer{Endpoint: "h:1", PublicKey: srvPub, AllTraffic: true}
	with := func(f func(*ServerPeer)) ServerForm { p := ok; f(&p); return onePeer(p) }
	for field, f := range map[string]ServerForm{
		"address":               {Address: "nope", Peers: []ServerPeer{ok}},
		"address ":              {Address: "", Peers: []ServerPeer{ok}},
		"dns":                   {Address: "10.8.0.2/32", DNS: []string{"bad host!"}, Peers: []ServerPeer{ok}},
		"mtu":                   {Address: "10.8.0.2/32", MTU: 100, Peers: []ServerPeer{ok}},
		"peers":                 {Address: "10.8.0.2/32"},
		"peers[0].endpoint":     with(func(p *ServerPeer) { p.Endpoint = "no-port" }),
		"peers[0].endpoint ":    with(func(p *ServerPeer) { p.Endpoint = "h:70000" }),
		"peers[0].endpoint  ":   with(func(p *ServerPeer) { p.Endpoint = "h:1 # x" }),
		"peers[0].publickey":    with(func(p *ServerPeer) { p.PublicKey = "short" }),
		"peers[0].presharedkey": with(func(p *ServerPeer) { p.PresharedKey = "short" }),
		"peers[0].networks":     with(func(p *ServerPeer) { p.AllTraffic = false }),
		"peers[0].networks ":    with(func(p *ServerPeer) { p.AllTraffic = false; p.Networks = []string{"x/99"} }),
		"peers[0].keepalive":    with(func(p *ServerPeer) { p.Keepalive = 70000 }),
	} {
		_, err := f.Conf()
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != strings.TrimSpace(field) {
			t.Errorf("%s: got %v", field, err)
		}
	}
}

func TestServerFormErrorHidesPSK(t *testing.T) {
	for _, psk := range []string{"not-base64-" + testPSK, testPSK + "AA"} {
		f := onePeer(ServerPeer{Endpoint: "h:1", PublicKey: srvPub, PresharedKey: psk, AllTraffic: true})
		_, err := f.Conf()
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "peers[0].presharedkey" {
			t.Fatalf("err %v", err)
		}
		if strings.Contains(err.Error(), testPSK) || strings.Contains(err.Error(), psk) {
			t.Fatalf("secret in error: %v", err)
		}
	}
}
