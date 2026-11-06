package desktop

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/config"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// 32 zero-ish bytes that are not secret: test values only.
const (
	fakePriv = "cFJ1c3RPbmx5QVRlc3RWYWx1ZU5vdEFSZWFsS2V5MDA="
	srvPub   = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
)

var (
	keyA = Key{Ref: keyref.Ref{Serial: 40727512, Slot: 0x82}, Public: [32]byte{1, 2}}
	keyB = Key{Ref: keyref.Ref{Serial: 40727513, Slot: 0x82}, Public: [32]byte{3, 4}}
)

func serverConf(extra string) string {
	return "# office\n[Interface]\nPrivateKey = " + fakePriv + "\nAddress = 10.8.0.2/32\nDNS = 10.8.0.1\n" + extra +
		"\n[Peer]\nPublicKey = " + srvPub + "\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
}

func TestSanitizeDropsPrivateKey(t *testing.T) {
	in := serverConf("# PrivateKey = " + fakePriv + "\n; privatekey=" + fakePriv + "\n")
	text, had := Sanitize([]byte(in))
	if !had {
		t.Fatal("not reported")
	}
	if strings.Contains(strings.ToLower(text), "privatekey") || strings.Contains(text, fakePriv) {
		t.Fatalf("a private key survived:\n%s", text)
	}
}

func TestSanitizeDoesNotKeepInput(t *testing.T) {
	data := []byte(serverConf(""))
	text, _ := Sanitize(data)
	clear(data)
	if strings.Contains(text, "\x00") || !strings.Contains(text, "Endpoint") {
		t.Fatal("the result aliases the input")
	}
}

func TestBindOneCard(t *testing.T) {
	text, _ := Sanitize([]byte(serverConf("")))
	out, err := Bind(text, keyA, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse("t", strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Identities) != 1 || cfg.Identities[0].Ref != keyA.Ref || cfg.Identities[0].PublicKey != keyA.Public {
		t.Fatalf("%+v", cfg.Identities)
	}
	if len(cfg.Identities[0].Addresses) != 1 || len(cfg.DNS) != 1 || len(cfg.Peers) != 1 {
		t.Fatalf("%+v", cfg)
	}
}

func TestCRLFAndNoPrivateKey(t *testing.T) {
	in := "[Interface]\r\nAddress = 10.8.0.2/32\r\n\r\n[Peer]\r\nPublicKey = " + srvPub + "\r\nAllowedIPs = 10.8.0.0/24\r\n"
	text, had := Sanitize([]byte(in))
	if had {
		t.Fatal("false alarm")
	}
	if _, err := Bind(text, keyA, nil); err != nil {
		t.Fatal(err)
	}
}

func TestBindTwoCards(t *testing.T) {
	text, _ := Sanitize([]byte(serverConf("")))
	out, err := Bind(text, keyA, &Backup{Key: keyB, Address: netip.MustParseAddr("10.8.0.3")})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse("t", strings.NewReader(out))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(cfg.Identities) != 2 {
		t.Fatalf("%+v", cfg.Identities)
	}
	if cfg.Identities[0].Ref != keyA.Ref || cfg.Identities[0].Addresses[0].String() != "10.8.0.2/32" {
		t.Fatalf("%+v", cfg.Identities[0])
	}
	if cfg.Identities[1].Ref != keyB.Ref || cfg.Identities[1].Addresses[0].String() != "10.8.0.3/32" {
		t.Fatalf("%+v", cfg.Identities[1])
	}
	if len(cfg.DNS) != 1 {
		t.Fatal("DNS lost")
	}
}

func TestBindRejectsHooks(t *testing.T) {
	text, _ := Sanitize([]byte(serverConf("PostUp = iptables -A\n")))
	if _, err := Bind(text, keyA, nil); err == nil || !strings.Contains(err.Error(), "PostUp") {
		t.Fatal(err)
	}
}

func TestBindRefusesAnUnsanitizedKey(t *testing.T) {
	if _, err := Bind(serverConf(""), keyA, nil); err == nil {
		t.Fatal("accepted a PrivateKey line")
	}
}

func TestBindRejectsRubbish(t *testing.T) {
	if _, err := Bind("hello", keyA, nil); err == nil {
		t.Fatal("accepted")
	}
	if _, err := Bind("[Peer]\nPublicKey = "+srvPub+"\nAllowedIPs = 10.0.0.0/8\n", keyA, nil); err == nil {
		t.Fatal("accepted a file without [Interface]")
	}
}

func TestPeerBlockMatchesCLI(t *testing.T) {
	got := PeerBlock("en", keyA, netip.MustParseAddr("10.8.0.2"))
	want := "[Peer]\nPublicKey = " + keyA.PublicBase64() + "\nAllowedIPs = 10.8.0.2/32"
	if got != want {
		t.Fatal(got)
	}
	got = PeerBlock("en", keyA, netip.MustParseAddr("fd00::2"))
	if !strings.HasSuffix(got, "AllowedIPs = fd00::2/128") {
		t.Fatal(got)
	}
	got = PeerBlock("en", keyA, netip.Addr{})
	if !strings.HasSuffix(got, "AllowedIPs = "+msg.KeygenTunnelIP+"/32") {
		t.Fatal(got)
	}
	if got = PeerBlock("tr", keyA, netip.Addr{}); !strings.Contains(got, "<tünel IP'si>") {
		t.Fatal(got)
	}
}
