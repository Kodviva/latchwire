package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/keyref"
)

// Fixed test keys: 32 bytes each, not secrets.
var (
	pubA = bytes32(0x11)
	pubB = bytes32(0x22)
	psk  = bytes32(0x33)
	idA  = bytes32(0x55) // identity (card) public keys
	idB  = bytes32(0x66)
)

// idKey is the identity PublicKey line for idA.
var idKey = "PublicKey = " + b64(idA) + "\n"

func bytes32(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func b64(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }
func hx(k [32]byte) string  { return hex.EncodeToString(k[:]) }

func parse(t *testing.T, conf string) (*Tunnel, error) {
	t.Helper()
	return Parse("office", strings.NewReader(conf))
}

func mustParse(t *testing.T, conf string) *Tunnel {
	t.Helper()
	tun, err := parse(t, conf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tun
}

func TestParseShorthand(t *testing.T) {
	tun := mustParse(t, `
[Interface]
KeyRef = piv://40727512/82
PublicKey = `+b64(idA)+`
Address = 10.0.0.2/32, fd00::2/128
ListenPort = 51820
MTU = 1380
DNS = 10.0.0.1, fd00::1

[Peer]
PublicKey = `+b64(pubA)+`
PresharedKey = `+b64(psk)+`
Endpoint = 192.0.2.1:51820
AllowedIPs = 10.0.0.0/24, 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`)
	if tun.Name != "office" || tun.ListenPort != 51820 || tun.MTU != 1380 {
		t.Fatalf("tunnel fields: %+v", tun)
	}
	if len(tun.Identities) != 1 {
		t.Fatalf("identities = %d", len(tun.Identities))
	}
	id := tun.Identities[0]
	if id.Ref != (keyref.Ref{Serial: 40727512, Slot: 0x82}) {
		t.Fatalf("ref = %v", id.Ref)
	}
	wantAddr := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("fd00::2/128")}
	if !samePrefixes(id.Addresses, wantAddr) {
		t.Fatalf("addresses = %v", id.Addresses)
	}
	if len(tun.DNS) != 2 || tun.DNS[0] != netip.MustParseAddr("10.0.0.1") || tun.DNS[1] != netip.MustParseAddr("fd00::1") {
		t.Fatalf("dns = %v", tun.DNS)
	}
	if len(tun.Peers) != 1 {
		t.Fatalf("peers = %d", len(tun.Peers))
	}
	p := tun.Peers[0]
	if p.PublicKey != pubA || p.PresharedKey == nil || *p.PresharedKey != psk {
		t.Fatalf("keys wrong: %+v", p)
	}
	if p.Endpoint != "192.0.2.1:51820" || p.PersistentKeepalive != 25 {
		t.Fatalf("peer: %+v", p)
	}
	if len(p.AllowedIPs) != 3 || p.AllowedIPs[2] != netip.MustParsePrefix("::/0") {
		t.Fatalf("allowed = %v", p.AllowedIPs)
	}
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseIdentities(t *testing.T) {
	tun := mustParse(t, `
[Interface]
ListenPort = 1234

[Identity]
KeyRef = piv://111/83
PublicKey = `+b64(idA)+`
Address = 10.0.0.2/32

[Identity]
KeyRef = piv://222/82
PublicKey = `+b64(idB)+`
Address = 10.0.1.2/32, fd00::2/128

[Peer]
PublicKey = `+b64(pubA)+`
AllowedIPs = 0.0.0.0/0
`)
	if len(tun.Identities) != 2 {
		t.Fatalf("identities = %d", len(tun.Identities))
	}
	if tun.Identities[0].Ref.String() != "piv://111/83" || tun.Identities[1].Ref.String() != "piv://222/82" {
		t.Fatalf("order lost: %v %v", tun.Identities[0].Ref, tun.Identities[1].Ref)
	}
	if len(tun.Identities[0].Addresses) != 1 || len(tun.Identities[1].Addresses) != 2 {
		t.Fatalf("addresses: %+v", tun.Identities)
	}
	if tun.Peers[0].PresharedKey != nil {
		t.Fatal("psk should be nil")
	}
}

func TestParseRejectsPrivateKey(t *testing.T) {
	pk := b64(bytes32(0x44))
	cases := map[string]string{
		"interface": "[Interface]\nPrivateKey = " + pk + "\nKeyRef = piv://1/82\n",
		"identity":  "[Identity]\nKeyRef = piv://1/82\nPrivateKey = " + pk + "\n",
		"peer":      "[Interface]\nKeyRef = piv://1/82\n[Peer]\nPrivateKey = " + pk + "\n",
		"lowercase": "[interface]\nkeyref = piv://1/82\nprivatekey=" + pk + "\n",
		"empty":     "[Interface]\nKeyRef = piv://1/82\nPrivateKey =\n",
		"first":     "[Interface]\nPrivateKey = " + pk + "\n",
	}
	for name, conf := range cases {
		_, err := parse(t, conf)
		if !errors.Is(err, ErrPrivateKeyNotAllowed) {
			t.Errorf("%s: err = %v, want ErrPrivateKeyNotAllowed", name, err)
		}
		if err != nil && strings.Contains(err.Error(), pk) {
			t.Errorf("%s: error leaks key value: %v", name, err)
		}
	}
}

func TestParseRejectsNoIdentity(t *testing.T) {
	for name, conf := range map[string]string{
		"no keyref": "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + b64(pubA) + "\n",
		"empty":     "",
		"comments":  "# nothing\n\n",
	} {
		if _, err := parse(t, conf); !errors.Is(err, ErrNoIdentity) {
			t.Errorf("%s: err = %v, want ErrNoIdentity", name, err)
		}
	}
}

func TestParseRejectsHooks(t *testing.T) {
	for _, key := range []string{"PreUp", "PostUp", "PreDown", "PostDown", "Table", "SaveConfig", "FwMark"} {
		for _, k := range []string{key, strings.ToLower(key)} {
			conf := "[Interface]\nKeyRef = piv://1/82\n" + k + " = rm -rf /\n"
			_, err := parse(t, conf)
			if err == nil {
				t.Errorf("%s: accepted", k)
				continue
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("%s: error does not name key: %v", k, err)
			}
			if errors.Is(err, ErrPrivateKeyNotAllowed) || errors.Is(err, ErrNoIdentity) {
				t.Errorf("%s: wrong sentinel: %v", k, err)
			}
		}
	}
	// Hooks must also be refused in other sections.
	if _, err := parse(t, "[Identity]\nKeyRef = piv://1/82\nPostUp = true\n"); err == nil {
		t.Error("PostUp in [Identity] accepted")
	}
	if _, err := parse(t, "[Interface]\nKeyRef = piv://1/82\n"+idKey+"[Peer]\nPublicKey = "+b64(pubA)+"\nPostUp = true\n"); err == nil {
		t.Error("PostUp in [Peer] accepted")
	}
}

func TestParseRobustness(t *testing.T) {
	tun := mustParse(t, "\xef\xbb\xbf# header comment\r\n"+
		"\r\n"+
		"[interface]   # trailing\r\n"+
		"  keyref=piv://7/95   \r\n"+
		"  publickey = "+b64(idA)+"\r\n"+
		"ADDRESS =10.9.0.2/24 ,  fd09::2/64\r\n"+
		"Address = 10.9.1.2/24\r\n"+
		"\r\n"+
		"[ PEER ]\r\n"+
		"publickey = "+b64(pubB)+" # pk\r\n"+
		"allowedips = 10.9.0.0/24 ,fd09::/64,   192.168.0.1\r\n"+
		"allowedips = 172.16.0.0/12\r\n"+
		"endpoint = [2001:db8::1]:51820\r\n"+
		"persistentkeepalive = off\r\n")
	if got := len(tun.Identities[0].Addresses); got != 3 {
		t.Fatalf("addresses = %v", tun.Identities[0].Addresses)
	}
	p := tun.Peers[0]
	if p.PublicKey != pubB || p.Endpoint != "[2001:db8::1]:51820" || p.PersistentKeepalive != 0 {
		t.Fatalf("peer: %+v", p)
	}
	want := []string{"10.9.0.0/24", "fd09::/64", "192.168.0.1/32", "172.16.0.0/12"}
	if len(p.AllowedIPs) != len(want) {
		t.Fatalf("allowed = %v", p.AllowedIPs)
	}
	for i, w := range want {
		if p.AllowedIPs[i] != netip.MustParsePrefix(w) {
			t.Errorf("allowed[%d] = %v, want %s", i, p.AllowedIPs[i], w)
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	id := "[Interface]\nKeyRef = piv://1/82\n" + idKey
	peer := "[Peer]\nPublicKey = " + b64(pubA) + "\n"
	cases := map[string]string{
		"unknown section":            "[Foo]\n",
		"key before section":         "KeyRef = piv://1/82\n",
		"no equals":                  id + "Address\n",
		"unknown key":                id + "Bogus = 1\n",
		"bad keyref":                 "[Interface]\nKeyRef = piv://1/9a\n",
		"bad address":                id + "Address = 10.0.0.2/33\n",
		"bad port":                   id + "ListenPort = 70000\n",
		"bad mtu":                    id + "MTU = abc\n",
		"bad dns":                    id + "DNS = notanip!\n",
		"dup listen port":            id + "ListenPort = 1\nListenPort = 2\n",
		"dup keyref":                 id + "KeyRef = piv://2/82\n",
		"shorthand+identity":         id + "[Identity]\nKeyRef = piv://2/82\n",
		"interface address+identity": "[Interface]\nAddress = 10.0.0.2/32\n[Identity]\nKeyRef = piv://2/82\n",
		"identity bad key":           "[Identity]\nKeyRef = piv://1/82\nListenPort = 1\n",
		"peer no pubkey":             id + "[Peer]\nAllowedIPs = 0.0.0.0/0\n",
		"peer bad pubkey":            id + "[Peer]\nPublicKey = abc\n",
		"peer short pubkey":          id + "[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"peer bad psk":               id + peer + "PresharedKey = zzz\n",
		"peer bad endpoint":          id + peer + "Endpoint = 1.2.3.4\n",
		"peer endpoint port":         id + peer + "Endpoint = 1.2.3.4:0\n",
		"peer bad allowed":           id + peer + "AllowedIPs = 1.2.3.4/40\n",
		"peer bad keepalive":         id + peer + "PersistentKeepalive = 70000\n",
		"peer dup":                   id + peer + peer,
		"interface in peer":          id + peer + "ListenPort = 5\n",
		"two interfaces":             id + id,
	}
	for name, conf := range cases {
		if _, err := parse(t, conf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUAPINeverContainsPrivateKey(t *testing.T) {
	tun := mustParse(t, `
[Interface]
KeyRef = piv://40727512/82
PublicKey = `+b64(idA)+`
Address = 10.0.0.2/32
ListenPort = 51820

[Peer]
PublicKey = `+b64(pubA)+`
PresharedKey = `+b64(psk)+`
Endpoint = 192.0.2.1:51820
AllowedIPs = 10.0.0.0/24, fd00::/64
PersistentKeepalive = 25

[Peer]
PublicKey = `+b64(pubB)+`
AllowedIPs = 0.0.0.0/0
`)
	u := tun.UAPI()
	if strings.Contains(u, "private_key") {
		t.Fatalf("UAPI contains private_key:\n%s", u)
	}
	want := "listen_port=51820\n" +
		"public_key=" + hx(pubA) + "\n" +
		"preshared_key=" + hx(psk) + "\n" +
		"endpoint=192.0.2.1:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.0.0.0/24\n" +
		"allowed_ip=fd00::/64\n" +
		"public_key=" + hx(pubB) + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n"
	if u != want {
		t.Fatalf("UAPI mismatch\n got:\n%s\nwant:\n%s", u, want)
	}
	if strings.Contains(u, b64(pubA)) {
		t.Fatal("UAPI contains base64 key")
	}
}

func TestUAPIOmitsZeroListenPort(t *testing.T) {
	tun := mustParse(t, "[Interface]\nKeyRef = piv://1/82\n"+idKey+"[Peer]\nPublicKey = "+b64(pubA)+"\n")
	if strings.Contains(tun.UAPI(), "listen_port") {
		t.Fatalf("unexpected listen_port:\n%s", tun.UAPI())
	}
}

func TestParseDNSSearchDomains(t *testing.T) {
	tun := mustParse(t, "[Interface]\nKeyRef = piv://1/82\n"+idKey+
		"DNS = 10.0.0.1, corp.example, fd00::1\n"+
		"DNS = Lab-1.internal.example.com\n")
	if len(tun.DNS) != 2 || tun.DNS[0] != netip.MustParseAddr("10.0.0.1") || tun.DNS[1] != netip.MustParseAddr("fd00::1") {
		t.Fatalf("DNS = %v", tun.DNS)
	}
	if len(tun.DNSSearch) != 2 || tun.DNSSearch[0] != "corp.example" || tun.DNSSearch[1] != "Lab-1.internal.example.com" {
		t.Fatalf("DNSSearch = %v", tun.DNSSearch)
	}

	for _, bad := range []string{
		"notanip!", "-bad.example", "bad-.example", "a..b", ".example", "a b",
		"fd00::zz", "10.0.0.256", "exa_mple.com", "1.2.3.4.5",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 127) + "a",
	} {
		_, err := parse(t, "[Interface]\nKeyRef = piv://1/82\n"+idKey+"DNS = 10.0.0.1, "+bad+"\n")
		if err == nil {
			t.Errorf("DNS item %q accepted", bad)
		}
	}
}

func TestParseRequiresIdentityPublicKey(t *testing.T) {
	peer := "[Peer]\nPublicKey = " + b64(pubA) + "\n"
	for name, conf := range map[string]string{
		"shorthand": "[Interface]\nKeyRef = piv://1/82\n" + peer,
		"identity":  "[Identity]\nKeyRef = piv://1/82\n" + peer,
		"second identity": "[Identity]\nKeyRef = piv://1/82\n" + idKey +
			"[Identity]\nKeyRef = piv://2/82\n" + peer,
	} {
		_, err := parse(t, conf)
		if err == nil || !strings.Contains(err.Error(), "PublicKey") {
			t.Errorf("%s: err = %v, want missing PublicKey", name, err)
		}
	}
	tun := mustParse(t, "[Identity]\nKeyRef = piv://1/82\n"+idKey+
		"[Identity]\nKeyRef = piv://2/82\nPublicKey = "+b64(idB)+"\n"+peer)
	if tun.Identities[0].PublicKey != idA || tun.Identities[1].PublicKey != idB {
		t.Fatalf("identity keys %x %x", tun.Identities[0].PublicKey, tun.Identities[1].PublicKey)
	}
	tun = mustParse(t, "[Interface]\nKeyRef = piv://1/82\n"+idKey+peer)
	if tun.Identities[0].PublicKey != idA {
		t.Fatalf("shorthand identity key %x", tun.Identities[0].PublicKey)
	}
}

func TestParseRejectsBadIdentityPublicKey(t *testing.T) {
	for name, conf := range map[string]string{
		"not base64":    "[Interface]\nKeyRef = piv://1/82\nPublicKey = zz!\n",
		"short":         "[Interface]\nKeyRef = piv://1/82\nPublicKey = " + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"all zero":      "[Interface]\nKeyRef = piv://1/82\nPublicKey = " + b64([32]byte{}) + "\n",
		"identity":      "[Identity]\nKeyRef = piv://1/82\nPublicKey = abc\n",
		"duplicate":     "[Interface]\nKeyRef = piv://1/82\n" + idKey + idKey,
		"without ref":   "[Interface]\n" + idKey + "[Identity]\nKeyRef = piv://1/82\n" + idKey,
		"no ref at all": "[Interface]\n" + idKey,
	} {
		if _, err := parse(t, conf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
