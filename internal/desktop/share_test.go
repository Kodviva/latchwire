package desktop

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestAdminMessageHasKeysOnly(t *testing.T) {
	_, body := AdminMessage("en", []Key{keyA}, []netip.Addr{netip.MustParseAddr("10.8.0.2")})
	if !strings.Contains(body, keyA.PublicBase64()) || !strings.Contains(body, "10.8.0.2/32") {
		t.Fatal(body)
	}
	for _, bad := range []string{"privatekey", "piv://", keyA.Ref.String()} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(bad)) {
			t.Fatalf("leaks %q:\n%s", bad, body)
		}
	}
	for _, want := range []string{"OPNsense", "pfSense", "MikroTik", "Linux", "tunnel IP"} {
		if !strings.Contains(body, want) {
			t.Fatalf("no %q:\n%s", want, body)
		}
	}
}

func TestAdminMessageTwoCards(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.3")}
	_, body := AdminMessage("en", []Key{keyA, keyB}, addrs)
	if strings.Count(body, "\n[Peer]\n") != 2 || !strings.Contains(body, keyB.PublicBase64()) || !strings.Contains(body, "10.8.0.3/32") {
		t.Fatal(body)
	}
}

func TestAdminMessageNoAddress(t *testing.T) {
	_, body := AdminMessage("en", []Key{keyA}, []netip.Addr{{}})
	if !strings.Contains(body, "your choice") {
		t.Fatal(body)
	}
	_, tr := AdminMessage("tr", []Key{keyA}, nil)
	if !strings.Contains(tr, "sizin seçeceğiniz") {
		t.Fatal(tr)
	}
}

func TestMailtoEncodes(t *testing.T) {
	subject, body := "a b+c", "line1\nline2 +x&y=z\r\n[Peer]\nKey = ab+/cd=="
	u := MailtoURL(subject, body)
	s := u.String()
	if !strings.HasPrefix(s, "mailto:?") || strings.ContainsAny(s, " \n\r+") {
		t.Fatalf("bad encoding: %q", s)
	}
	back, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	q := back.Query()
	if q.Get("subject") != subject || q.Get("body") != body {
		t.Fatalf("round trip: %q %q", q.Get("subject"), q.Get("body"))
	}
}
