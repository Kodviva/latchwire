package keyref

import "testing"

func TestRefRoundTrip(t *testing.T) {
	r, err := Parse("piv://40727512/82")
	if err != nil {
		t.Fatal(err)
	}
	if r.Serial != 40727512 || r.Slot != 0x82 {
		t.Fatalf("got %+v", r)
	}
	if got := r.String(); got != "piv://40727512/82" {
		t.Fatalf("String() = %q", got)
	}
	// Range edges.
	for _, s := range []string{"piv://1/82", "piv://4294967295/95"} {
		r, err := Parse(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if r.String() != s {
			t.Fatalf("round trip %s -> %s", s, r.String())
		}
	}
}

func TestRefRejectsBadSlot(t *testing.T) {
	for _, s := range []string{"piv://1/9a", "piv://1/96", "piv://1/81", "pkcs11://x"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", s)
		}
	}
}

func TestRefRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"PIV://1/82",          // uppercase scheme
		"piv:/1/82",           // bad separator
		"piv://",              // nothing
		"piv://1",             // no slot
		"piv://1/",            // empty slot
		"piv:///82",           // empty serial
		"piv://1/82/",         // trailing part
		"piv://1/82/x",        // extra part
		"piv://1/8",           // short slot
		"piv://1/082",         // long slot
		"piv://1/8A",          // uppercase hex
		"piv://1/0x82",        // prefixed hex
		"piv://1/+2",          // sign in slot
		"piv://0/82",          // serial zero
		"piv://-1/82",         // negative serial
		"piv://+1/82",         // signed serial
		"piv://0x10/82",       // hex serial
		"piv://abc/82",        // non-decimal serial
		"piv://1_0/82",        // underscore
		"piv://01/82",         // non-canonical leading zero
		"piv://4294967296/82", // uint32 overflow
		"piv://99999999999999999999/82",
		" piv://1/82",
		"piv://1/82 ",
	}
	for _, s := range bad {
		if r, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) = %+v, want error", s, r)
		}
	}
}
