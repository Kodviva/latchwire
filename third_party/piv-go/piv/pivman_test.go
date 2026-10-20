// Latchwire addition: unit tests for the patches. None of them touches a card.

package piv

import (
	"bytes"
	"testing"
)

func TestMetadataMarshalAllKeyLengths(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		key := bytes.Repeat([]byte{0xa5}, n)
		want := append([]byte{0x88, byte(n + 2), 0x89, byte(n)}, key...)

		m := Metadata{ManagementKey: &key}
		got, err := m.marshal()
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%d bytes: got %x, want %x", n, got, want)
		}

		var back Metadata
		if err := back.unmarshal(got); err != nil {
			t.Fatalf("%d bytes: unmarshal: %v", n, err)
		}
		if back.ManagementKey == nil || !bytes.Equal(*back.ManagementKey, key) {
			t.Fatalf("%d bytes: round trip lost the key", n)
		}

		// Raw path: existing metadata with another field and an old key.
		old := bytes.Repeat([]byte{0x11}, 24)
		raw := append([]byte{0x88, 0x1d, 0x8a, 0x01, 0x07, 0x89, 0x18}, old...)
		var existing Metadata
		if err := existing.unmarshal(raw); err != nil {
			t.Fatal(err)
		}
		existing.ManagementKey = &key
		got, err = existing.marshal()
		if err != nil {
			t.Fatalf("%d bytes raw: %v", n, err)
		}
		want = append([]byte{0x88, byte(n + 5), 0x8a, 0x01, 0x07, 0x89, byte(n)}, key...)
		if !bytes.Equal(got, want) {
			t.Fatalf("%d bytes raw: got %x, want %x", n, got, want)
		}
	}
}

func TestMetadataMarshalRejectsBadKeyLength(t *testing.T) {
	key := make([]byte, 20)
	m := Metadata{ManagementKey: &key}
	if _, err := m.marshal(); err == nil {
		t.Fatal("20-byte key accepted")
	}
}

func TestPIVManSetFlags(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5a}, 16)
	ts := []byte{0x00, 0x00, 0x12, 0x34}
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"absent", nil, []byte{0x80, 0x03, 0x81, 0x01, 0x02}},
		{"empty", []byte{}, []byte{0x80, 0x03, 0x81, 0x01, 0x02}},
		{"empty 0x80", []byte{0x80, 0x00}, []byte{0x80, 0x03, 0x81, 0x01, 0x02}},
		{"keeps puk-blocked bit", []byte{0x80, 0x03, 0x81, 0x01, 0x01}, []byte{0x80, 0x03, 0x81, 0x01, 0x03}},
		{"already set", []byte{0x80, 0x03, 0x81, 0x01, 0x02}, []byte{0x80, 0x03, 0x81, 0x01, 0x02}},
		{
			"keeps salt and timestamp",
			append(append(append([]byte{0x80, 0x18, 0x82, 0x10}, salt...), 0x83, 0x04), ts...),
			append(append(append([]byte{0x80, 0x1b, 0x81, 0x01, 0x02, 0x82, 0x10}, salt...), 0x83, 0x04), ts...),
		},
	}
	for _, tc := range tests {
		got, err := pivManSetFlags(tc.in, PIVManFlagMgmtKeyStored)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("%s: got %x, want %x", tc.name, got, tc.want)
		}
	}
}

func TestPIVManSetFlagsRejectsMalformed(t *testing.T) {
	for _, in := range [][]byte{
		{0x53, 0x00},                         // wrong outer tag
		{0x80, 0x05, 0x81, 0x01},             // short
		{0x80, 0x04, 0x81, 0x02, 0x01, 0x02}, // flags not one byte
		{0x80, 0x00, 0x00},                   // trailing data
	} {
		if _, err := pivManSetFlags(in, PIVManFlagMgmtKeyStored); err == nil {
			t.Fatalf("accepted %x", in)
		}
	}
}
