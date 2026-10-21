package netmon

import (
	"encoding/binary"
	"testing"
)

// nlmsg builds one netlink message: header, payload, padding to 4 bytes.
func nlmsg(typ uint16, payload []byte) []byte {
	n := 16 + len(payload)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint32(b[0:], uint32(n))
	binary.NativeEndian.PutUint16(b[4:], typ)
	copy(b[16:], payload)
	return b
}

func ifinfo(index int32) []byte {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint32(b[4:], uint32(index))
	return b
}

func ifaddr(index uint32) []byte {
	b := make([]byte, 8)
	binary.NativeEndian.PutUint32(b[4:], index)
	return b
}

// rtmsg builds an rtmsg in the given table with the given attributes.
func rtmsg(table byte, attrs ...[]byte) []byte {
	b := make([]byte, 12)
	b[4] = table
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func rtattr(typ uint16, data []byte) []byte {
	n := 4 + len(data)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b[0:], uint16(n))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func TestParseNetlink(t *testing.T) {
	var buf []byte
	buf = append(buf, nlmsg(nlRTMNewLink, ifinfo(7))...)
	buf = append(buf, nlmsg(nlRTMDelAddr, ifaddr(3))...)
	buf = append(buf, nlmsg(nlRTMNewRoute, rtmsg(254, rtattr(1, []byte{10, 0, 0, 0}), rtattr(rtaOIF, u32(9))))...)
	buf = append(buf, nlmsg(nlRTMDelRoute, rtmsg(254))...)                         // no OIF: unnamed change
	buf = append(buf, nlmsg(nlRTMNewRoute, rtmsg(255, rtattr(rtaOIF, u32(1))))...) // local table: noise
	buf = append(buf, nlmsg(2 /* NLMSG_ERROR */, make([]byte, 20))...)             // not a change
	buf = append(buf, nlmsg(3 /* NLMSG_DONE */, nil)...)                           // not a change
	buf = append(buf, nlmsg(30 /* RTM_NEWNEIGH-ish */, make([]byte, 12))...)       // not subscribed
	got := parseNetlink(buf)
	want := []int{7, 3, 9, 0}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseNetlinkTruncated(t *testing.T) {
	good := nlmsg(nlRTMNewLink, ifinfo(7))
	for _, buf := range [][]byte{
		nil,
		good[:10], // short header
		good[:20], // payload shorter than length says
		append(append([]byte{}, good...), 1, 2, 3), // trailing junk
	} {
		got := parseNetlink(buf) // must not panic
		if len(buf) == len(good)+3 && (len(got) != 1 || got[0] != 7) {
			t.Errorf("trailing junk: got %v", got)
		}
	}
	// A header claiming a length below 16 must not loop forever.
	bad := make([]byte, 16)
	binary.NativeEndian.PutUint32(bad, 4)
	parseNetlink(bad)
	// A link message too short for ifinfomsg is still a change, unnamed.
	short := nlmsg(nlRTMNewLink, []byte{0, 0})
	if got := parseNetlink(short); len(got) != 1 || got[0] != 0 {
		t.Errorf("short link message: %v", got)
	}
	// A route attribute with a bad length must not panic.
	parseNetlink(nlmsg(nlRTMNewRoute, rtmsg(254, []byte{2, 0, 4, 0})))
	parseNetlink(nlmsg(nlRTMNewRoute, rtmsg(254, []byte{0xff, 0xff, 4, 0, 1, 2})))
}
