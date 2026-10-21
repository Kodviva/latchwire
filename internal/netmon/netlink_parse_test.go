package netmon

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"
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

func ifname(name string) []byte { return rtattr(3, append([]byte(name), 0)) }

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
	want := []nlChange{{Index: 7, Link: true}, {Index: 3}, {Index: 9}, {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseNetlinkLinkName(t *testing.T) {
	// A deleted link still names itself in IFLA_IFNAME.
	del := nlmsg(nlRTMDelLink, append(ifinfo(7), ifname("wg0")...))
	got := parseNetlink(del)
	want := []nlChange{{Index: 7, Name: "wg0", Link: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseNetlinkMalformed(t *testing.T) {
	good := nlmsg(nlRTMNewLink, ifinfo(7))
	unnamed := nlChange{}
	for name, tc := range map[string]struct {
		buf  []byte
		want []nlChange
	}{
		"short header":        {good[:10], []nlChange{unnamed}},
		"payload cut":         {good[:20], []nlChange{unnamed}},
		"trailing junk":       {append(append([]byte{}, good...), 1, 2, 3), []nlChange{{Index: 7, Link: true}, unnamed}},
		"empty":               {nil, nil},
		"bad length":          {func() []byte { b := make([]byte, 16); binary.NativeEndian.PutUint32(b, 4); return b }(), []nlChange{unnamed}},
		"short link message":  {nlmsg(nlRTMNewLink, []byte{0, 0}), []nlChange{{Link: true}}},
		"bad attr length":     {nlmsg(nlRTMNewRoute, rtmsg(254, []byte{2, 0, 4, 0})), []nlChange{unnamed}},
		"huge attr length":    {nlmsg(nlRTMNewRoute, rtmsg(254, []byte{0xff, 0xff, 4, 0, 1, 2})), []nlChange{unnamed}},
		"unterminated ifname": {nlmsg(nlRTMNewLink, append(ifinfo(2), rtattr(3, []byte("eth"))...)), []nlChange{{Index: 2, Name: "eth", Link: true}}},
	} {
		if got := parseNetlink(tc.buf); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", name, got, tc.want)
		}
	}
}

func testCache(names map[int]string) *ifaceCache {
	return &ifaceCache{
		names: names,
		fresh: map[int]bool{},
		// The system knows no interface: everything has vanished.
		byIndex: func(int) (string, error) { return "", errors.New("no such interface") },
	}
}

// A tunnel being torn down is reported by index only; its name must come from
// the cache so Watch can ignore it.
func TestResolveVanishedOwnInterface(t *testing.T) {
	cache := testCache(map[int]string{7: "wg0", 2: "eth0"})
	for name, buf := range map[string][]byte{
		"link deleted, name in message": nlmsg(nlRTMDelLink, append(ifinfo(7), ifname("wg0")...)),
		"link deleted, name from cache": nlmsg(nlRTMDelLink, ifinfo(7)),
		"address deleted":               nlmsg(nlRTMDelAddr, ifaddr(7)),
		"route deleted":                 nlmsg(nlRTMDelRoute, rtmsg(254, rtattr(rtaOIF, u32(7)))),
	} {
		iface, ok := resolveChanges(parseNetlink(buf), cache)
		if !ok || iface != "wg0" {
			t.Errorf("%s: got (%q, %v), want (wg0, true)", name, iface, ok)
		}
	}

	// End to end through Watch: no Event for the teardown, one for eth0.
	src := newFakeSource()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ev := Watch(ctx, src, 50*time.Millisecond, func(n string) bool { return n == "wg0" })
	for _, buf := range [][]byte{
		nlmsg(nlRTMDelRoute, rtmsg(254, rtattr(rtaOIF, u32(7)))),
		nlmsg(nlRTMDelLink, ifinfo(7)),
	} {
		iface, _ := resolveChanges(parseNetlink(buf), cache)
		src.ch <- iface
	}
	select {
	case e := <-ev:
		t.Fatalf("Event for own interface teardown: %v", e)
	case <-time.After(300 * time.Millisecond):
	}
	iface, _ := resolveChanges(parseNetlink(nlmsg(nlRTMDelAddr, ifaddr(2))), cache)
	src.ch <- iface
	select {
	case <-ev:
	case <-time.After(2 * time.Second):
		t.Fatal("no Event for eth0")
	}
}

func TestIfaceCacheLookups(t *testing.T) {
	calls := map[int]int{}
	live := map[int]string{5: "utun5"}
	c := &ifaceCache{
		names: map[int]string{},
		fresh: map[int]bool{},
		byIndex: func(i int) (string, error) {
			calls[i]++
			if n, ok := live[i]; ok {
				return n, nil
			}
			return "", errors.New("gone")
		},
	}
	// Miss: asks the system once, then the cache answers.
	c.begin()
	if got := c.name(5, false); got != "utun5" {
		t.Fatalf("miss: %q", got)
	}
	c.begin()
	if got := c.name(5, false); got != "utun5" || calls[5] != 1 {
		t.Errorf("hit: %q after %d lookups", got, calls[5])
	}
	// Refresh within one datagram looks up once, and picks up a reused index.
	live[5] = "utun9"
	c.begin()
	if got := c.name(5, true); got != "utun9" {
		t.Errorf("refresh: %q", got)
	}
	c.name(5, true)
	c.name(5, true)
	if calls[5] != 2 {
		t.Errorf("lookups in one datagram: %d, want 2 in total", calls[5])
	}
	// Vanished: falls back to the last known name.
	delete(live, 5)
	c.begin()
	if got := c.name(5, true); got != "utun9" {
		t.Errorf("vanished: %q", got)
	}
	// Unknown and invalid indexes.
	c.begin()
	if got := c.name(77, false); got != "" {
		t.Errorf("unknown: %q", got)
	}
	if got := c.name(0, true); got != "" {
		t.Errorf("zero: %q", got)
	}
}
