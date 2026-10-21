package netmon

import "encoding/binary"

// Linux rtnetlink message types and attributes (linux/rtnetlink.h). They are
// spelled out here so the parser builds, and is tested, on every OS.
const (
	nlRTMNewLink  = 16
	nlRTMDelLink  = 17
	nlRTMNewAddr  = 20
	nlRTMDelAddr  = 21
	nlRTMNewRoute = 24
	nlRTMDelRoute = 25

	rtaOIF     = 4 // output interface index of a route
	iflaIfname = 3 // interface name of a link message

	nlHdrLen     = 16 // struct nlmsghdr
	ifInfoMsgLen = 16 // struct ifinfomsg
	ifAddrMsgLen = 8  // struct ifaddrmsg
	rtMsgLen     = 12 // struct rtmsg
	rtTableLocal = 255
	rtaHdrLen    = 4 // struct rtattr
)

// nlChange is one rtnetlink message that signals a network change.
type nlChange struct {
	Index int    // interface index, 0 if the message names none
	Name  string // interface name if the message carries one (link messages)
	Link  bool   // a link message: the interface itself changed
}

// parseNetlink reads the rtnetlink messages in one datagram and returns one
// nlChange for each message that signals a network change. Other messages
// (errors, acknowledgements, route changes in the local table, which only
// mirror address changes) are skipped. A malformed or truncated datagram
// yields an extra unnamed change: bytes arrived, so something happened, and
// it never panics. A link message names its interface even when the link is
// already gone (RTM_DELLINK), which is how a vanished tunnel is recognised.
func parseNetlink(b []byte) []nlChange {
	var out []nlChange
	for len(b) > 0 {
		if len(b) < nlHdrLen {
			out = append(out, nlChange{})
			break
		}
		n := int(binary.NativeEndian.Uint32(b[0:]))
		if n < nlHdrLen || n > len(b) {
			out = append(out, nlChange{})
			break
		}
		typ := binary.NativeEndian.Uint16(b[4:])
		payload := b[nlHdrLen:n]
		switch typ {
		case nlRTMNewLink, nlRTMDelLink:
			c := nlChange{Index: int(le32(payload, 4, ifInfoMsgLen)), Link: true}
			if len(payload) >= ifInfoMsgLen {
				c.Name = cString(rtAttr(payload[ifInfoMsgLen:], iflaIfname))
			}
			out = append(out, c)
		case nlRTMNewAddr, nlRTMDelAddr:
			out = append(out, nlChange{Index: int(le32(payload, 4, ifAddrMsgLen))})
		case nlRTMNewRoute, nlRTMDelRoute:
			if len(payload) >= rtMsgLen && payload[4] == rtTableLocal {
				break
			}
			c := nlChange{}
			if len(payload) >= rtMsgLen {
				if oif := rtAttr(payload[rtMsgLen:], rtaOIF); len(oif) >= 4 {
					c.Index = int(binary.NativeEndian.Uint32(oif))
				}
			}
			out = append(out, c)
		}
		next := (n + 3) &^ 3 // messages are aligned to 4 bytes
		if next >= len(b) {
			break
		}
		b = b[next:]
	}
	return out
}

// le32 reads a uint32 at off from p when p holds a whole struct of size
// structLen; otherwise it returns 0.
func le32(p []byte, off, structLen int) uint32 {
	if len(p) < structLen {
		return 0
	}
	return binary.NativeEndian.Uint32(p[off:])
}

// rtAttr returns the data of the first attribute of type typ in a
// rtattr list, or nil.
func rtAttr(a []byte, typ uint16) []byte {
	for len(a) >= rtaHdrLen {
		n := int(binary.NativeEndian.Uint16(a[0:]))
		if n < rtaHdrLen || n > len(a) {
			return nil
		}
		if binary.NativeEndian.Uint16(a[2:]) == typ {
			return a[rtaHdrLen:n]
		}
		next := (n + 3) &^ 3
		if next >= len(a) {
			return nil
		}
		a = a[next:]
	}
	return nil
}

// cString returns b up to its first NUL.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// resolveChanges names the interface of each change through cache and
// combines them like a Source does: ok is false when there is nothing to
// report, iface is "" unless every change names the same interface. A name
// carried by a message is learned first, so the delete of a link that no
// longer exists still resolves.
func resolveChanges(changes []nlChange, cache *ifaceCache) (iface string, ok bool) {
	cache.begin()
	if len(changes) == 0 {
		return "", false
	}
	names := make([]string, len(changes))
	for i, c := range changes {
		cache.learn(c.Index, c.Name)
		names[i] = cache.name(c.Index, c.Link)
	}
	return commonIface(names), true
}
