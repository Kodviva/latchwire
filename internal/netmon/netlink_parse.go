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

	rtaOIF = 4 // output interface index of a route

	nlHdrLen     = 16 // struct nlmsghdr
	ifInfoMsgLen = 16 // struct ifinfomsg
	ifAddrMsgLen = 8  // struct ifaddrmsg
	rtMsgLen     = 12 // struct rtmsg
	rtTableLocal = 255
	rtaHdrLen    = 4 // struct rtattr
)

// parseNetlink reads the rtnetlink messages in one datagram and returns, for
// each message that signals a network change, the index of the interface it
// concerns (0 when it names none). Other messages (errors, acknowledgements,
// route changes in the local table, which only mirror address changes) are
// skipped. Malformed input is cut short, never a panic.
func parseNetlink(b []byte) []int {
	var out []int
	for len(b) >= nlHdrLen {
		n := int(binary.NativeEndian.Uint32(b[0:]))
		if n < nlHdrLen || n > len(b) {
			break
		}
		typ := binary.NativeEndian.Uint16(b[4:])
		payload := b[nlHdrLen:n]
		switch typ {
		case nlRTMNewLink, nlRTMDelLink:
			out = append(out, int(le32(payload, 4, ifInfoMsgLen)))
		case nlRTMNewAddr, nlRTMDelAddr:
			out = append(out, int(le32(payload, 4, ifAddrMsgLen)))
		case nlRTMNewRoute, nlRTMDelRoute:
			if len(payload) >= rtMsgLen && payload[4] == rtTableLocal {
				break
			}
			out = append(out, routeOIF(payload))
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

// routeOIF returns the RTA_OIF attribute of an rtmsg payload, or 0.
func routeOIF(p []byte) int {
	if len(p) < rtMsgLen {
		return 0
	}
	a := p[rtMsgLen:]
	for len(a) >= rtaHdrLen {
		n := int(binary.NativeEndian.Uint16(a[0:]))
		if n < rtaHdrLen || n > len(a) {
			return 0
		}
		if binary.NativeEndian.Uint16(a[2:]) == rtaOIF && n >= rtaHdrLen+4 {
			return int(binary.NativeEndian.Uint32(a[rtaHdrLen:]))
		}
		next := (n + 3) &^ 3
		if next >= len(a) {
			return 0
		}
		a = a[next:]
	}
	return 0
}
