package desktop

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/Kodviva/latchwire/internal/msg"
)

// AdminMessage is the ready message for the person who runs the server: the
// public key of every card, the tunnel IP asked for, the [Peer] blocks, one
// line on how to add a peer per kind of server, and what to send back. Only
// public values go in: never a key reference, a PIN or a pre-shared key. An
// address that is missing or invalid is left for the administrator to pick.
func AdminMessage(lang string, keys []Key, addrs []netip.Addr) (subject, body string) {
	var b strings.Builder
	b.WriteString(msg.Render(lang, msg.UIShareIntro, nil))
	for i, k := range keys {
		var addr netip.Addr
		if i < len(addrs) {
			addr = addrs[i]
		}
		b.WriteString("\n\n")
		if len(keys) > 1 {
			head := msg.UIShareKeyMain
			if i > 0 {
				head = msg.UIShareKeyBackup
			}
			b.WriteString(msg.Render(lang, head, nil) + "\n")
		}
		ip := msg.Render(lang, msg.UIShareIPFree, nil)
		if addr.IsValid() {
			ip = addr.String()
		}
		b.WriteString(msg.Render(lang, msg.UIShareKeyLine, msg.Args{"key": k.PublicBase64()}) + "\n")
		b.WriteString(msg.Render(lang, msg.UIShareIPLine, msg.Args{"ip": ip}) + "\n\n")
		b.WriteString(PeerBlock(lang, k, addr))
	}
	b.WriteString("\n\n" + msg.Render(lang, msg.UIShareHow, nil))
	for _, id := range []msg.ID{msg.UIShareHowOPNsense, msg.UIShareHowPfSense, msg.UIShareHowMikroTik, msg.UIShareHowLinux} {
		b.WriteString("\n- " + msg.Render(lang, id, nil))
	}
	b.WriteString("\n\n" + msg.Render(lang, msg.UIShareReply, nil) + "\n")
	return msg.Render(lang, msg.UIShareSubject, nil), b.String()
}

// MailtoURL is a mailto: link with a subject and a body. Spaces become %20
// and '+' becomes %2B: mail programs read a '+' in a mailto: link literally.
// Line breaks in the body become CRLF, %0D%0A, as RFC 6068 asks.
func MailtoURL(subject, body string) *url.URL {
	esc := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	return &url.URL{Scheme: "mailto", RawQuery: "subject=" + esc(subject) + "&body=" + esc(body)}
}
