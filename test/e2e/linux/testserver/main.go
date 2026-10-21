//go:build e2e && linux

// Command testserver is the WireGuard peer of the Linux end-to-end test
// (test/e2e/linux): wireguard-go with an ordinary software private key, plus
// a tiny DNS responder so the test can tell whether names are resolved
// through the tunnel. It is a test binary only and never part of a release.
//
//	testserver -iface wgs -key FILE -port 51820 -peer PUB@ALLOWED[,ALLOWED] ... \
//	           -dns 0.0.0.0:53 -answer NAME=IPv4
//
// The interface is created by this process; the test gives it its addresses
// once it exists.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, " ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	iface := flag.String("iface", "wgs", "interface name")
	keyFile := flag.String("key", "", "file with the base64 private key")
	port := flag.Int("port", 51820, "UDP listen port")
	dnsAddr := flag.String("dns", "", "UDP address of the DNS responder (empty: none)")
	answer := flag.String("answer", "", "NAME=IPv4 the DNS responder answers")
	var peers listFlag
	flag.Var(&peers, "peer", "PUB@ALLOWED[,ALLOWED...] (repeatable)")
	flag.Parse()

	data, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	sk, err := b64hex(strings.TrimSpace(string(data)))
	if err != nil {
		log.Fatalf("testserver: key: %v", err)
	}
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", sk, *port)
	for _, p := range peers {
		pub, allowed, ok := strings.Cut(p, "@")
		if !ok {
			log.Fatalf("testserver: bad -peer %q", p)
		}
		pk, err := b64hex(pub)
		if err != nil {
			log.Fatalf("testserver: peer key %q: %v", pub, err)
		}
		uapi += "public_key=" + pk + "\n"
		for _, a := range strings.Split(allowed, ",") {
			if _, err := netip.ParsePrefix(a); err != nil {
				log.Fatalf("testserver: allowed IP %q: %v", a, err)
			}
			uapi += "allowed_ip=" + a + "\n"
		}
	}

	tdev, err := tun.CreateTUN(*iface, 1420)
	if err != nil {
		log.Fatalf("testserver: create %s: %v", *iface, err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "testserver: "))
	if err := dev.IpcSet(uapi); err != nil {
		log.Fatalf("testserver: configure: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("testserver: up: %v", err)
	}
	log.Printf("testserver: %s listening on %d with %d peer(s)", *iface, *port, len(peers))

	if *dnsAddr != "" {
		name, ip, ok := strings.Cut(*answer, "=")
		addr, err := netip.ParseAddr(ip)
		if !ok || err != nil || !addr.Is4() {
			log.Fatalf("testserver: bad -answer %q", *answer)
		}
		go serveDNS(*dnsAddr, name, addr)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-dev.Wait():
	}
	dev.Close()
}

// b64hex turns a base64 WireGuard key into the hex form UAPI expects.
func b64hex(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key is %d bytes, want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// serveDNS answers A queries for name with addr and everything else with
// NXDOMAIN.
func serveDNS(listen, name string, addr netip.Addr) {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		log.Fatalf("testserver: dns: %v", err)
	}
	want := strings.TrimSuffix(strings.ToLower(name), ".") + "."
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("testserver: dns: %v", err)
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired}
		hit := strings.ToLower(q.Name.String()) == want
		if !hit {
			rh.RCode = dnsmessage.RCodeNameError
		}
		b := dnsmessage.NewBuilder(nil, rh)
		b.EnableCompression()
		if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
			continue
		}
		if hit && q.Type == dnsmessage.TypeA {
			if b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 1},
				dnsmessage.AResource{A: addr.As4()}) != nil {
				continue
			}
		}
		msg, err := b.Finish()
		if err != nil {
			continue
		}
		log.Printf("testserver: dns %s %s from %s", q.Type, q.Name, from)
		pc.WriteTo(msg, from)
	}
}
