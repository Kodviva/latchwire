//go:build darwin || linux

package netmon

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A zero-length datagram must not end the source: os.File reports it as EOF.
func TestSockSourceSkipsEmptyDatagram(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	defer unix.Close(fds[1])
	src, err := newSockSource(fds[0], "test", func(b []byte) (string, bool) { return string(b), true })
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	if _, err := unix.Write(fds[1], nil); err != nil {
		t.Skipf("zero-length datagram: %v", err)
	}
	if _, err := unix.Write(fds[1], []byte("en0")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	iface, err := src.Next(ctx)
	if err != nil || iface != "en0" {
		t.Fatalf("Next = (%q, %v), want (en0, nil)", iface, err)
	}
}
