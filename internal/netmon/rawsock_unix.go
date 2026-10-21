//go:build darwin || linux

package netmon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// sockSource reads change notifications from a raw routing socket. The
// socket is non-blocking and registered with the Go poller, so a read can be
// unblocked by a deadline when ctx ends.
type sockSource struct {
	f   *os.File
	buf []byte
	// parse reads one datagram. ok is false when it holds nothing worth
	// reporting; iface is the interface the change concerns, or "".
	parse func(b []byte) (iface string, ok bool)
}

// newSockSource takes ownership of fd (closing it on error).
func newSockSource(fd int, name string, parse func([]byte) (string, bool)) (*sockSource, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	// Fails if the descriptor is not in the poller; Next could then never be
	// interrupted, so refuse to start.
	if err := f.SetReadDeadline(time.Time{}); err != nil {
		f.Close()
		return nil, fmt.Errorf("netmon: %s: %w", name, err)
	}
	return &sockSource{f: f, buf: make([]byte, 1<<16), parse: parse}, nil
}

// Next implements Source.
func (s *sockSource) Next(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.f.SetReadDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { s.f.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		n, err := s.f.Read(s.buf)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if errors.Is(err, syscall.ENOBUFS) {
				// The kernel dropped notifications: something changed.
				return "", nil
			}
			return "", fmt.Errorf("netmon: read: %w", err)
		}
		if iface, ok := s.parse(s.buf[:n]); ok {
			return iface, nil
		}
	}
}

// Close implements io.Closer; it also unblocks a pending Next.
func (s *sockSource) Close() error { return s.f.Close() }
