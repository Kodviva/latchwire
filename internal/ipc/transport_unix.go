//go:build unix

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

func connFromUnix(uc *net.UnixConn) (*Conn, error) {
	uid, err := PeerUID(uc)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("ipc: peer credentials: %w", err)
	}
	return newConn(uc, uid, 0), nil
}

// Users is the table of Windows user identities; Unix has real uids.
func Users() *UserTable { return nil }

// Dial connects to the unix socket at path. PeerUID of the result is the
// server's uid, which lets a client check it is talking to root.
func Dial(path string) (*Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	nc, err := d.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return connFromUnix(nc.(*net.UnixConn))
}

// ListenUsers is Listen. The table of users exists on Windows only.
func ListenUsers(path string, _ *UserTable) (net.Listener, error) { return Listen(path) }

// Listen creates a unix socket listener at path with mode 0666; callers are
// told apart by peer credentials, not file permissions. A stale socket file
// (nothing accepts connections on it) is replaced. A live one, or a path that
// is not a socket, is left untouched and an error is returned.
func Listen(path string) (net.Listener, error) {
	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ipc: %s exists and is not a socket", path)
		}
		c, derr := net.DialTimeout("unix", path, dialTimeout)
		if derr == nil {
			c.Close()
			return nil, fmt.Errorf("%w: %s", ErrAddrInUse, path)
		}
		if !errors.Is(derr, syscall.ECONNREFUSED) && !errors.Is(derr, syscall.ENOENT) {
			return nil, fmt.Errorf("ipc: probing %s: %w", path, derr)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Accept accepts one connection from l, which must be a unix listener, and
// reads the peer's credentials.
func Accept(l net.Listener) (*Conn, error) {
	nc, err := l.Accept()
	if err != nil {
		return nil, err
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		nc.Close()
		return nil, errors.New("ipc: not a unix connection")
	}
	return connFromUnix(uc)
}
