package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// connectTimeout is longer than the daemon's wait for a PIN (2 minutes).
const (
	statusTimeout  = 3 * time.Second
	addTimeout     = 10 * time.Second
	connectTimeout = 3 * time.Minute
)

// ErrDaemonDown means the daemon cannot be reached. Its text is the one the
// CLI prints on this platform.
var ErrDaemonDown = errors.New(daemonDownText())

func daemonDownText() string {
	if runtime.GOOS == "windows" {
		return msg.CLIDaemonNotRunningWindows
	}
	return msg.CLIDaemonNotRunning
}

// Client talks to the daemon over the same IPC as the CLI, one connection per
// call.
type Client struct {
	// Socket is the daemon socket; empty means daemon.DefaultSocket.
	Socket string
	// UID is the uid written as owner of added tunnels and accepted, next to
	// root, as the socket's server.
	UID uint32
}

// NewClient returns a client for the production socket.
func NewClient() *Client { return &Client{UID: currentUID()} }

// currentUID is this user's uid. Windows has none and os.Getuid returns -1
// there: 0 tells the daemon to take the owner from the elevated connection.
func currentUID() uint32 {
	if uid := os.Getuid(); uid > 0 {
		return uint32(uid)
	}
	return 0
}

func (c *Client) call(ctx context.Context, timeout time.Duration, method string, params, result any) error {
	socket := c.Socket
	if socket == "" {
		socket = daemon.DefaultSocket
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := ipc.Dial(socket)
	if err != nil {
		return userError(err)
	}
	defer conn.Close()
	// Only root (the daemon) or this user may serve it: configuration texts
	// go over this connection.
	if uid := conn.PeerUID(); uid != 0 && uid != c.UID {
		return fmt.Errorf(msg.CLIUntrustedDaemonFmt, uid)
	}
	go conn.Serve(ctx)
	return userError(conn.Call(ctx, method, params, result))
}

// userError is the CLI's daemonErr: the text to show.
func userError(err error) error {
	var ie *ipc.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ie):
		return errors.New(ie.Message)
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
		return ErrDaemonDown
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrDaemonDown
	}
	return err
}

// Status returns every tunnel.
func (c *Client) Status(ctx context.Context) ([]ipc.TunnelStatus, error) {
	var sts []ipc.TunnelStatus
	err := c.call(ctx, statusTimeout, ipc.MethodTunnelStatus, nil, &sts)
	return sts, err
}

// Connect brings a tunnel up. It returns when the tunnel is up, which can
// take as long as the PIN prompt.
func (c *Client) Connect(ctx context.Context, name string) (ipc.TunnelStatus, error) {
	var st ipc.TunnelStatus
	err := c.call(ctx, connectTimeout, ipc.MethodTunnelConnect, ipc.TunnelName{Name: name}, &st)
	return st, err
}

// Disconnect takes a tunnel down.
func (c *Client) Disconnect(ctx context.Context, name string) error {
	return c.call(ctx, statusTimeout, ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: name}, nil)
}

// Add stores a tunnel with this user as its allowed user. The daemon refuses
// it unless the user is an administrator.
func (c *Client) Add(ctx context.Context, name, config string) error {
	return c.call(ctx, addTimeout, ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: name, Config: config, Owner: c.UID}, nil)
}
