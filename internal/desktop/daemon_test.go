package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/ipc/ipctest"
	"github.com/Kodviva/latchwire/internal/msg"
)

// fakeDaemon speaks the real IPC protocol.
type fakeDaemon struct {
	socket string
	added  chan ipc.TunnelAdd
}

func startDaemon(t *testing.T, tunnels []ipc.TunnelStatus) *fakeDaemon {
	t.Helper()
	socket := ipctest.Path(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	d := &fakeDaemon{socket: socket, added: make(chan ipc.TunnelAdd, 1)}
	go func() {
		for {
			c, err := ipc.Accept(l)
			if err != nil {
				return
			}
			d.serve(c, tunnels)
		}
	}()
	return d
}

func (d *fakeDaemon) serve(c *ipc.Conn, tunnels []ipc.TunnelStatus) {
	c.Handle(ipc.MethodTunnelStatus, func(context.Context, uint32, json.RawMessage) (any, error) {
		return tunnels, nil
	})
	c.Handle(ipc.MethodTunnelConnect, func(_ context.Context, _ uint32, p json.RawMessage) (any, error) {
		var n ipc.TunnelName
		json.Unmarshal(p, &n)
		if n.Name == "bad" {
			return nil, &ipc.Error{Code: ipc.CodeUnavailable, Message: msg.DaemonNoCard}
		}
		return ipc.TunnelStatus{Name: n.Name, State: daemon.StateConnected}, nil
	})
	c.Handle(ipc.MethodTunnelAdd, func(_ context.Context, _ uint32, p json.RawMessage) (any, error) {
		var a ipc.TunnelAdd
		json.Unmarshal(p, &a)
		d.added <- a
		return nil, nil
	})
	go c.Serve(context.Background())
}

func TestClientOverRealIPC(t *testing.T) {
	d := startDaemon(t, []ipc.TunnelStatus{{Name: "office", State: daemon.StateConnected}})
	c := &Client{Socket: d.socket, UID: uint32(os.Getuid())}
	ctx := context.Background()

	sts, err := c.Status(ctx)
	if err != nil || len(sts) != 1 || sts[0].Name != "office" {
		t.Fatal(sts, err)
	}
	st, err := c.Connect(ctx, "office")
	if err != nil || st.State != daemon.StateConnected {
		t.Fatal(st, err)
	}
	if _, err := c.Connect(ctx, "bad"); err == nil || err.Error() != msg.DaemonNoCard {
		t.Fatal(err)
	}
	if err := c.Add(ctx, "new", "text"); err != nil {
		t.Fatal(err)
	}
	if a := <-d.added; a.Owner != c.UID || a.Name != "new" {
		t.Fatalf("%+v", a)
	}
}

func TestClientDaemonDown(t *testing.T) {
	dir := t.TempDir()
	c := &Client{Socket: filepath.Join(dir, "nothing"), UID: 501}
	if _, err := c.Status(context.Background()); !errors.Is(err, ErrDaemonDown) {
		t.Fatal(err)
	}
}

func TestClientRefusesForeignDaemon(t *testing.T) {
	d := startDaemon(t, nil)
	c := &Client{Socket: d.socket, UID: uint32(os.Getuid()) + 1}
	_, err := c.Status(context.Background())
	if os.Getuid() <= 0 {
		t.Skip("root and the Windows service are always trusted")
	}
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatal(err)
	}
}

// A uid the daemon would store as the owner, never the -1 of Windows.
func TestNewClientUID(t *testing.T) {
	want := uint32(0)
	if uid := os.Getuid(); uid > 0 {
		want = uint32(uid)
	}
	if got := NewClient().UID; got != want {
		t.Fatalf("UID %d, want %d", got, want)
	}
}

func TestUserError(t *testing.T) {
	if userError(nil) != nil {
		t.Fatal("nil")
	}
	var te net.Error = timeoutErr{}
	if !errors.Is(userError(te), ErrDaemonDown) {
		t.Fatal("timeout")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "t" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
