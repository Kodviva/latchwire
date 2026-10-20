package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sockPath returns a short socket path: macOS limits sun_path to 104 bytes.
func sockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// pair returns the accepted (server-side) and dialled (client-side) ends of
// one connection. Both ends are already being served.
func pair(t *testing.T) (srv, cli *Conn) {
	t.Helper()
	path := sockPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	type res struct {
		c   *Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := Accept(l)
		ch <- res{c, err}
	}()
	cli, err = Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	srv = r.c

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Close()
		cli.Close()
	})
	go srv.Serve(ctx)
	go cli.Serve(ctx)
	return srv, cli
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCallRoundTrip(t *testing.T) {
	srv, cli := pair(t)

	// client -> server (CLI/agent -> daemon direction)
	srv.Handle(MethodTunnelAdd, func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		var in TunnelAdd
		if err := json.Unmarshal(p, &in); err != nil {
			return nil, err
		}
		return TunnelName{Name: in.Name + "!"}, nil
	})
	// server -> client (daemon -> agent direction), same connection
	cli.Handle(MethodKeyPublic, func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		var in KeyRequest
		if err := json.Unmarshal(p, &in); err != nil {
			return nil, err
		}
		return KeyPublicResult{Public: "pub:" + in.Ref}, nil
	})

	var out TunnelName
	if err := cli.Call(ctx5(t), MethodTunnelAdd, TunnelAdd{Name: "home", Config: "x"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Name != "home!" {
		t.Fatalf("got %q", out.Name)
	}

	var pub KeyPublicResult
	if err := srv.Call(ctx5(t), MethodKeyPublic, KeyRequest{Ref: "piv://1/82"}, &pub); err != nil {
		t.Fatal(err)
	}
	if pub.Public != "pub:piv://1/82" {
		t.Fatalf("got %q", pub.Public)
	}
}

func TestHandlerReceivesPeerUID(t *testing.T) {
	srv, cli := pair(t)
	got := make(chan uint32, 1)
	srv.Handle("x", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		got <- uid
		return nil, nil
	})
	if err := cli.Call(ctx5(t), "x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if uid := <-got; uid != uint32(os.Getuid()) {
		t.Fatalf("handler uid %d, want %d", uid, os.Getuid())
	}
}

func TestRemoteErrors(t *testing.T) {
	srv, cli := pair(t)
	srv.Handle("deny", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		return nil, &Error{Code: CodeForbidden, Message: "admin only"}
	})
	srv.Handle("wrapped", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		return nil, fmt.Errorf("ctx: %w", &Error{Code: CodeNotFound, Message: "no such tunnel"})
	})
	srv.Handle("plain", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		return nil, errors.New("secret detail /etc/foo")
	})
	srv.Handle("panic", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		panic("boom")
	})

	check := func(method, code string) {
		t.Helper()
		err := cli.Call(ctx5(t), method, nil, nil)
		var e *Error
		if !errors.As(err, &e) || e.Code != code {
			t.Fatalf("%s: got %v, want code %q", method, err, code)
		}
		if strings.Contains(e.Message, "secret detail") || strings.Contains(e.Message, "boom") {
			t.Fatalf("%s: internal detail leaked: %q", method, e.Message)
		}
	}
	check("deny", CodeForbidden)
	check("wrapped", CodeNotFound)
	check("plain", CodeInternal)
	check("panic", CodeInternal)
	check("nonexistent", CodeNotFound)

	// connection still healthy after all of that
	srv.Handle("ok", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) { return nil, nil })
	if err := cli.Call(ctx5(t), "ok", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOversizeMessageCloses(t *testing.T) {
	path := sockPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	serveErr := make(chan error, 1)
	go func() {
		c, err := Accept(l)
		if err != nil {
			serveErr <- err
			return
		}
		serveErr <- c.Serve(context.Background())
	}()

	raw, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	line := strings.Repeat("a", 65*1024) + "\n"
	go raw.Write([]byte(line)) // may fail once the server hangs up

	raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, raw); err != nil {
		t.Fatalf("expected clean close, got %v", err)
	}
	select {
	case err := <-serveErr:
		if !errors.Is(err, ErrMessageTooLarge) {
			t.Fatalf("Serve returned %v, want ErrMessageTooLarge", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}

	// listener (server) is unaffected
	go func() {
		c, err := Accept(l)
		if err == nil {
			c.Handle("ping", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) { return nil, nil })
			c.Serve(context.Background())
		}
	}()
	c2, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	go c2.Serve(context.Background())
	if err := c2.Call(ctx5(t), "ping", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOversizeCallRejectedLocally(t *testing.T) {
	_, cli := pair(t)
	big := strings.Repeat("a", MaxMessageSize)
	err := cli.Call(ctx5(t), "x", big, nil)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("got %v", err)
	}
	// nothing was sent, the connection is still usable
	select {
	case <-cli.Done():
		t.Fatal("conn closed by local oversize rejection")
	default:
	}
}

func TestMalformedJSONCloses(t *testing.T) {
	path := sockPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	serveErr := make(chan error, 1)
	go func() {
		c, _ := Accept(l)
		serveErr <- c.Serve(context.Background())
	}()
	raw, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.Write([]byte("{not json\n"))
	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestPeerUIDIsCaller(t *testing.T) {
	path := sockPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	acc := make(chan *Conn, 1)
	go func() {
		c, err := Accept(l)
		if err != nil {
			t.Error(err)
		}
		acc <- c
	}()
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	srv := <-acc
	if srv == nil {
		t.FailNow()
	}
	defer srv.Close()
	want := uint32(os.Getuid())
	if got := srv.PeerUID(); got != want {
		t.Fatalf("Conn.PeerUID = %d, want %d", got, want)
	}
	got, err := PeerUID(uc)
	if err != nil {
		t.Fatal(err)
	}
	if got != want { // same process on both ends
		t.Fatalf("PeerUID = %d, want %d", got, want)
	}
}

func TestIsAdminRoot(t *testing.T) {
	ok, err := IsAdmin(0)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("IsAdmin(0) = false")
	}
}

func TestIsAdminUnknownUID(t *testing.T) {
	ok, err := IsAdmin(3999999999)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("unknown uid must not be admin")
	}
}

func TestConcurrentCalls(t *testing.T) {
	srv, cli := pair(t)
	srv.Handle("echo", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		var n int
		if err := json.Unmarshal(p, &n); err != nil {
			return nil, err
		}
		// stagger so responses come back out of order
		time.Sleep(time.Duration((100-n)%7) * time.Millisecond)
		return n * 2, nil
	})
	const N = 100
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out int
			if err := cli.Call(ctx5(t), "echo", i, &out); err != nil {
				errs <- err
				return
			}
			if out != i*2 {
				errs <- fmt.Errorf("call %d got %d", i, out)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSlowHandlerDoesNotBlockReading(t *testing.T) {
	srv, cli := pair(t)
	release := make(chan struct{})
	srv.Handle("slow", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		<-release
		return nil, nil
	})
	srv.Handle("fast", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) { return nil, nil })

	slowDone := make(chan error, 1)
	go func() { slowDone <- cli.Call(ctx5(t), "slow", nil, nil) }()
	time.Sleep(50 * time.Millisecond)
	if err := cli.Call(ctx5(t), "fast", nil, nil); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-slowDone; err != nil {
		t.Fatal(err)
	}
}

func TestCallCtxCancel(t *testing.T) {
	srv, cli := pair(t)
	started := make(chan struct{})
	release := make(chan struct{})
	srv.Handle("hang", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		close(started)
		<-release
		return "late", nil
	})
	srv.Handle("ok", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) { return "fine", nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		var s string
		done <- cli.Call(ctx, "hang", nil, &s)
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Call did not return after cancel")
	}

	close(release) // late response arrives, must be discarded
	var s string
	if err := cli.Call(ctx5(t), "ok", nil, &s); err != nil || s != "fine" {
		t.Fatalf("conn broken after late response: %v %q", err, s)
	}
	cli.mu.Lock()
	n := len(cli.pending)
	cli.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d pending entries leaked", n)
	}
}

func TestPendingFailOnClose(t *testing.T) {
	srv, cli := pair(t)
	started := make(chan struct{}, 10)
	srv.Handle("hang", func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
		started <- struct{}{}
		<-ctx.Done() // handler ctx must be cancelled when conn dies
		return nil, ctx.Err()
	})

	const N = 10
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() { errs <- cli.Call(context.Background(), "hang", nil, nil) }()
	}
	for i := 0; i < N; i++ {
		<-started
	}
	srv.Close() // peer goes away
	for i := 0; i < N; i++ {
		select {
		case err := <-errs:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("got %v, want ErrClosed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pending Call did not fail on close")
		}
	}
	if err := cli.Call(ctx5(t), "hang", nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Call after close: %v", err)
	}
}

func TestListenMode0666(t *testing.T) {
	path := sockPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o666 {
		t.Fatalf("mode %v, want 0666", fi.Mode().Perm())
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := sockPath(t)
	// leave a stale socket file behind: listener closed without unlinking
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ul.SetUnlinkOnClose(false)
	ul.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("stale socket not created:", err)
	}
	l, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	l.Close()
}

func TestListenRefusesLiveSocket(t *testing.T) {
	path := sockPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l2, err := Listen(path); err == nil {
		l2.Close()
		t.Fatal("second Listen on live socket succeeded")
	}
	// the live socket must still work
	go func() {
		if c, err := Accept(l); err == nil {
			c.Close()
		}
	}()
	c, err := Dial(path)
	if err != nil {
		t.Fatalf("live socket was disturbed: %v", err)
	}
	c.Close()
}

func TestListenRefusesRegularFile(t *testing.T) {
	path := sockPath(t)
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(path); err == nil {
		l.Close()
		t.Fatal("Listen replaced a regular file")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "precious" {
		t.Fatal("regular file was modified")
	}
}

func TestMessageJSONShape(t *testing.T) {
	b, err := json.Marshal(Message{ID: 7, Method: "m", Params: json.RawMessage(`{"a":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"id":7,"method":"m","params":{"a":1}}` {
		t.Fatalf("got %s", b)
	}
	r := bufio.NewReader(strings.NewReader(`{"id":7,"error":{"code":"forbidden","message":"x"}}` + "\n"))
	line, _ := r.ReadBytes('\n')
	var m Message
	if err := json.Unmarshal(line, &m); err != nil || m.Error == nil || m.Error.Code != "forbidden" {
		t.Fatalf("decode: %v %+v", err, m)
	}
}
