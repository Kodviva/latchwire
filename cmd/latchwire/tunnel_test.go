package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

type call struct {
	method string
	params any
}

// fakeRPC stands in for the daemon connection. replies maps a method to a
// function that fills the result or returns an error.
type fakeRPC struct {
	calls   []call
	replies map[string]func(params any, result any) error
	closed  bool
}

func (f *fakeRPC) Call(_ context.Context, method string, params, result any) error {
	f.calls = append(f.calls, call{method, params})
	if fn := f.replies[method]; fn != nil {
		return fn(params, result)
	}
	return nil
}

func (f *fakeRPC) Close() error { f.closed = true; return nil }

func (f *fakeRPC) methods() []string {
	var m []string
	for _, c := range f.calls {
		m = append(m, c.method)
	}
	return m
}

func setResult(t *testing.T, result, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, result); err != nil {
		t.Fatal(err)
	}
}

func withRPC(te *testEnv, rpc *fakeRPC) {
	te.dial = func(context.Context) (rpcConn, error) { return rpc, nil }
}

func TestDownAlreadyDisconnected(t *testing.T) {
	for _, state := range []string{"disconnected", "error"} {
		te := newTestEnv(nil)
		rpc := &fakeRPC{replies: map[string]func(any, any) error{
			ipc.MethodTunnelStatus: func(_, r any) error {
				setResult(t, r, []ipc.TunnelStatus{{Name: "office", State: state}})
				return nil
			},
			// What the daemon would answer a non-admin for an unbound tunnel.
			ipc.MethodTunnelDisconnect: func(_, _ any) error {
				return &ipc.Error{Code: ipc.CodeForbidden, Message: msg.DaemonNotYourTunnel}
			},
		}}
		withRPC(te, rpc)
		if code := run(context.Background(), te.env, []string{"down", "office"}); code != 0 {
			t.Fatalf("%s: exit %d, stderr: %s", state, code, te.errOut)
		}
		if got := strings.Join(rpc.methods(), ","); got != ipc.MethodTunnelStatus {
			t.Errorf("%s: calls = %s, want status only", state, got)
		}
		all := te.out.String() + te.errOut.String()
		if !strings.Contains(all, "already disconnected") || strings.Contains(all, msg.DaemonNotYourTunnel) {
			t.Errorf("%s: output: %s", state, all)
		}
		if !rpc.closed {
			t.Error("connection not closed")
		}
	}
}

func TestDownConnected(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelStatus: func(_, r any) error {
			setResult(t, r, []ipc.TunnelStatus{{Name: "office", State: "connected"}})
			return nil
		},
		ipc.MethodTunnelDisconnect: func(_, r any) error {
			setResult(t, r, ipc.TunnelStatus{Name: "office", State: "disconnected"})
			return nil
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"down", "office"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if got := strings.Join(rpc.methods(), ","); got != ipc.MethodTunnelStatus+","+ipc.MethodTunnelDisconnect {
		t.Errorf("calls = %s", got)
	}
	if rpc.calls[1].params.(ipc.TunnelName).Name != "office" {
		t.Errorf("params = %+v", rpc.calls[1].params)
	}
	if !strings.Contains(te.out.String(), "disconnected") {
		t.Errorf("stdout: %s", te.out)
	}
}

func TestDownOtherUsersTunnelShowsDaemonMessage(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelStatus: func(_, r any) error {
			setResult(t, r, []ipc.TunnelStatus{{Name: "office", State: "connected"}})
			return nil
		},
		ipc.MethodTunnelDisconnect: func(_, _ any) error {
			return &ipc.Error{Code: ipc.CodeForbidden, Message: msg.DaemonNotYourTunnel}
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"down", "office"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errOut.String(), msg.DaemonNotYourTunnel) {
		t.Errorf("stderr: %s", te.errOut)
	}
}

func TestUpPrintsDaemonErrorMessage(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelConnect: func(_, _ any) error {
			return &ipc.Error{Code: ipc.CodeWrongPIN, Message: "wrong PIN, 2 attempts left"}
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"up", "office"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errOut.String(), "wrong PIN, 2 attempts left") {
		t.Errorf("stderr: %s", te.errOut)
	}
	if strings.Contains(te.errOut.String(), ipc.CodeWrongPIN+":") {
		t.Errorf("error code leaked into output: %s", te.errOut)
	}
}

func TestUpSuccess(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelConnect: func(_, r any) error {
			setResult(t, r, ipc.TunnelStatus{Name: "office", State: "connected", Identity: "piv://7/82"})
			return nil
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"up", "office"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if !strings.Contains(te.out.String(), "office") || !strings.Contains(te.out.String(), "connected") {
		t.Errorf("stdout: %s", te.out)
	}
}

func TestDaemonNotRunning(t *testing.T) {
	te := newTestEnv(nil)
	te.dial = func(context.Context) (rpcConn, error) {
		return nil, &os.PathError{Op: "dial", Path: "/x", Err: syscall.ENOENT}
	}
	if code := run(context.Background(), te.env, []string{"status"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errOut.String(), msg.CLIDaemonNotRunning) {
		t.Errorf("stderr: %s", te.errOut)
	}
}

func TestStatusTable(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelStatus: func(_, r any) error {
			setResult(t, r, []ipc.TunnelStatus{
				{Name: "office", State: "connected", Identity: "piv://7/82", LastHandshake: "2026-10-20T10:00:00Z"},
				{Name: "lab", State: "disconnected"},
			})
			return nil
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"status"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	out := te.out.String()
	for _, want := range []string{"NAME", "office", "connected", "piv://7/82", "2026-10-20T10:00:00Z", "lab", "disconnected"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
}

func TestAddSendsConfig(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "office.conf")
	if err := os.WriteFile(file, []byte("[Interface]\nKeyRef = x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	te := newTestEnv(nil)
	rpc := &fakeRPC{}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"add", "office", file}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if len(rpc.calls) != 1 || rpc.calls[0].method != ipc.MethodTunnelAdd {
		t.Fatalf("calls = %v", rpc.methods())
	}
	p := rpc.calls[0].params.(ipc.TunnelAdd)
	if p.Name != "office" || p.Config != "[Interface]\nKeyRef = x\n" {
		t.Errorf("params = %+v", p)
	}

	// Unreadable file: no daemon call.
	te = newTestEnv(nil)
	rpc = &fakeRPC{}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"add", "office", filepath.Join(dir, "missing.conf")}); code != 1 {
		t.Errorf("missing file: exit %d", code)
	}
	if len(rpc.calls) != 0 {
		t.Error("daemon called for an unreadable file")
	}
}

func TestRemove(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"remove", "office"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if len(rpc.calls) != 1 || rpc.calls[0].method != ipc.MethodTunnelRemove {
		t.Fatalf("calls = %v", rpc.methods())
	}
}

func TestDaemonRefusesNonRoot(t *testing.T) {
	te := newTestEnv(nil)
	started := false
	te.runDaemon = func(context.Context) error { started = true; return nil }
	if code := run(context.Background(), te.env, []string{"daemon"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if started {
		t.Error("daemon started as non-root")
	}
	if !strings.Contains(te.errOut.String(), msg.DaemonMustBeRoot) {
		t.Errorf("stderr: %s", te.errOut)
	}

	te = newTestEnv(nil)
	te.geteuid = func() int { return 0 }
	te.runDaemon = func(context.Context) error { started = true; return context.Canceled }
	if code := run(context.Background(), te.env, []string{"daemon"}); code != 0 {
		t.Errorf("root: exit %d: %s", code, te.errOut)
	}
	if !started {
		t.Error("daemon did not start as root")
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"up"},
		{"up", "a", "b"},
		{"down"},
		{"add", "x"},
		{"remove"},
		{"status", "a", "b"},
		{"devices", "x"},
		{"agent", "x"},
		{"daemon", "x"},
	} {
		te := newTestEnv(nil)
		rpc := &fakeRPC{}
		withRPC(te, rpc)
		if code := run(context.Background(), te.env, args); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if len(rpc.calls) != 0 {
			t.Errorf("%v: called the daemon", args)
		}
		if !strings.Contains(te.errOut.String(), "usage") {
			t.Errorf("%v: no usage text: %s", args, te.errOut)
		}
	}
}

func TestHelp(t *testing.T) {
	te := newTestEnv(nil)
	if code := run(context.Background(), te.env, []string{"help"}); code != 0 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(te.out.String(), "keygen") {
		t.Errorf("stdout: %s", te.out)
	}
}
