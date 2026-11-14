package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/ipc/ipctest"
	"github.com/Kodviva/latchwire/internal/msg"
)

var (
	testPub    = base64.StdEncoding.EncodeToString(make32(1))
	testBackup = base64.StdEncoding.EncodeToString(make32(2))
	serverPub  = base64.StdEncoding.EncodeToString(make32(3))
	testPSK    = base64.StdEncoding.EncodeToString(make32(4))
)

func make32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

// fakeDaemon answers assist.call with handle and records every call and
// every connection that ends.
type fakeDaemon struct {
	handle func(ctx context.Context, p ipc.AssistCall) (ipc.AssistResult, error)
	old    bool // a daemon from before assist.call

	mu     sync.Mutex
	calls  []ipc.AssistCall
	closed chan struct{} // one value per connection that ended
}

func (d *fakeDaemon) recorded() []ipc.AssistCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls)
}

// startDaemon serves a fake daemon on a test socket and returns the dial
// function for New.
func startDaemon(t *testing.T, d *fakeDaemon) func(context.Context) (*ipc.Conn, error) {
	t.Helper()
	d.closed = make(chan struct{}, 16)
	path := ipctest.Path(t)
	l, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); l.Close() })
	go func() {
		for {
			c, err := ipc.Accept(l)
			if err != nil {
				return
			}
			if d.old {
				go c.Serve(ctx)
				continue
			}
			c.Handle(ipc.MethodAssistCall, func(ctx context.Context, _ uint32, params json.RawMessage) (any, error) {
				var p ipc.AssistCall
				if err := json.Unmarshal(params, &p); err != nil {
					return nil, err
				}
				d.mu.Lock()
				d.calls = append(d.calls, p)
				d.mu.Unlock()
				return d.handle(ctx, p)
			})
			go func() {
				c.Serve(ctx)
				d.closed <- struct{}{}
			}()
		}
	}()
	return func(context.Context) (*ipc.Conn, error) { return ipc.Dial(path) }
}

// connect starts the MCP server for dial and a client session to it.
func connect(t *testing.T, dial func(context.Context) (*ipc.Conn, error), opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := New(dial).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, opts)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func ok(context.Context, ipc.AssistCall) (ipc.AssistResult, error) {
	return ipc.AssistResult{Data: json.RawMessage(`{"ok":true}`)}, nil
}

func TestToolsListed(t *testing.T) {
	cs := connect(t, startDaemon(t, &fakeDaemon{handle: ok}), nil)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if tool.Description == "" {
			t.Errorf("%s has no description", tool.Name)
		}
	}
	slices.Sort(names)
	want := []string{"add_tunnel", "connect", "create_key", "disconnect", "peer_block", "server_guide", "setup_progress", "status"}
	if !slices.Equal(names, want) {
		t.Errorf("tools = %v, want %v", names, want)
	}
}

func TestAccessOffSurfacesMessage(t *testing.T) {
	d := &fakeDaemon{handle: func(context.Context, ipc.AssistCall) (ipc.AssistResult, error) {
		return ipc.AssistResult{}, &ipc.Error{Code: ipc.CodeAccessOff, Message: msg.AssistAccessOff}
	}}
	cs := connect(t, startDaemon(t, d), nil)
	res := call(t, cs, "status", map[string]any{})
	if !res.IsError || text(res) != msg.AssistAccessOff {
		t.Errorf("status = %v %q, want the access_off message", res.IsError, text(res))
	}
	calls := d.recorded()
	if len(calls) != 1 || calls[0].Tool != ipc.ToolStatus || calls[0].Client != "test-client" {
		t.Errorf("daemon calls = %+v", calls)
	}
}

func TestStatusReturnsDaemonData(t *testing.T) {
	cs := connect(t, startDaemon(t, &fakeDaemon{handle: ok}), nil)
	res := call(t, cs, "status", nil)
	if res.IsError || !strings.Contains(text(res), `"ok":true`) {
		t.Errorf("status = %v %q", res.IsError, text(res))
	}
}

func TestPeerBlockChecksAccessFirst(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	d := &fakeDaemon{handle: func(context.Context, ipc.AssistCall) (ipc.AssistResult, error) {
		if refuse.Load() {
			return ipc.AssistResult{}, &ipc.Error{Code: ipc.CodeAccessOff, Message: msg.AssistAccessOff}
		}
		return ipc.AssistResult{}, nil
	}}
	cs := connect(t, startDaemon(t, d), nil)
	args := map[string]any{"public_key": testPub, "address": "10.8.0.2"}

	res := call(t, cs, "peer_block", args)
	if !res.IsError || strings.Contains(text(res), "[Peer]") || strings.Contains(text(res), testPub) {
		t.Errorf("refused peer_block = %v %q", res.IsError, text(res))
	}
	// Access is checked before the arguments: nothing is said while it is off.
	res = call(t, cs, "peer_block", map[string]any{"public_key": "bad", "address": "bad"})
	if text(res) != msg.AssistAccessOff {
		t.Errorf("refused peer_block with bad arguments = %q", text(res))
	}

	refuse.Store(false)
	res = call(t, cs, "peer_block", args)
	if res.IsError || !strings.Contains(text(res), "[Peer]") || !strings.Contains(text(res), testPub) || !strings.Contains(text(res), "10.8.0.2/32") {
		t.Errorf("peer_block = %v %q", res.IsError, text(res))
	}
	for _, c := range d.recorded() {
		var a ipc.AssistCheckArgs
		json.Unmarshal(c.Args, &a)
		if c.Tool != ipc.ToolCheck || a.Tool != ipc.ToolPeerBlock {
			t.Errorf("daemon call = %+v, want check of peer_block", c)
		}
	}
}

func TestServerGuide(t *testing.T) {
	d := &fakeDaemon{handle: ok}
	cs := connect(t, startDaemon(t, d), nil)
	res := call(t, cs, "server_guide", map[string]any{
		"kind": "mikrotik", "public_key": testPub, "address": "10.8.0.2",
		"backup_public_key": testBackup, "backup_address": "10.8.0.3",
	})
	got := text(res)
	if res.IsError || !strings.Contains(got, testPub) || !strings.Contains(got, testBackup) || !strings.Contains(got, "10.8.0.3/32") {
		t.Errorf("server_guide = %v %q", res.IsError, got)
	}
	res = call(t, cs, "server_guide", map[string]any{"kind": "toaster", "public_key": testPub, "address": "10.8.0.2"})
	if !res.IsError || text(res) != "kind: invalid" {
		t.Errorf("unknown kind = %v %q", res.IsError, text(res))
	}
	calls := d.recorded()
	var a ipc.AssistCheckArgs
	json.Unmarshal(calls[0].Args, &a)
	if calls[0].Tool != ipc.ToolCheck || a.Tool != ipc.ToolServerGuide {
		t.Errorf("daemon call = %+v", calls[0])
	}
}

func TestCreateKeySendsSlot(t *testing.T) {
	d := &fakeDaemon{handle: ok}
	cs := connect(t, startDaemon(t, d), nil)
	if res := call(t, cs, "create_key", map[string]any{"serial": 12345678, "slot": "83"}); res.IsError {
		t.Fatalf("create_key: %q", text(res))
	}
	if res := call(t, cs, "create_key", map[string]any{"serial": 12345678, "slot": "zz"}); !res.IsError || text(res) != "slot: invalid" {
		t.Errorf("bad slot = %v %q", res.IsError, text(res))
	}
	calls := d.recorded()
	if len(calls) != 1 {
		t.Fatalf("daemon calls = %+v", calls)
	}
	var a ipc.AssistKeyArgs
	json.Unmarshal(calls[0].Args, &a)
	if calls[0].Tool != ipc.ToolCreateKey || a != (ipc.AssistKeyArgs{Serial: 12345678, Slot: 0x83}) {
		t.Errorf("daemon call = %+v %+v", calls[0], a)
	}
}

func tunnelArgs(endpoint string) map[string]any {
	return map[string]any{
		"name": "office", "key_ref": "piv://12345678/82", "public_key": testPub, "address": "10.8.0.2",
		"servers": []map[string]any{{
			"endpoint": endpoint, "public_key": serverPub, "networks": []string{"10.0.0.0/24"},
			"preshared_key": testPSK, "keepalive": 25,
		}},
		"dns": []string{"10.0.0.1"},
	}
}

func TestAddTunnelFieldErrorHasNoValues(t *testing.T) {
	d := &fakeDaemon{handle: ok}
	cs := connect(t, startDaemon(t, d), nil)
	endpoint := "vpn.example.com#secret"
	res := call(t, cs, "add_tunnel", tunnelArgs(endpoint))
	got := text(res)
	if !res.IsError || got != "servers[0].endpoint: invalid" {
		t.Errorf("add_tunnel = %v %q", res.IsError, got)
	}
	if strings.Contains(got, endpoint) || strings.Contains(got, testPSK) {
		t.Errorf("error text holds a value: %q", got)
	}

	a := tunnelArgs("vpn.example.com:51820")
	a["servers"].([]map[string]any)[0]["preshared_key"] = "not-a-key-" + testPSK
	res = call(t, cs, "add_tunnel", a)
	if got := text(res); !res.IsError || got != "servers[0].preshared_key: invalid" || strings.Contains(got, testPSK) {
		t.Errorf("bad PSK = %v %q", res.IsError, got)
	}
	if calls := d.recorded(); len(calls) != 0 {
		t.Errorf("daemon called with an invalid form: %+v", calls)
	}
}

func TestAddTunnelSendsBoundConfig(t *testing.T) {
	d := &fakeDaemon{handle: ok}
	cs := connect(t, startDaemon(t, d), nil)
	res := call(t, cs, "add_tunnel", tunnelArgs("vpn.example.com:51820"))
	if res.IsError {
		t.Fatalf("add_tunnel: %q", text(res))
	}
	if strings.Contains(text(res), testPSK) {
		t.Errorf("result holds the PSK: %q", text(res))
	}

	a := tunnelArgs("vpn.example.com:51820")
	a["name"] = "office2"
	a["backup"] = map[string]any{"key_ref": "piv://87654321/83", "public_key": testBackup, "address": "10.8.0.3"}
	if res := call(t, cs, "add_tunnel", a); res.IsError {
		t.Fatalf("add_tunnel with backup: %q", text(res))
	}

	calls := d.recorded()
	if len(calls) != 2 {
		t.Fatalf("daemon calls = %+v", calls)
	}
	for i, c := range calls {
		var ta ipc.AssistTunnelArgs
		if err := json.Unmarshal(c.Args, &ta); err != nil {
			t.Fatal(err)
		}
		if c.Tool != ipc.ToolAddTunnel || ta.Name != []string{"office", "office2"}[i] {
			t.Errorf("daemon call %d = %+v", i, c)
		}
		for _, want := range []string{"KeyRef = piv://12345678/82", "PublicKey = " + testPub, "Endpoint = vpn.example.com:51820", "PresharedKey = " + testPSK, "DNS = 10.0.0.1"} {
			if !strings.Contains(ta.Config, want) {
				t.Errorf("config %d lacks %q:\n%s", i, want, ta.Config)
			}
		}
		if strings.Contains(strings.ToLower(ta.Config), "privatekey") {
			t.Errorf("config %d has a private key line:\n%s", i, ta.Config)
		}
	}
	var ta ipc.AssistTunnelArgs
	json.Unmarshal(calls[1].Args, &ta)
	for _, want := range []string{"[Identity]", "KeyRef = piv://87654321/83", "Address = 10.8.0.3/32"} {
		if !strings.Contains(ta.Config, want) {
			t.Errorf("backup config lacks %q:\n%s", want, ta.Config)
		}
	}
}

func TestProgressDuringLongCall(t *testing.T) {
	old := progressInterval
	progressInterval = 10 * time.Millisecond
	t.Cleanup(func() { progressInterval = old })

	progress := make(chan float64, 100)
	d := &fakeDaemon{handle: func(ctx context.Context, p ipc.AssistCall) (ipc.AssistResult, error) {
		// The daemon waits (for the approval and the PIN) until the client
		// has seen two progress notifications.
		for n := 0; n < 2; n++ {
			select {
			case <-progress:
			case <-time.After(5 * time.Second):
				return ipc.AssistResult{}, &ipc.Error{Code: ipc.CodeInternal, Message: "no progress"}
			}
		}
		return ok(ctx, p)
	}}
	cs := connect(t, startDaemon(t, d), &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
			if r.Params.ProgressToken == "tok" {
				progress <- r.Params.Progress
			}
		},
	})
	params := &mcp.CallToolParams{Name: "connect", Arguments: map[string]any{"name": "office"}}
	params.SetProgressToken("tok")
	res, err := cs.CallTool(context.Background(), params)
	if err != nil || res.IsError {
		t.Fatalf("connect = %v %q", err, text(res))
	}
}

func TestCancelClosesDaemonConn(t *testing.T) {
	started := make(chan struct{}, 1)
	d := &fakeDaemon{handle: func(ctx context.Context, p ipc.AssistCall) (ipc.AssistResult, error) {
		started <- struct{}{}
		<-ctx.Done()
		return ipc.AssistResult{}, ctx.Err()
	}}
	cs := connect(t, startDaemon(t, d), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "connect", Arguments: map[string]any{"name": "office"}})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the call did not reach the daemon")
	}
	cancel()
	select {
	case <-d.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon connection stayed open after the client cancelled")
	}
	<-done
}

func TestConnectAndDisconnectSendName(t *testing.T) {
	d := &fakeDaemon{handle: ok}
	cs := connect(t, startDaemon(t, d), nil)
	call(t, cs, "connect", map[string]any{"name": "office"})
	call(t, cs, "disconnect", map[string]any{"name": "office"})
	call(t, cs, "setup_progress", map[string]any{"path": "invited", "tunnel": "office"})
	calls := d.recorded()
	if len(calls) != 3 {
		t.Fatalf("daemon calls = %+v", calls)
	}
	for i, want := range []string{`{"name":"office"}`, `{"name":"office"}`, `{"path":"invited","tunnel":"office"}`} {
		if string(calls[i].Args) != want {
			t.Errorf("call %d (%s) args = %s, want %s", i, calls[i].Tool, calls[i].Args, want)
		}
	}
	// Each tool call has its own daemon connection, closed when it ends.
	for range 3 {
		select {
		case <-d.closed:
		case <-time.After(5 * time.Second):
			t.Fatal("a daemon connection stayed open")
		}
	}
}

func TestOldDaemonSaysUpdate(t *testing.T) {
	cs := connect(t, startDaemon(t, &fakeDaemon{old: true}), nil)
	if res := call(t, cs, "status", nil); !res.IsError || text(res) != msg.AssistDaemonTooOld {
		t.Errorf("status = %v %q", res.IsError, text(res))
	}
}
