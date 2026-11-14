package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// grantAssist registers f as an assist app of uid and opens access for it
// with groups.
func grantAssist(t *testing.T, e *env, f *fakeApprover, uid uint32, groups []string) *ipc.Conn {
	t.Helper()
	dc := connPairWith(t, e, f.setup)
	e.m.agentRegister(dc, uid, nil, ipc.CapAssist)
	if err := e.m.assist.set(uid, dc, ipc.AssistGrant{Minutes: 60, Groups: groups}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dc
}

func toolArgs(t *testing.T, args any) json.RawMessage {
	t.Helper()
	if args == nil {
		return nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tool runs one assist.call of uid in the daemon.
func tool(t *testing.T, e *env, ctx context.Context, uid uint32, name string, args any) (ipc.AssistResult, error) {
	t.Helper()
	return e.m.assistCall(ctx, nil, uid, ipc.AssistCall{Client: "test-client", Tool: name, Args: toolArgs(t, args)})
}

// lastActivity returns uid's newest activity entry.
func lastActivity(t *testing.T, e *env, uid uint32) ipc.ActivityEntry {
	t.Helper()
	got := e.m.assist.activity(uid)
	if len(got) == 0 {
		t.Fatal("no activity recorded")
	}
	return got[0]
}

func wantResult(t *testing.T, e *env, uid uint32, toolName, result string) {
	t.Helper()
	a := lastActivity(t, e, uid)
	if a.Tool != toolName || a.Result != result || a.Client != "test-client" {
		t.Fatalf("activity %+v, want tool %s result %q", a, toolName, result)
	}
}

// everyTool is one call of each of the eight agent tools; peer_block and
// server_guide reach the daemon as checks.
var everyTool = []struct {
	tool string
	args any
	want string // the tool name in the activity list
}{
	{ipc.ToolStatus, nil, ipc.ToolStatus},
	{ipc.ToolSetupProgress, nil, ipc.ToolSetupProgress},
	{ipc.ToolCheck, ipc.AssistCheckArgs{Tool: ipc.ToolPeerBlock}, ipc.ToolPeerBlock},
	{ipc.ToolCheck, ipc.AssistCheckArgs{Tool: ipc.ToolServerGuide}, ipc.ToolServerGuide},
	{ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA}, ipc.ToolCreateKey},
	{ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: tunName, Config: "x"}, ipc.ToolAddTunnel},
	{ipc.ToolConnect, ipc.TunnelName{Name: tunName}, ipc.ToolConnect},
	{ipc.ToolDisconnect, ipc.TunnelName{Name: tunName}, ipc.ToolDisconnect},
}

func TestAccessOffRefusesEveryTool(t *testing.T) {
	// Through the socket, as the MCP server calls: access was never opened.
	e := newEnv(t, envOpts{noAgent: true})
	for _, c := range everyTool {
		err := e.call(ipc.MethodAssistCall, ipc.AssistCall{Client: "test-client", Tool: c.tool, Args: toolArgs(t, c.args)}, nil)
		wantCode(t, err, ipc.CodeAccessOff)
		wantResult(t, e, uidA, c.want, "access_off")
	}
	// The caller's connection never becomes an access owner.
	e.m.mu.Lock()
	marked := len(e.m.assistCallers)
	e.m.mu.Unlock()
	if marked != 1 {
		t.Fatalf("%d assist callers marked, want 1", marked)
	}

	// Open access without any group: the reads pass, the rest is off.
	f := &fakeApprover{allow: true}
	grantAssist(t, e, f, assistUID, nil)
	for _, c := range everyTool {
		_, err := tool(t, e, context.Background(), assistUID, c.tool, c.args)
		switch c.tool {
		case ipc.ToolStatus, ipc.ToolSetupProgress, ipc.ToolCheck:
			if err != nil {
				t.Fatalf("%s with access on: %v", c.want, err)
			}
			wantResult(t, e, assistUID, c.want, "done")
		default:
			wantCode(t, err, ipc.CodeAccessOff)
			wantResult(t, e, assistUID, c.want, "access_off")
		}
	}

	// Revoked: every tool, reads included, is off again.
	e.m.assist.revoke(assistUID)
	for _, c := range everyTool {
		_, err := tool(t, e, context.Background(), assistUID, c.tool, c.args)
		wantCode(t, err, ipc.CodeAccessOff)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests)+len(f.keygens) != 0 {
		t.Fatalf("the app was asked %d times", len(f.requests)+len(f.keygens))
	}
}

func TestUnknownToolIsBadRequest(t *testing.T) {
	f := &fakeApprover{allow: true}
	e, _ := assistEnv(t, f)
	_, err := tool(t, e, context.Background(), assistUID, "rm -rf", nil)
	wantCode(t, err, ipc.CodeBadRequest)
	wantResult(t, e, assistUID, "unknown", "error: bad_request")
	_, err = tool(t, e, context.Background(), assistUID, ipc.ToolCheck, ipc.AssistCheckArgs{Tool: ipc.ToolConnect})
	wantCode(t, err, ipc.CodeBadRequest) // check is for read-only tools, create_key and add_tunnel only
}

// The MCP server checks access and the tunnels group before it validates
// add_tunnel's form: the check asks no approval and adds no tunnel.
func TestCheckAddTunnel(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	check := ipc.AssistCheckArgs{Tool: ipc.ToolAddTunnel}

	_, err := tool(t, e, context.Background(), assistUID, ipc.ToolCheck, check)
	wantCode(t, err, ipc.CodeAccessOff)
	wantResult(t, e, assistUID, ipc.ToolAddTunnel, "access_off")

	f := &fakeApprover{allow: true}
	grantAssist(t, e, f, assistUID, []string{ipc.GroupKeys, ipc.GroupConnect})
	_, err = tool(t, e, context.Background(), assistUID, ipc.ToolCheck, check)
	wantCode(t, err, ipc.CodeAccessOff) // the tunnels group is off
	wantResult(t, e, assistUID, ipc.ToolAddTunnel, "access_off")

	grantAssist(t, e, f, assistUID, []string{ipc.GroupTunnels})
	res, err := tool(t, e, context.Background(), assistUID, ipc.ToolCheck, check)
	if err != nil {
		t.Fatalf("check of add_tunnel with tunnels on: %v", err)
	}
	if len(res.Data) != 0 || res.Summary != "" {
		t.Fatalf("check result %+v, want none", res)
	}
	wantResult(t, e, assistUID, ipc.ToolAddTunnel, "checked")
	if a := lastActivity(t, e, assistUID); a.Summary != "" {
		t.Fatalf("check activity summary %q, want none", a.Summary)
	}
	f.mu.Lock()
	asked := len(f.requests)
	f.mu.Unlock()
	if asked != 0 {
		t.Fatalf("the check asked the app %d times", asked)
	}
	e.m.mu.Lock()
	n := len(e.m.tunnels)
	e.m.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d tunnels after a check", n)
	}
}

// The MCP server checks access and the keys group before it reports a bad
// create_key slot: the check asks no approval and makes no key.
func TestCheckCreateKey(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	check := ipc.AssistCheckArgs{Tool: ipc.ToolCreateKey}

	_, err := tool(t, e, context.Background(), assistUID, ipc.ToolCheck, check)
	wantCode(t, err, ipc.CodeAccessOff)
	wantResult(t, e, assistUID, ipc.ToolCreateKey, "access_off")

	f := &fakeApprover{allow: true}
	grantAssist(t, e, f, assistUID, []string{ipc.GroupTunnels, ipc.GroupConnect})
	_, err = tool(t, e, context.Background(), assistUID, ipc.ToolCheck, check)
	wantCode(t, err, ipc.CodeAccessOff) // the keys group is off
	wantResult(t, e, assistUID, ipc.ToolCreateKey, "access_off")

	grantAssist(t, e, f, assistUID, []string{ipc.GroupKeys})
	res, err := tool(t, e, context.Background(), assistUID, ipc.ToolCheck, check)
	if err != nil {
		t.Fatalf("check of create_key with keys on: %v", err)
	}
	if len(res.Data) != 0 || res.Summary != "" {
		t.Fatalf("check result %+v, want none", res)
	}
	wantResult(t, e, assistUID, ipc.ToolCreateKey, "checked")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests)+len(f.keygens) != 0 {
		t.Fatalf("the check asked the app %d times", len(f.requests)+len(f.keygens))
	}
}

func TestCreateKeyAsksApprovalThenKeygen(t *testing.T) {
	f := &fakeApprover{allow: false, cards: []ipc.CardEntry{{Serial: serialA, Supported: true, FreeSlots: []uint8{0x83, 0x84}}}}
	e, _ := assistEnv(t, f)
	ctx := context.Background()

	// Refused: no key is made.
	_, err := tool(t, e, ctx, assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA})
	wantCode(t, err, ipc.CodeDenied)
	wantResult(t, e, assistUID, ipc.ToolCreateKey, "denied")
	f.mu.Lock()
	if len(f.requests) != 1 || len(f.keygens) != 0 {
		t.Fatalf("requests %d keygens %d after a refusal", len(f.requests), len(f.keygens))
	}
	r := f.requests[0]
	f.allow = true
	f.mu.Unlock()
	if r.Tool != ipc.ToolCreateKey || r.Client != "test-client" || r.Fresh || !strings.Contains(r.Summary, fmt.Sprint(serialA)) {
		t.Fatalf("approval request %+v", r)
	}

	// Allowed: the first free slot gets the key.
	res, err := tool(t, e, ctx, assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA})
	if err != nil {
		t.Fatal(err)
	}
	var kr ipc.KeygenResult
	if err := json.Unmarshal(res.Data, &kr); err != nil {
		t.Fatal(err)
	}
	if want := (keyref.Ref{Serial: serialA, Slot: 0x83}).String(); kr.Ref != want || kr.Public != testPublic {
		t.Fatalf("result %+v, want ref %s", kr, want)
	}
	wantResult(t, e, assistUID, ipc.ToolCreateKey, "done")
	f.mu.Lock()
	if len(f.keygens) != 1 || f.keygens[0] != (ipc.KeygenRequest{Serial: serialA, Slot: 0x83}) || f.keygenIDs[0] == "" {
		t.Fatalf("keygens %+v", f.keygens)
	}
	if !slices.Equal(f.notices, []string{"key_created"}) {
		t.Fatalf("notices %v", f.notices)
	}
	f.mu.Unlock()

	// A slot that is not free, and a card that is not there, ask nobody.
	_, err = tool(t, e, ctx, assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA, Slot: 0x82})
	wantCode(t, err, ipc.CodeBadRequest)
	_, err = tool(t, e, ctx, assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialB})
	wantCode(t, err, ipc.CodeNotFound)
	f.mu.Lock()
	n := len(f.requests)
	f.mu.Unlock()
	if n != 2 {
		t.Fatalf("%d approval requests, want 2", n)
	}
}

// What the app returns is checked: a key reference for another slot or a
// public key that is not 32 bytes is an error, not a result.
func TestCreateKeyRejectsBadKeygenResult(t *testing.T) {
	bad := []ipc.KeygenResult{
		{Ref: "yubikey:1/0x82", Public: testPublic},
		{Ref: refB.String(), Public: testPublic},
		{Ref: refA.String(), Public: "AAAA"},
		{Ref: refA.String(), Public: "not base64!"},
	}
	for _, kr := range bad {
		f := &fakeApprover{allow: true, keygen: func(ipc.KeygenRequest) (ipc.KeygenResult, error) { return kr, nil }}
		e, _ := assistEnv(t, f)
		res, err := tool(t, e, context.Background(), assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA})
		wantCode(t, err, ipc.CodeInternal)
		if res.Data != nil {
			t.Fatalf("%+v: data %s", kr, res.Data)
		}
		wantResult(t, e, assistUID, ipc.ToolCreateKey, "error: internal")
	}
}

func TestCreateKeyFreshCardTellsApproval(t *testing.T) {
	f := &fakeApprover{allow: true} // the default card is factory-fresh
	e, _ := assistEnv(t, f)
	if _, err := tool(t, e, context.Background(), assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 1 || !f.requests[0].Fresh {
		t.Fatalf("approval requests %+v, want one with Fresh", f.requests)
	}
}

// pskConfig is an office tunnel with a preshared key.
func pskConfig(psk string) string {
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	return fmt.Sprintf(`[Interface]
[Identity]
KeyRef = %s
PublicKey = %s
Address = 10.8.0.2/32
[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = vpn.example.com:51820
AllowedIPs = 10.8.0.0/24, 192.168.1.0/24
`, refA, key(1), key(2), psk)
}

func TestAddTunnelSummaryHidesPSK(t *testing.T) {
	logs := &syncBuffer{}
	log.SetOutput(logs)
	defer log.SetOutput(io.Discard)
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	f := &fakeApprover{allow: true}
	e, _ := assistEnv(t, f)
	ctx := context.Background()

	// A configuration error names no value.
	_, err := tool(t, e, ctx, assistUID, ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: tunName, Config: pskConfig(psk) + "MTU = " + psk + "\n"})
	wantCode(t, err, ipc.CodeBadRequest)
	if strings.Contains(err.Error(), psk) {
		t.Fatalf("error carries the PSK: %v", err)
	}

	res, err := tool(t, e, ctx, assistUID, ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: tunName, Config: pskConfig(psk)})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	reqs := slices.Clone(f.requests)
	notices := slices.Clone(f.notices)
	f.mu.Unlock()
	if len(reqs) != 1 {
		t.Fatalf("%d approval requests, want 1", len(reqs))
	}
	s := reqs[0].Summary
	for _, want := range []string{tunName, "vpn.example.com:51820", "10.8.0.0/24", "192.168.1.0/24", "PSK: yes"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q lacks %q", s, want)
		}
	}
	if !slices.Equal(notices, []string{"server_info_entered"}) {
		t.Fatalf("notices %v", notices)
	}
	wantResult(t, e, assistUID, ipc.ToolAddTunnel, "done")
	// The tunnel belongs to the user who granted access.
	if pol := e.m.store.policyFor(tunName); !slices.Equal(pol.AllowedUsers, []uint32{assistUID}) {
		t.Fatalf("allowed users %v, want [%d]", pol.AllowedUsers, assistUID)
	}

	// The PSK appears nowhere: not in the approval, the result, the
	// activity list or the daemon log.
	act, _ := json.Marshal(e.m.assist.activity(assistUID))
	req, _ := json.Marshal(reqs)
	resJSON, _ := json.Marshal(res)
	pskRaw := string(bytes.Repeat([]byte{0x5a}, 32))
	for what, text := range map[string]string{"approval": string(req), "result": string(resJSON), "activity": string(act), "log": logs.String()} {
		if strings.Contains(text, psk) || strings.Contains(text, pskRaw) {
			t.Errorf("the %s carries the PSK: %s", what, text)
		}
	}
	if !strings.Contains(logs.String(), "PSK: yes") {
		t.Errorf("log lacks the summary: %s", logs.String())
	}

	// Without a PSK the summary says so.
	f.mu.Lock()
	f.allow = false
	f.mu.Unlock()
	noPSK := strings.Replace(pskConfig(psk), "PresharedKey = "+psk+"\n", "", 1)
	_, err = tool(t, e, ctx, assistUID, ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: "home", Config: noPSK})
	wantCode(t, err, ipc.CodeDenied)
	f.mu.Lock()
	last := f.requests[len(f.requests)-1].Summary
	f.mu.Unlock()
	if !strings.Contains(last, "PSK: no") {
		t.Fatalf("summary %q, want PSK: no", last)
	}
	if _, err := e.m.statuses("home"); err == nil {
		t.Fatal("a refused tunnel was added")
	}
}

func TestAddTunnelNonAdminForbidden(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true, notAdmin: true})
	f := &fakeApprover{allow: true}
	grantAssist(t, e, f, assistUID, allGroups())
	_, err := tool(t, e, context.Background(), assistUID, ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: tunName, Config: pskConfig(testPublic)})
	wantCode(t, err, ipc.CodeForbidden)
	wantResult(t, e, assistUID, ipc.ToolAddTunnel, "error: forbidden")
	f.mu.Lock()
	n := len(f.requests)
	f.mu.Unlock()
	if n != 0 {
		t.Fatalf("asked %d times for a forbidden action", n)
	}
	if _, err := e.m.statuses(tunName); err == nil {
		t.Fatal("tunnel added")
	}
}

// connectEnv is a connectable office tunnel for card A behind the real
// agent of uidA, and f as uidA's assist app.
func connectEnv(t *testing.T, f *fakeApprover) *env {
	t.Helper()
	e := newEnv(t, envOpts{present: []uint32{serialA}})
	srv := newServer(t, e.b.pub(serialA), "10.0.0.2")
	e.add(e.config([]keyref.Ref{refA}, []string{"10.0.0.2"}, srv, ""))
	e.allow(uidA) // uidA's own tunnel: its agent connects as a user
	e.waitCard(serialA, true)
	grantAssist(t, e, f, uidA, allGroups())
	return e
}

func TestConnectNeedsApproval(t *testing.T) {
	f := &fakeApprover{allow: false}
	e := connectEnv(t, f)
	ctx := context.Background()
	_, err := tool(t, e, ctx, uidA, ipc.ToolConnect, ipc.TunnelName{Name: tunName})
	wantCode(t, err, ipc.CodeDenied)
	wantResult(t, e, uidA, ipc.ToolConnect, "denied")
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q after a refusal", st.State)
	}
	if n := e.p.count(); n != 0 {
		t.Fatalf("PIN asked %d times after a refusal", n)
	}

	f.mu.Lock()
	f.allow = true
	f.mu.Unlock()
	res, err := tool(t, e, ctx, uidA, ipc.ToolConnect, ipc.TunnelName{Name: tunName})
	if err != nil {
		t.Fatal(err)
	}
	var st ipc.TunnelStatus
	if err := json.Unmarshal(res.Data, &st); err != nil || st.State != StateConnected {
		t.Fatalf("result %s, %v", res.Data, err)
	}
	wantResult(t, e, uidA, ipc.ToolConnect, "done")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || f.requests[1].Tool != ipc.ToolConnect || !strings.Contains(f.requests[1].Summary, tunName) {
		t.Fatalf("approval requests %+v", f.requests)
	}
}

func TestDisconnectNoApproval(t *testing.T) {
	f := &fakeApprover{allow: true}
	e := connectEnv(t, f)
	if st := e.connect(); st.State != StateConnected {
		t.Fatalf("state %q", st.State)
	}
	f.mu.Lock()
	f.allow = false // would refuse, if asked
	f.mu.Unlock()
	res, err := tool(t, e, context.Background(), uidA, ipc.ToolDisconnect, ipc.TunnelName{Name: tunName})
	if err != nil {
		t.Fatal(err)
	}
	var st ipc.TunnelStatus
	if err := json.Unmarshal(res.Data, &st); err != nil || st.State != StateDisconnected {
		t.Fatalf("result %s, %v", res.Data, err)
	}
	wantResult(t, e, uidA, ipc.ToolDisconnect, "done")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 {
		t.Fatalf("disconnect asked for approval %d times", len(f.requests))
	}
}

// The MCP client goes away while the connect waits for the PIN: the
// connect is abandoned and recorded as cancelled.
func TestCallCancelledByClient(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	k := otherKey(t)
	gate := make(chan struct{}) // the PIN is never typed
	t.Cleanup(func() { close(gate) })
	fa := newLyingAgent(t, e, assistUID, k.PublicKey(), k, gate, serialA)
	pub := k.PublicKey()
	cfg := fmt.Sprintf("[Interface]\n[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 10.0.0.1/32\n",
		refA, base64.StdEncoding.EncodeToString(pub[:]), testPublic)
	if err := e.m.add(tunName, cfg, assistUID); err != nil {
		t.Fatal(err)
	}
	f := &fakeApprover{allow: true}
	grantAssist(t, e, f, assistUID, allGroups())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := tool(t, e, ctx, assistUID, ipc.ToolConnect, ipc.TunnelName{Name: tunName})
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for fa.x25519s.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the connect never asked for the PIN")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		wantCode(t, err, ipc.CodeCancelled)
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled call did not return")
	}
	wantResult(t, e, assistUID, ipc.ToolConnect, "cancelled")
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q, want disconnected", st.State)
	}
}

// Turning access off while the PIN is awaited abandons the connect too.
func TestConnectRevokedWhileWaitingForPIN(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	k := otherKey(t)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	fa := newLyingAgent(t, e, assistUID, k.PublicKey(), k, gate, serialA)
	pub := k.PublicKey()
	cfg := fmt.Sprintf("[Interface]\n[Identity]\nKeyRef = %s\nPublicKey = %s\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 10.0.0.1/32\n",
		refA, base64.StdEncoding.EncodeToString(pub[:]), testPublic)
	if err := e.m.add(tunName, cfg, assistUID); err != nil {
		t.Fatal(err)
	}
	grantAssist(t, e, &fakeApprover{allow: true}, assistUID, allGroups())
	done := make(chan error, 1)
	go func() {
		_, err := tool(t, e, context.Background(), assistUID, ipc.ToolConnect, ipc.TunnelName{Name: tunName})
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for fa.x25519s.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the connect never asked for the PIN")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.m.assist.revoke(assistUID)
	select {
	case err := <-done:
		wantCode(t, err, ipc.CodeDenied)
	case <-time.After(5 * time.Second):
		t.Fatal("the revoked call did not return")
	}
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q, want disconnected", st.State)
	}
}

func progress(t *testing.T, e *env, uid uint32, args any) ipc.AssistProgress {
	t.Helper()
	res, err := tool(t, e, context.Background(), uid, ipc.ToolSetupProgress, args)
	if err != nil {
		t.Fatal(err)
	}
	var p ipc.AssistProgress
	if err := json.Unmarshal(res.Data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func steps(p ipc.AssistProgress) string {
	var b []string
	for _, s := range p.Steps {
		b = append(b, s.ID+" "+s.State)
	}
	return strings.Join(b, ", ")
}

func TestSetupProgressFromFacts(t *testing.T) {
	// A card with a key, no tunnel.
	f := &fakeApprover{cards: []ipc.CardEntry{{Serial: serialA, Supported: true, Keys: []string{refA.String()}}}}
	e, _ := assistEnv(t, f)
	p := progress(t, e, assistUID, nil)
	want := "card_ready done, key_created done, backup_offered unknown, server_added unknown, server_info_entered pending, connected pending"
	if p.Path != "owner" || steps(p) != want {
		t.Fatalf("progress %s %s, want owner %s", p.Path, steps(p), want)
	}
	wantResult(t, e, assistUID, ipc.ToolSetupProgress, "done")

	// The invited path, for a tunnel that is defined but never connected.
	if err := e.m.add(tunName, pskConfig(testPublic), assistUID); err != nil {
		t.Fatal(err)
	}
	p = progress(t, e, assistUID, ipc.AssistProgressArgs{Path: "invited", Tunnel: tunName})
	want = "card_ready done, key_created done, backup_offered done, pubkey_shared done, server_info_entered done, connected pending"
	if p.Path != "invited" || p.Tunnel != tunName || steps(p) != want {
		t.Fatalf("progress %s %s, want invited %s", p.Path, steps(p), want)
	}

	// A plugged card without a key.
	f.mu.Lock()
	f.cards = []ipc.CardEntry{{Serial: serialA, Supported: true}}
	f.mu.Unlock()
	p = progress(t, e, assistUID, ipc.AssistProgressArgs{Tunnel: "other"})
	want = "card_ready done, key_created pending, backup_offered unknown, server_added unknown, server_info_entered pending, connected pending"
	if steps(p) != want {
		t.Fatalf("progress %s, want %s", steps(p), want)
	}

	// What is seen is reported as it is: a card without a key is pending
	// even though the tunnel exists; the unseen steps before the tunnel
	// are done.
	p = progress(t, e, assistUID, ipc.AssistProgressArgs{Tunnel: tunName})
	want = "card_ready done, key_created pending, backup_offered done, server_added done, server_info_entered done, connected pending"
	if steps(p) != want {
		t.Fatalf("progress %s, want %s", steps(p), want)
	}
	// No card plugged in: card_ready is pending too.
	f.mu.Lock()
	f.cards = []ipc.CardEntry{}
	f.mu.Unlock()
	p = progress(t, e, assistUID, ipc.AssistProgressArgs{Tunnel: tunName})
	want = "card_ready pending, key_created pending, backup_offered done, server_added done, server_info_entered done, connected pending"
	if steps(p) != want {
		t.Fatalf("progress %s, want %s", steps(p), want)
	}

	_, err := tool(t, e, context.Background(), assistUID, ipc.ToolSetupProgress, ipc.AssistProgressArgs{Path: "explore"})
	wantCode(t, err, ipc.CodeBadRequest)
}

// Without the app the cards cannot be seen: status says so, and progress
// reports the card steps from what can be seen.
func TestStatusAndProgressWithoutApp(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	if err := e.m.add(tunName, pskConfig(testPublic), assistUID); err != nil {
		t.Fatal(err)
	}
	// Access is open, but its owner is not an app (no CapAssist).
	dc := connPairWith(t, e, nil)
	e.m.agentRegister(dc, assistUID, nil)
	if err := e.m.assist.set(assistUID, dc, ipc.AssistGrant{Minutes: 60, Groups: allGroups()}, time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := tool(t, e, context.Background(), assistUID, ipc.ToolStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var st ipc.AssistStatus
	if err := json.Unmarshal(res.Data, &st); err != nil {
		t.Fatal(err)
	}
	if !st.CardsUnavailable || len(st.Cards) != 0 || len(st.Tunnels) != 1 || st.Tunnels[0].Name != tunName {
		t.Fatalf("status %s", res.Data)
	}
	if strings.Contains(string(res.Data), testPublic) {
		t.Fatalf("status carries the PSK: %s", res.Data)
	}
	p := progress(t, e, assistUID, nil)
	want := "card_ready done, key_created done, backup_offered done, server_added done, server_info_entered done, connected pending"
	if steps(p) != want {
		t.Fatalf("progress %s, want %s", steps(p), want)
	}
}

func TestStatusListsCards(t *testing.T) {
	f := &fakeApprover{}
	e, _ := assistEnv(t, f)
	res, err := tool(t, e, context.Background(), assistUID, ipc.ToolStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var st ipc.AssistStatus
	if err := json.Unmarshal(res.Data, &st); err != nil {
		t.Fatal(err)
	}
	if st.CardsUnavailable || len(st.Cards) != 1 || st.Cards[0].Serial != serialA || st.Tunnels == nil {
		t.Fatalf("status %s", res.Data)
	}
}

func TestAssistStepsPaths(t *testing.T) {
	if got := AssistSteps("owner"); len(got) != 6 || got[3] != "server_added" {
		t.Fatalf("owner %v", got)
	}
	if got := AssistSteps("invited"); len(got) != 6 || got[3] != "pubkey_shared" {
		t.Fatalf("invited %v", got)
	}
	if got := AssistSteps("explore"); got != nil {
		t.Fatalf("explore %v", got)
	}
}

// A key the person never finishes (the PIN is not typed) ends after
// cardKeygenTimeout, without a result.
func TestCreateKeyTimesOut(t *testing.T) {
	prev := cardKeygenTimeout
	cardKeygenTimeout = 50 * time.Millisecond
	t.Cleanup(func() { cardKeygenTimeout = prev })
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	f := &fakeApprover{allow: true, keygen: func(ipc.KeygenRequest) (ipc.KeygenResult, error) {
		<-never
		return ipc.KeygenResult{}, nil
	}}
	e, _ := assistEnv(t, f)
	start := time.Now()
	_, err := tool(t, e, context.Background(), assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA})
	wantCode(t, err, ipc.CodeUnavailable)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("returned after %v", d)
	}
	wantResult(t, e, assistUID, ipc.ToolCreateKey, "error: unavailable")
	f.mu.Lock()
	id := f.keygenIDs[0]
	if len(f.notices) != 0 || id == "" {
		t.Fatalf("notices %v, keygen ID %q after a timeout", f.notices, id)
	}
	f.mu.Unlock()
	// The app is told to give the key up.
	f.waitAborts(t, id)
}

// Access closing while the PIN and PUK are typed abandons the key, and the
// app is told so.
func TestCreateKeyRevokedAbortsKeygen(t *testing.T) {
	started := make(chan struct{})
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	f := &fakeApprover{allow: true, keygen: func(ipc.KeygenRequest) (ipc.KeygenResult, error) {
		close(started)
		<-never
		return ipc.KeygenResult{}, nil
	}}
	e, _ := assistEnv(t, f)
	done := make(chan error, 1)
	go func() {
		_, err := tool(t, e, context.Background(), assistUID, ipc.ToolCreateKey, ipc.AssistKeyArgs{Serial: serialA})
		done <- err
	}()
	<-started
	e.m.assist.revoke(assistUID)
	select {
	case err := <-done:
		wantCode(t, err, ipc.CodeDenied)
	case <-time.After(5 * time.Second):
		t.Fatal("create_key still waits after the revoke")
	}
	f.mu.Lock()
	id := f.keygenIDs[0]
	f.mu.Unlock()
	f.waitAborts(t, id)
}

// Text that the agent controls reaches the approval window and the
// activity list only as validated, printable parts: no bidi override or
// zero-width character can disguise it.
func TestSummaryAndClientArePrintable(t *testing.T) {
	f := &fakeApprover{allow: true}
	e, _ := assistEnv(t, f)
	ctx := context.Background()
	call := func(client, name string, args any) error {
		_, err := e.m.assistCall(ctx, nil, assistUID, ipc.AssistCall{Client: client, Tool: name, Args: toolArgs(t, args)})
		return err
	}
	evil := []string{"\u202e", "\u200b", "\u2066", "\ufeff"}
	// An endpoint host that is not a plain DNS name is refused before any
	// approval.
	for _, bad := range []string{"vpn\u202eexample.com", "vpn\u200b.example.com", "vpn example.com"} {
		cfg := strings.Replace(pskConfig(testPublic), "vpn.example.com", bad, 1)
		wantCode(t, call("c", ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: tunName, Config: cfg}), ipc.CodeBadRequest)
	}
	// A tunnel name outside the daemon's rules never reaches a summary.
	wantCode(t, call("c", ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: "of\u202efice", Config: pskConfig(testPublic)}), ipc.CodeBadRequest)
	wantCode(t, call("c", ipc.ToolConnect, ipc.TunnelName{Name: "of\u202efice"}), ipc.CodeNotFound)
	f.mu.Lock()
	n := len(f.requests)
	f.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d approvals for refused input", n)
	}
	// IP endpoints are shown normalised; the client name loses its
	// non-printing characters.
	cfg := strings.Replace(pskConfig(testPublic), "vpn.example.com:51820", "[2001:DB8::1]:51820", 1)
	if err := call("Code\u202eedoC\u200b\u2066 x\n", ipc.ToolAddTunnel, ipc.AssistTunnelArgs{Name: tunName, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	r := f.requests[0]
	f.mu.Unlock()
	if r.Client != "CodeedoC x" {
		t.Fatalf("client %q", r.Client)
	}
	if !strings.Contains(r.Summary, "[2001:db8::1]:51820") || !strings.Contains(r.Summary, `"`+tunName+`"`) {
		t.Fatalf("summary %q", r.Summary)
	}
	act, _ := json.Marshal(e.m.assist.activity(assistUID))
	for _, text := range []string{r.Client, r.Summary, string(act)} {
		for _, c := range evil {
			if strings.Contains(text, c) || strings.ContainsRune(text, []rune(c)[0]) {
				t.Fatalf("%q carries %+q", text, c)
			}
		}
	}
}

func TestClientName(t *testing.T) {
	for in, want := range map[string]string{
		"Claude Code":            "Claude Code",
		"a\u202eb\u200cc\u200bd": "abcd",
		"":                       "unknown",
		"\u200b\u202e":           "unknown",
		strings.Repeat("x", 100): strings.Repeat("x", 64),
	} {
		if got := clientName(in); got != want {
			t.Errorf("clientName(%+q) = %+q, want %+q", in, got, want)
		}
	}
}

// An administrator's agent is not an administrator: it takes down only
// tunnels its user may take down as a user.
func TestAgentDisconnectIsNotAdmin(t *testing.T) {
	f := &fakeApprover{allow: true}
	e := connectEnv(t, f) // everyone is an administrator here
	if st := e.connect(); st.State != StateConnected {
		t.Fatalf("state %q", st.State)
	}
	other := &fakeApprover{allow: true}
	grantAssist(t, e, other, assistUID, allGroups())
	_, err := tool(t, e, context.Background(), assistUID, ipc.ToolDisconnect, ipc.TunnelName{Name: tunName})
	wantCode(t, err, ipc.CodeForbidden)
	wantResult(t, e, assistUID, ipc.ToolDisconnect, "error: forbidden")
	if st := e.status(); st.State != StateConnected {
		t.Fatalf("state %q after another user's agent disconnect", st.State)
	}
	// The administrator itself still can, through the CLI.
	if err := e.call(ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: tunName}, nil); err != nil {
		t.Fatal(err)
	}
}

// An administrator's agent connects with its user's own rights: a tunnel
// that only another user may use is refused as for any user, before a PIN
// is asked of anyone.
func TestAgentConnectIsNotAdmin(t *testing.T) {
	f := &fakeApprover{allow: true}
	e := connectEnv(t, f) // everyone is an administrator; only uidA may use it
	other := &fakeApprover{allow: true}
	grantAssist(t, e, other, assistUID, allGroups())
	_, err := tool(t, e, context.Background(), assistUID, ipc.ToolConnect, ipc.TunnelName{Name: tunName})
	wantCode(t, err, ipc.CodeForbidden)
	if want := fmt.Sprintf(msg.DaemonNotAllowedUserFmt, tunName); err.(*ipc.Error).Message != want {
		t.Fatalf("message %q, want the user refusal %q", err.(*ipc.Error).Message, want)
	}
	wantResult(t, e, assistUID, ipc.ToolConnect, "error: forbidden")
	if st := e.status(); st.State != StateDisconnected {
		t.Fatalf("state %q after another user's agent connect", st.State)
	}
	if n := e.p.count(); n != 0 {
		t.Fatalf("PIN asked %d times", n)
	}
	// The same administrator through the CLI path still may.
	if _, err := e.m.requestConnect(context.Background(), assistUID, tunName); err != nil {
		t.Fatalf("administrator connect: %v", err)
	}
}
