package daemon

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
)

const assistUID = 1000

// fakeApprover is the desktop agent's side of assist.approve and the card
// methods. answer, if set, decides each approval; otherwise allow does.
type fakeApprover struct {
	mu       sync.Mutex
	allow    bool
	answer   func(ctx context.Context) bool
	requests []ipc.ApproveRequest
	notices  []string
	keygens  []ipc.KeygenRequest
}

func (f *fakeApprover) setup(ac *ipc.Conn) {
	ac.Handle(ipc.MethodAssistApprove, func(ctx context.Context, _ uint32, p json.RawMessage) (any, error) {
		var r ipc.ApproveRequest
		if err := json.Unmarshal(p, &r); err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.requests = append(f.requests, r)
		allow, answer := f.allow, f.answer
		f.mu.Unlock()
		if answer != nil {
			allow = answer(ctx)
		}
		return ipc.ApproveResult{Allow: allow}, nil
	})
	ac.Handle(ipc.MethodCardList, func(context.Context, uint32, json.RawMessage) (any, error) {
		return ipc.CardListResult{Cards: []ipc.CardEntry{{Serial: serialA, Supported: true, Fresh: true}}}, nil
	})
	ac.Handle(ipc.MethodCardKeygen, func(_ context.Context, _ uint32, p json.RawMessage) (any, error) {
		var r ipc.KeygenRequest
		if err := json.Unmarshal(p, &r); err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.keygens = append(f.keygens, r)
		f.mu.Unlock()
		return ipc.KeygenResult{Ref: "yubikey:1/0x82", Public: "AAAA"}, nil
	})
	ac.Handle(ipc.MethodAssistNotice, func(_ context.Context, _ uint32, p json.RawMessage) (any, error) {
		var n ipc.AssistNotice
		if err := json.Unmarshal(p, &n); err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.notices = append(f.notices, n.Step)
		f.mu.Unlock()
		return nil, nil
	})
}

// assistEnv is a daemon with one registered assist agent of assistUID and
// open access for it.
func assistEnv(t *testing.T, f *fakeApprover) (*env, *ipc.Conn) {
	t.Helper()
	e := newEnv(t, envOpts{noAgent: true})
	dc := connPairWith(t, e, f.setup)
	e.m.agentRegister(dc, assistUID, nil, ipc.CapAssist)
	if err := e.m.assist.set(assistUID, dc, ipc.AssistGrant{Minutes: 60, Groups: allGroups()}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return e, dc
}

var testApproval = ipc.ApproveRequest{Client: "test-client", Tool: "create_key", Summary: "new key"}

func approveAsync(e *env, ctx context.Context) chan error {
	done := make(chan error, 1)
	go func() { done <- e.m.approve(ctx, assistUID, testApproval) }()
	return done
}

func result(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("approve did not return")
	}
	return nil
}

func TestApproveAllowAndDeny(t *testing.T) {
	f := &fakeApprover{allow: true}
	e, _ := assistEnv(t, f)
	if err := e.m.approve(context.Background(), assistUID, testApproval); err != nil {
		t.Fatalf("allowed: %v", err)
	}
	f.mu.Lock()
	f.allow = false
	f.mu.Unlock()
	wantCode(t, e.m.approve(context.Background(), assistUID, testApproval), ipc.CodeDenied)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || f.requests[0] != testApproval {
		t.Fatalf("requests %+v", f.requests)
	}
}

func TestApproveTimesOutAsDeny(t *testing.T) {
	prev := approveTimeout
	approveTimeout = 50 * time.Millisecond
	t.Cleanup(func() { approveTimeout = prev })
	// The user never answers.
	f := &fakeApprover{answer: func(ctx context.Context) bool { <-ctx.Done(); return true }}
	e, _ := assistEnv(t, f)
	start := time.Now()
	wantCode(t, result(t, approveAsync(e, context.Background())), ipc.CodeDenied)
	if d := time.Since(start); d < approveTimeout {
		t.Fatalf("returned after %v, before the timeout", d)
	}
}

func TestApproveRevokedWhilePending(t *testing.T) {
	started := make(chan struct{})
	answer := make(chan struct{})
	f := &fakeApprover{answer: func(context.Context) bool {
		close(started)
		<-answer
		return true // the user allows, too late
	}}
	e, _ := assistEnv(t, f)
	defer close(answer)
	done := approveAsync(e, context.Background())
	<-started
	e.m.assist.revoke(assistUID)
	wantCode(t, result(t, done), ipc.CodeDenied)
}

// An allow that arrives after the revoke still counts as a refusal.
func TestApproveAllowAfterRevokeIsDenied(t *testing.T) {
	var e *env
	f := &fakeApprover{answer: func(context.Context) bool {
		e.m.assist.revoke(assistUID)
		return true
	}}
	e, _ = assistEnv(t, f)
	wantCode(t, result(t, approveAsync(e, context.Background())), ipc.CodeDenied)
}

func TestApproveWithoutAccessAsksNobody(t *testing.T) {
	f := &fakeApprover{allow: true}
	e, _ := assistEnv(t, f)
	e.m.assist.revoke(assistUID)
	wantCode(t, e.m.approve(context.Background(), assistUID, testApproval), ipc.CodeDenied)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 {
		t.Fatalf("asked %d times without access", len(f.requests))
	}
}

func TestApproveCallerCancelled(t *testing.T) {
	started := make(chan struct{})
	f := &fakeApprover{answer: func(ctx context.Context) bool { close(started); <-ctx.Done(); return true }}
	e, dc := assistEnv(t, f)
	defer dc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := approveAsync(e, ctx)
	<-started
	cancel()
	wantCode(t, result(t, done), ipc.CodeCancelled)
}

func TestApproveAgentLostIsDenied(t *testing.T) {
	started := make(chan struct{})
	f := &fakeApprover{answer: func(ctx context.Context) bool { close(started); <-ctx.Done(); return true }}
	e, dc := assistEnv(t, f)
	done := approveAsync(e, context.Background())
	<-started
	dc.Close()
	wantCode(t, result(t, done), ipc.CodeDenied)
}

func TestNoAssistAgentRefusesApproval(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	wantCode(t, e.m.approve(context.Background(), assistUID, testApproval), ipc.CodeNoApp)
	// An agent without the capability (the CLI agent) is never asked.
	f := &fakeApprover{allow: true}
	dc := connPairWith(t, e, f.setup)
	e.m.agentRegister(dc, assistUID, nil)
	e.m.assist.set(assistUID, nil, ipc.AssistGrant{Groups: allGroups()}, time.Now())
	wantCode(t, e.m.approve(context.Background(), assistUID, testApproval), ipc.CodeNoApp)
	_, err := e.m.cardList(context.Background(), assistUID)
	wantCode(t, err, ipc.CodeNoApp)
	_, err = e.m.cardKeygen(context.Background(), assistUID, serialA, 0x82)
	wantCode(t, err, ipc.CodeNoApp)
	e.m.notify(assistUID, "key") // logged only
	// Another user's assist agent is not this user's app.
	other := connPairWith(t, e, f.setup)
	e.m.agentRegister(other, assistUID+1, nil, ipc.CapAssist)
	wantCode(t, e.m.approve(context.Background(), assistUID, testApproval), ipc.CodeNoApp)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 {
		t.Fatalf("asked %d times", len(f.requests))
	}
}

func TestAssistAgentIsEarliest(t *testing.T) {
	f := &fakeApprover{}
	e, first := assistEnv(t, f)
	second := connPairWith(t, e, f.setup)
	e.m.agentRegister(second, assistUID, nil, ipc.CapAssist)
	if got := e.m.assistAgent(assistUID); got != first {
		t.Fatal("assistAgent is not the earliest registered")
	}
	e.m.dropAgent(first)
	if got := e.m.assistAgent(assistUID); got != second {
		t.Fatal("assistAgent did not fall back to the next one")
	}
	// A connection that makes assist calls is never the app.
	e.m.markAssistCaller(second)
	if got := e.m.assistAgent(assistUID); got != nil {
		t.Fatal("an assist caller was chosen")
	}
}

func TestCardOpsReachAssistAgent(t *testing.T) {
	f := &fakeApprover{}
	e, _ := assistEnv(t, f)
	cards, err := e.m.cardList(context.Background(), assistUID)
	if err != nil || len(cards) != 1 || cards[0].Serial != serialA || !cards[0].Fresh {
		t.Fatalf("cards %+v, %v", cards, err)
	}
	res, err := e.m.cardKeygen(context.Background(), assistUID, serialA, 0x82)
	if err != nil || res.Ref != "yubikey:1/0x82" {
		t.Fatalf("keygen %+v, %v", res, err)
	}
	e.m.notify(assistUID, "key")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.keygens) != 1 || f.keygens[0] != (ipc.KeygenRequest{Serial: serialA, Slot: 0x82}) {
		t.Fatalf("keygens %+v", f.keygens)
	}
	if len(f.notices) != 1 || f.notices[0] != "key" {
		t.Fatalf("notices %v", f.notices)
	}
}
