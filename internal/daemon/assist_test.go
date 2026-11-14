package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
)

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var ie *ipc.Error
	if !errors.As(err, &ie) || ie.Code != code {
		t.Fatalf("error %v, want code %q", err, code)
	}
}

var t0 = time.Date(2026, 11, 14, 14, 0, 0, 0, time.UTC)

func allGroups() []string { return []string{ipc.GroupKeys, ipc.GroupTunnels, ipc.GroupConnect} }

func TestGrantExpires(t *testing.T) {
	var a assistState
	if err := a.set(501, nil, ipc.AssistGrant{Minutes: 15, Groups: allGroups()}, t0); err != nil {
		t.Fatal(err)
	}
	if err := a.allowed(501, ipc.GroupConnect, t0.Add(14*time.Minute+59*time.Second)); err != nil {
		t.Fatalf("at 14:59: %v", err)
	}
	wantCode(t, a.allowed(501, "", t0.Add(15*time.Minute)), ipc.CodeAccessOff)
}

func TestGrantUntilClosedEndsWithOwner(t *testing.T) {
	var a assistState
	owner := &ipc.Conn{}
	if err := a.set(501, owner, ipc.AssistGrant{Minutes: 0, Groups: allGroups()}, t0); err != nil {
		t.Fatal(err)
	}
	if err := a.allowed(501, "", t0.Add(100*time.Hour)); err != nil {
		t.Fatal(err)
	}
	a.dropOwner(&ipc.Conn{}) // someone else's connection
	if err := a.allowed(501, "", t0); err != nil {
		t.Fatal(err)
	}
	a.dropOwner(owner)
	wantCode(t, a.allowed(501, "", t0), ipc.CodeAccessOff)
}

func TestGroupOff(t *testing.T) {
	var a assistState
	if err := a.set(501, nil, ipc.AssistGrant{Groups: []string{ipc.GroupKeys}}, t0); err != nil {
		t.Fatal(err)
	}
	wantCode(t, a.allowed(501, ipc.GroupConnect, t0), ipc.CodeAccessOff)
	if err := a.allowed(501, ipc.GroupKeys, t0); err != nil {
		t.Fatal(err)
	}
	if err := a.allowed(501, "", t0); err != nil {
		t.Fatal(err)
	}
}

func TestGrantIsPerUser(t *testing.T) {
	var a assistState
	if err := a.set(501, nil, ipc.AssistGrant{Minutes: 60, Groups: allGroups()}, t0); err != nil {
		t.Fatal(err)
	}
	wantCode(t, a.allowed(502, "", t0), ipc.CodeAccessOff)
}

func TestBadGrant(t *testing.T) {
	var a assistState
	wantCode(t, a.set(501, nil, ipc.AssistGrant{Minutes: 30, Groups: allGroups()}, t0), ipc.CodeBadRequest)
	wantCode(t, a.set(501, nil, ipc.AssistGrant{Minutes: 15, Groups: []string{"x"}}, t0), ipc.CodeBadRequest)
	wantCode(t, a.allowed(501, "", t0), ipc.CodeAccessOff) // nothing was opened
}

func TestRevoke(t *testing.T) {
	var a assistState
	if err := a.set(501, nil, ipc.AssistGrant{Minutes: 60, Groups: allGroups()}, t0); err != nil {
		t.Fatal(err)
	}
	a.revoke(501)
	wantCode(t, a.allowed(501, "", t0), ipc.CodeAccessOff)
}

func TestActivityKeepsTwenty(t *testing.T) {
	var a assistState
	for i := 0; i < 25; i++ {
		a.record(501, ipc.ActivityEntry{Tool: fmt.Sprint("t", i), Summary: "s", Result: "ok"})
	}
	got := a.activity(501)
	if len(got) != 20 {
		t.Fatalf("%d entries, want 20", len(got))
	}
	if got[0].Tool != "t24" || got[19].Tool != "t5" {
		t.Fatalf("order: first %s last %s", got[0].Tool, got[19].Tool)
	}
	if n := len(a.activity(502)); n != 0 {
		t.Fatalf("other user sees %d entries", n)
	}
}

func TestPendingCancelled(t *testing.T) {
	var a assistState
	owner := &ipc.Conn{}
	cancelled := func(ctx context.Context) bool {
		select {
		case <-ctx.Done():
			return true
		default:
			return false
		}
	}
	open := func() {
		if err := a.set(501, owner, ipc.AssistGrant{Minutes: 60, Groups: allGroups()}, t0); err != nil {
			t.Fatal(err)
		}
	}

	open()
	ctx, release := a.pending(501)
	a.revoke(501)
	if !cancelled(ctx) {
		t.Fatal("revoke did not cancel")
	}
	release()

	open()
	ctx, release = a.pending(501)
	a.dropOwner(owner)
	if !cancelled(ctx) {
		t.Fatal("dropOwner did not cancel")
	}
	release()

	open()
	ctx, release = a.pending(501)
	open() // replaced
	if !cancelled(ctx) {
		t.Fatal("a new grant did not cancel")
	}
	release()

	open()
	ctx, release = a.pending(501)
	other, releaseOther := a.pending(502)
	a.revoke(502)
	if cancelled(ctx) || !cancelled(other) {
		t.Fatal("revoke leaked across users")
	}
	release()
	releaseOther()
	if n := pendingCount(&a); n != 0 {
		t.Fatalf("%d pending contexts leaked", n)
	}
	if cancelled(ctx) {
		// release cancels its own context to free it.
		return
	}
	t.Fatal("release did not free the context")
}

func TestGrantNeedsAssistAgent(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	g := ipc.AssistGrant{Minutes: 15, Groups: allGroups()}
	// A connection that never registered.
	wantCode(t, e.call(ipc.MethodAssistGrant, g, nil), ipc.CodeForbidden)
	// A registered agent without the capability.
	if err := e.call(ipc.MethodAgentRegister, ipc.AgentRegister{}, nil); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.call(ipc.MethodAssistGrant, g, nil), ipc.CodeForbidden)
	// Registering again with the capability.
	var uid uint32
	if err := e.call(ipc.MethodAgentRegister, ipc.AgentRegister{Caps: []string{ipc.CapAssist}}, nil); err != nil {
		t.Fatal(err)
	}
	e.m.mu.Lock()
	for _, a := range e.m.agents {
		uid = a.uid
	}
	e.m.mu.Unlock()
	if err := e.call(ipc.MethodAssistGrant, g, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.call(ipc.MethodAssistRevoke, nil, nil); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.m.assist.allowed(uid, "", time.Now()), ipc.CodeAccessOff)
	var act ipc.AssistActivity
	if err := e.call(ipc.MethodAssistActivity, nil, &act); err != nil {
		t.Fatal(err)
	}
	e.m.assist.record(uid, ipc.ActivityEntry{Tool: "list_cards", Result: "ok"})
	if err := e.call(ipc.MethodAssistActivity, nil, &act); err != nil || len(act.Entries) != 1 || act.Entries[0].Tool != "list_cards" {
		t.Fatalf("activity %+v, %v", act, err)
	}
	// Closing the connection closes access.
	if err := e.call(ipc.MethodAssistGrant, g, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.m.assist.allowed(uid, "", time.Now()); err != nil {
		t.Fatalf("after grant: %v", err)
	}
	e.cli.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := e.m.assist.allowed(uid, "", time.Now())
		if err != nil {
			wantCode(t, err, ipc.CodeAccessOff)
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("access stayed open after the owner closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func pendingCount(a *assistState) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, u := range a.users {
		n += len(u.pending)
	}
	return n
}

func TestSetAfterOwnerGone(t *testing.T) {
	var a assistState
	owner := &ipc.Conn{}
	a.dropOwner(owner)
	// A closed connection cannot own a grant.
	e := newEnv(t, envOpts{noAgent: true})
	closed := e.cli
	closed.Close()
	<-closed.Done()
	wantCode(t, a.set(501, closed, ipc.AssistGrant{Groups: allGroups()}, t0), ipc.CodeAccessOff)
	wantCode(t, a.allowed(501, "", t0), ipc.CodeAccessOff)
}

func TestPendingWithoutGrantIsCancelled(t *testing.T) {
	var a assistState
	ctx, release := a.pending(501)
	if ctx.Err() == nil {
		t.Fatal("no grant: context must be cancelled")
	}
	release()
	a.clock = func() time.Time { return t0.Add(16 * time.Minute) }
	a.set(501, nil, ipc.AssistGrant{Minutes: 15, Groups: allGroups()}, t0)
	ctx, release = a.pending(501)
	defer release()
	if ctx.Err() == nil {
		t.Fatal("expired grant: context must be cancelled")
	}
	if n := pendingCount(&a); n != 0 {
		t.Fatalf("%d leaked", n)
	}
}

func TestGrantRefusedForAssistCaller(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	g := ipc.AssistGrant{Minutes: 15, Groups: allGroups()}
	if err := e.call(ipc.MethodAgentRegister, ipc.AgentRegister{Caps: []string{ipc.CapAssist}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.call(ipc.MethodAssistGrant, g, nil); err != nil {
		t.Fatal(err)
	}
	e.m.mu.Lock()
	var c *ipc.Conn
	var uid uint32
	for k, a := range e.m.agents {
		c, uid = k, a.uid
	}
	e.m.mu.Unlock()
	e.m.markAssistCaller(c)
	wantCode(t, e.m.assist.allowed(uid, "", time.Now()), ipc.CodeAccessOff)
	wantCode(t, e.call(ipc.MethodAssistGrant, g, nil), ipc.CodeForbidden)
}

func TestReregisterWithoutAssistClosesAccess(t *testing.T) {
	e := newEnv(t, envOpts{noAgent: true})
	if err := e.call(ipc.MethodAgentRegister, ipc.AgentRegister{Caps: []string{ipc.CapAssist}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.call(ipc.MethodAssistGrant, ipc.AssistGrant{Groups: allGroups()}, nil); err != nil {
		t.Fatal(err)
	}
	e.m.mu.Lock()
	var uid uint32
	for _, a := range e.m.agents {
		uid = a.uid
	}
	e.m.mu.Unlock()
	if err := e.call(ipc.MethodAgentRegister, ipc.AgentRegister{}, nil); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.m.assist.allowed(uid, "", time.Now()), ipc.CodeAccessOff)
}
