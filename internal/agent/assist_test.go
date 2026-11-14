package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
)

// fakeAssistant records what the daemon asked for.
type fakeAssistant struct {
	mu       sync.Mutex
	allow    bool
	approved []ipc.ApproveRequest
	keygens  [][2]uint32 // serial, slot
	notices  []string
	cards    []ipc.CardEntry
	pub      [32]byte
	aborts   []string
	// block, if set, makes Approve and Keygen wait for their ctx.
	block   bool
	started chan struct{}
}

func (f *fakeAssistant) wait(ctx context.Context) {
	f.mu.Lock()
	block, started := f.block, f.started
	f.mu.Unlock()
	if block {
		started <- struct{}{}
		<-ctx.Done()
	}
}

func (f *fakeAssistant) Abort(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aborts = append(f.aborts, id)
}

func (f *fakeAssistant) Approve(ctx context.Context, r ipc.ApproveRequest) (bool, error) {
	f.wait(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approved = append(f.approved, r)
	return f.allow, nil
}

func (f *fakeAssistant) Cards() ([]ipc.CardEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.cards), nil
}

func (f *fakeAssistant) Keygen(ctx context.Context, serial uint32, slot uint8) (string, [32]byte, error) {
	f.wait(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keygens = append(f.keygens, [2]uint32{serial, uint32(slot)})
	if serial != serialA {
		return "", [32]byte{}, &ipc.Error{Code: ipc.CodeUnavailable, Message: "no such card"}
	}
	return "yubikey:40727512/0x82", f.pub, nil
}

func (f *fakeAssistant) Notice(step string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notices = append(f.notices, step)
}

func startWith(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
}

func startAssist(t *testing.T, d *daemon, f *fakeAssistant) (*Agent, *ipc.Conn) {
	t.Helper()
	a := New(d.path, newFakeBackend(t, serialA), &fakePrompter{}, poll).WithAssistant(f)
	startWith(t, a)
	c, reg := d.conn()
	if !slices.Equal(reg.Caps, []string{ipc.CapAssist}) {
		t.Fatalf("caps %v, want [%s]", reg.Caps, ipc.CapAssist)
	}
	return a, c
}

func TestAssistantRegistersCaps(t *testing.T) {
	d := newDaemon(t)
	startAssist(t, d, &fakeAssistant{})

	d2 := newDaemon(t)
	startAgent(t, d2, newFakeBackend(t, serialA), &fakePrompter{})
	c, reg := d2.conn()
	if len(reg.Caps) != 0 {
		t.Fatalf("caps %v without an Assistant, want none", reg.Caps)
	}
	// Without an Assistant the agent serves none of its methods.
	err := c.Call(ctx5(t), ipc.MethodCardList, nil, nil)
	wantCode(t, err, ipc.CodeNotFound)
}

func TestKeygenRequestReachesAssistant(t *testing.T) {
	d := newDaemon(t)
	f := &fakeAssistant{pub: [32]byte{1, 2, 3}}
	_, c := startAssist(t, d, f)

	var res ipc.KeygenResult
	if err := c.Call(ctx5(t), ipc.MethodCardKeygen, ipc.KeygenRequest{Serial: serialA, Slot: 0x82}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Ref != "yubikey:40727512/0x82" || res.Public != base64.StdEncoding.EncodeToString(f.pub[:]) {
		t.Fatalf("result %+v", res)
	}
	err := c.Call(ctx5(t), ipc.MethodCardKeygen, ipc.KeygenRequest{Serial: serialB, Slot: 0x82}, &res)
	wantCode(t, err, ipc.CodeUnavailable)
	f.mu.Lock()
	got := slices.Clone(f.keygens)
	f.mu.Unlock()
	if !slices.Equal(got, [][2]uint32{{serialA, 0x82}, {serialB, 0x82}}) {
		t.Fatalf("keygens %v", got)
	}
	wantCode(t, c.Call(ctx5(t), ipc.MethodCardKeygen, json.RawMessage(`"x"`), nil), ipc.CodeBadRequest)
}

func TestApproveRequestReachesAssistant(t *testing.T) {
	d := newDaemon(t)
	f := &fakeAssistant{allow: true}
	_, c := startAssist(t, d, f)

	req := ipc.ApproveRequest{Client: "test-client", Tool: "create_key", Summary: "new key on 40727512", Fresh: true}
	var res ipc.ApproveResult
	if err := c.Call(ctx5(t), ipc.MethodAssistApprove, req, &res); err != nil || !res.Allow {
		t.Fatalf("allow: %+v, %v", res, err)
	}
	f.mu.Lock()
	f.allow = false
	f.mu.Unlock()
	if err := c.Call(ctx5(t), ipc.MethodAssistApprove, req, &res); err != nil || res.Allow {
		t.Fatalf("deny: %+v, %v", res, err)
	}
	f.mu.Lock()
	got := slices.Clone(f.approved)
	f.mu.Unlock()
	if len(got) != 2 || got[0] != req {
		t.Fatalf("approved %+v", got)
	}
}

func TestAssistCardsAndNotice(t *testing.T) {
	d := newDaemon(t)
	f := &fakeAssistant{cards: []ipc.CardEntry{{Serial: serialA, Firmware: "5.7.1", Supported: true, Fresh: true}}}
	_, c := startAssist(t, d, f)

	var res ipc.CardListResult
	if err := c.Call(ctx5(t), ipc.MethodCardList, nil, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Cards) != 1 || res.Cards[0].Serial != serialA || !res.Cards[0].Fresh {
		t.Fatalf("cards %+v", res)
	}
	if err := c.Call(ctx5(t), ipc.MethodAssistNotice, ipc.AssistNotice{Step: "key"}, nil); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	got := slices.Clone(f.notices)
	f.mu.Unlock()
	if !slices.Equal(got, []string{"key"}) {
		t.Fatalf("notices %v", got)
	}
}

func TestAssistCallUsesDaemonConnection(t *testing.T) {
	d := newDaemon(t)
	a := New(d.path, newFakeBackend(t, serialA), &fakePrompter{}, poll).WithAssistant(&fakeAssistant{})
	if err := a.Call(ctx5(t), ipc.MethodAssistActivity, nil, nil); !errors.Is(err, ipc.ErrClosed) {
		t.Fatalf("before Run: %v, want ErrClosed", err)
	}
	startWith(t, a)
	c, _ := d.conn()
	c.Handle(ipc.MethodAssistActivity, func(context.Context, uint32, json.RawMessage) (any, error) {
		return ipc.AssistActivity{Entries: []ipc.ActivityEntry{{Tool: "list_cards"}}}, nil
	})
	var act ipc.AssistActivity
	waitFor(t, "Call over the registered connection", func() bool {
		return a.Call(ctx5(t), ipc.MethodAssistActivity, nil, &act) == nil
	})
	if len(act.Entries) != 1 || act.Entries[0].Tool != "list_cards" {
		t.Fatalf("activity %+v", act)
	}
	// The connection ends: Call reports it until the agent is back.
	d.l.Close()
	c.Close()
	waitFor(t, "ErrClosed after the daemon went away", func() bool {
		return errors.Is(a.Call(ctx5(t), ipc.MethodAssistActivity, nil, nil), ipc.ErrClosed)
	})
}

// assist.abort cancels the named request's ctx and reaches the Assistant.
func TestAbortReachesAssistant(t *testing.T) {
	d := newDaemon(t)
	f := &fakeAssistant{block: true, started: make(chan struct{}, 1)}
	_, c := startAssist(t, d, f)
	for _, call := range []struct {
		method string
		params any
	}{
		{ipc.MethodAssistApprove, ipc.ApproveRequest{ID: "a1", Tool: "connect"}},
		{ipc.MethodCardKeygen, ipc.KeygenRequest{ID: "k1", Serial: serialA, Slot: 0x82}},
	} {
		done := make(chan error, 1)
		go func() { done <- c.Call(ctx5(t), call.method, call.params, nil) }()
		<-f.started
		id := "a1"
		if call.method == ipc.MethodCardKeygen {
			id = "k1"
		}
		if err := c.Call(ctx5(t), ipc.MethodAssistAbort, ipc.AssistAbort{ID: id}, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s still waits after the abort", call.method)
		}
	}
	// An unknown ID is passed on and harms nothing.
	if err := c.Call(ctx5(t), ipc.MethodAssistAbort, ipc.AssistAbort{ID: "zz"}, nil); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Equal(f.aborts, []string{"a1", "k1", "zz"}) {
		t.Fatalf("aborts %v", f.aborts)
	}
}
