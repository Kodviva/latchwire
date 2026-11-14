//go:build !demo

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyref"
)

// fakeUI stands in for the window: Approve and KeygenFor wait for their
// ctx when block is set.
type fakeUI struct {
	mu       sync.Mutex
	block    bool
	started  chan string
	approves int
	keygens  int
	keyErr   error
	notices  []string
}

func (f *fakeUI) wait(ctx context.Context, id string) {
	if f.block {
		f.started <- id
		<-ctx.Done()
	}
}

func (f *fakeUI) Approve(ctx context.Context, r ipc.ApproveRequest) (bool, error) {
	f.mu.Lock()
	f.approves++
	f.mu.Unlock()
	f.wait(ctx, r.ID)
	return ctx.Err() == nil, nil
}

func (f *fakeUI) CardList() ([]ipc.CardEntry, error) {
	return []ipc.CardEntry{{Serial: 1, Fresh: true}}, nil
}

func (f *fakeUI) KeygenFor(ctx context.Context, serial uint32, slot uint8) (desktop.Key, error) {
	f.mu.Lock()
	f.keygens++
	f.mu.Unlock()
	f.wait(ctx, "k")
	if ctx.Err() != nil {
		return desktop.Key{}, desktop.ErrCancelled
	}
	if f.keyErr != nil {
		return desktop.Key{}, f.keyErr
	}
	return desktop.Key{Ref: keyref.Ref{Serial: serial, Slot: slot}, Public: [32]byte{7}}, nil
}

func (f *fakeUI) Notice(step string) { f.notices = append(f.notices, step) }

func wantCancelled(t *testing.T, err error) {
	t.Helper()
	var ie *ipc.Error
	if !errors.As(err, &ie) || ie.Code != ipc.CodeCancelled {
		t.Fatalf("err %v, want %s", err, ipc.CodeCancelled)
	}
}

// The agent cancels a request's ctx on assist.abort; the window and the
// forms close with it.
func TestCancelledRequestsRefuse(t *testing.T) {
	f := &fakeUI{block: true, started: make(chan string, 1)}
	s := newAssistant(f)
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan bool, 1)
	go func() {
		ok, _ := s.Approve(ctx, ipc.ApproveRequest{ID: "a1"})
		res <- ok
	}()
	<-f.started
	cancel()
	select {
	case ok := <-res:
		if ok {
			t.Fatal("allowed after the request ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Approve still waits after the request ended")
	}
}

func TestKeygenCancelled(t *testing.T) {
	f := &fakeUI{}
	s := newAssistant(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := s.Keygen(ctx, 1, 0x82)
	wantCancelled(t, err)

	f.keyErr = desktop.ErrCancelled
	_, _, err = s.Keygen(context.Background(), 1, 0x82)
	wantCancelled(t, err)

	f.keyErr = errors.New("wrong PIN, 2 attempts left")
	if _, _, err = s.Keygen(context.Background(), 1, 0x82); err != f.keyErr {
		t.Fatalf("err %v", err)
	}

	f.keyErr = nil
	ref, pub, err := s.Keygen(context.Background(), 1, 0x83)
	if err != nil || ref != "piv://1/83" || pub != [32]byte{7} {
		t.Fatalf("%q %v %v", ref, pub, err)
	}
}

func TestAssistantPassesCardsAndNotices(t *testing.T) {
	f := &fakeUI{}
	s := newAssistant(f)
	cards, err := s.Cards()
	if err != nil || len(cards) != 1 || !cards[0].Fresh {
		t.Fatalf("%+v %v", cards, err)
	}
	s.Notice("key_created")
	if len(f.notices) != 1 || f.notices[0] != "key_created" {
		t.Fatal(f.notices)
	}
}
