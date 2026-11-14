package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Assistant is what the desktop app offers the daemon for agent access: the
// approval window and the card operations it runs for setup. The agent
// passes requests through; the Assistant asks the user and talks to the
// card. Its errors must not carry a PIN, PUK, management key or private key.
type Assistant interface {
	// Approve shows the approval window for r and reports whether the user
	// allowed it. ctx ends when the daemon connection does.
	Approve(ctx context.Context, r ipc.ApproveRequest) (bool, error)
	// Cards lists the present cards.
	Cards() ([]ipc.CardEntry, error)
	// Keygen makes a new key in slot of the card serial and returns its
	// KeyRef string and public key.
	Keygen(ctx context.Context, serial uint32, slot uint8) (ref string, public [32]byte, err error)
	// Notice shows the guided step step (a desktop.StepID value).
	Notice(step string)
	// Abort says the daemon no longer waits for the request id (an
	// ApproveRequest.ID or KeygenRequest.ID): close its approval window or
	// give up its key. The agent has already cancelled the request's ctx.
	// An unknown id is ignored.
	Abort(id string)
}

// inflight is the requests of the daemon that the Assistant is working on,
// by ID, so assist.abort can cancel them.
type inflight struct {
	mu sync.Mutex
	m  map[string]context.CancelFunc
}

// start returns ctx bound to id until done is called. An empty id cannot
// be aborted.
func (f *inflight) start(ctx context.Context, id string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	if id == "" {
		return ctx, cancel
	}
	f.mu.Lock()
	if f.m == nil {
		f.m = map[string]context.CancelFunc{}
	}
	f.m[id] = cancel
	f.mu.Unlock()
	return ctx, func() {
		f.mu.Lock()
		delete(f.m, id)
		f.mu.Unlock()
		cancel()
	}
}

func (f *inflight) cancel(id string) {
	f.mu.Lock()
	cancel := f.m[id]
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// WithAssistant makes the agent offer s to the daemon: agent.register then
// reports ipc.CapAssist, and the daemon's card.list, card.keygen,
// assist.approve and assist.notice requests go to s. Call it before Run.
// The CLI agent has no Assistant.
func (a *Agent) WithAssistant(s Assistant) *Agent {
	a.assist = s
	return a
}

// Call calls method on the daemon over the agent's current, registered
// connection. It returns ipc.ErrClosed when the agent is not connected.
func (a *Agent) Call(ctx context.Context, method string, params, result any) error {
	c := a.conn.Load()
	if c == nil {
		return ipc.ErrClosed
	}
	return c.Call(ctx, method, params, result)
}

// handleAssist registers the daemon's requests that go to the Assistant.
func (a *Agent) handleAssist(c *ipc.Conn) {
	s := a.assist
	var running inflight
	c.Handle(ipc.MethodAssistApprove, func(ctx context.Context, _ uint32, params json.RawMessage) (any, error) {
		var r ipc.ApproveRequest
		if err := decodeParams(params, &r); err != nil {
			return nil, err
		}
		ctx, done := running.start(ctx, r.ID)
		defer done()
		allow, err := s.Approve(ctx, r)
		if err != nil {
			log.Printf("agent: assist.approve %s: %v", r.Tool, err)
			return nil, assistErr(err)
		}
		return ipc.ApproveResult{Allow: allow}, nil
	})
	c.Handle(ipc.MethodCardList, func(context.Context, uint32, json.RawMessage) (any, error) {
		cards, err := s.Cards()
		if err != nil {
			log.Printf("agent: card.list: %v", err)
			return nil, assistErr(err)
		}
		if cards == nil {
			cards = []ipc.CardEntry{}
		}
		return ipc.CardListResult{Cards: cards}, nil
	})
	c.Handle(ipc.MethodCardKeygen, func(ctx context.Context, _ uint32, params json.RawMessage) (any, error) {
		var r ipc.KeygenRequest
		if err := decodeParams(params, &r); err != nil {
			return nil, err
		}
		ctx, done := running.start(ctx, r.ID)
		defer done()
		ref, pub, err := s.Keygen(ctx, r.Serial, r.Slot)
		if err != nil {
			log.Printf("agent: card.keygen %d slot %#x: %v", r.Serial, r.Slot, err)
			return nil, assistErr(err)
		}
		return ipc.KeygenResult{Ref: ref, Public: base64.StdEncoding.EncodeToString(pub[:])}, nil
	})
	c.Handle(ipc.MethodAssistNotice, func(_ context.Context, _ uint32, params json.RawMessage) (any, error) {
		var n ipc.AssistNotice
		if err := decodeParams(params, &n); err != nil {
			return nil, err
		}
		s.Notice(n.Step)
		return nil, nil
	})
	c.Handle(ipc.MethodAssistAbort, func(_ context.Context, _ uint32, params json.RawMessage) (any, error) {
		var r ipc.AssistAbort
		if err := decodeParams(params, &r); err != nil {
			return nil, err
		}
		running.cancel(r.ID)
		s.Abort(r.ID)
		return nil, nil
	})
}

func decodeParams(params json.RawMessage, v any) error {
	if len(params) == 0 || json.Unmarshal(params, v) != nil {
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.AgentBadRequest}
	}
	return nil
}

// assistErr passes an Assistant's *ipc.Error through and maps other errors
// like key requests do.
func assistErr(err error) error {
	var ie *ipc.Error
	if errors.As(err, &ie) {
		return ie
	}
	return userErr(err)
}
