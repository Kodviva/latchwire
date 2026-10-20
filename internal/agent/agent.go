// Package agent is the user-session side of Latchwire. It runs as the
// logged-in user, owns access to the hardware tokens and the PIN prompts,
// and serves the privileged daemon's key.public and key.x25519 requests over
// the daemon's unix socket. It also reports which cards are present.
//
// PIN rules:
//   - The PIN is asked only while serving a daemon request, at most once per
//     request, and only when the card needs it.
//   - A wrong PIN ends that request with an error; asking again happens only
//     with the next request.
//   - With one attempt left the user is warned before being asked; with none
//     left the user is never asked (keyprovider.ErrPINBlocked).
//   - If the card reports that its PIN verification was lost (for example
//     another program reset it) and nobody was asked yet in this request,
//     the operation is retried once, which asks once.
//   - Requests for one card run one at a time. A request that was already
//     waiting when a prompt for that card ended in a wrong PIN or was
//     cancelled gets that same outcome without being asked: the daemon may
//     have queued many requests behind a slow prompt and given up on them,
//     and each mistyped answer would cost a real PIN retry.
//   - A request carrying a deadline (ipc.KeyRequest.Deadline) that passed
//     while it waited ends without asking.
//   - The PIN is passed from the Prompter straight to the provider's prompt
//     callback. It is never logged or kept in any field.
package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Backend is access to the user's hardware tokens; *piv.Backend implements
// it. prompt is called by a provider when the card needs the PIN.
type Backend interface {
	Serials() ([]uint32, error)
	Provider(ref keyref.Ref, prompt func(retriesLeft int) (string, error)) (keyprovider.Provider, error)
}

// Prompter asks the user for the PIN and shows warnings.
type Prompter interface {
	PIN(d keyprovider.Description, retriesLeft int) (string, error)
	Warn(msg string)
}

// callTimeout bounds agent.register and agent.event calls to the daemon.
const callTimeout = 5 * time.Second

// Agent connects to the daemon and serves it. Create it with New.
type Agent struct {
	socket string
	b      Backend
	p      Prompter
	poll   time.Duration

	promptMu sync.Mutex // one prompt on the terminal at a time

	mu      sync.Mutex
	entries map[keyref.Ref]*entry // providers, kept so the card stays verified
	cards   map[uint32]*cardState // by serial; never removed (tiny)
}

// cardState serialises requests for one card and remembers the outcome of
// the last PIN prompt for it.
type cardState struct {
	sem chan struct{} // held for a whole attempt, prompt included

	mu      sync.Mutex
	epoch   uint64 // incremented when a prompt's outcome is known
	outcome error  // nil: the PIN was accepted; else wrong/cancelled/blocked
}

func (cs *cardState) last() (uint64, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.epoch, cs.outcome
}

func (cs *cardState) record(outcome error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.epoch++
	cs.outcome = outcome
}

// testHookWaiting, if set, is called when a request starts waiting for its
// card. Tests only.
var testHookWaiting func()

// New returns an agent for the daemon socket at socketPath. Card presence is
// polled every poll (1 s in production); the same interval paces reconnect
// attempts when the daemon is not reachable.
func New(socketPath string, b Backend, p Prompter, poll time.Duration) *Agent {
	return &Agent{socket: socketPath, b: b, p: p, poll: poll,
		entries: map[keyref.Ref]*entry{}, cards: map[uint32]*cardState{}}
}

// Run connects to the daemon, registers, reports card changes and serves
// key requests until ctx ends; it then returns ctx.Err(). When the
// connection fails or ends, Run reconnects and registers again.
func (a *Agent) Run(ctx context.Context) error {
	defer a.closeAll()
	var lastErr string
	for {
		err := a.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Log a failure once, not on every reconnect attempt.
		if s := fmt.Sprint(err); err != nil && s != lastErr {
			log.Printf("agent: daemon connection: %v", err)
			lastErr = s
		} else if err == nil {
			lastErr = ""
		}
		t := time.NewTimer(a.poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// session is one connection to the daemon. It returns nil when the daemon
// closed the connection.
func (a *Agent) session(ctx context.Context) error {
	c, err := ipc.Dial(a.socket)
	if err != nil {
		return err
	}
	defer c.Close()
	// Only root (the daemon) or this user may receive X25519 results: this
	// user can use the card directly anyway.
	if uid := c.PeerUID(); uid != 0 && int64(uid) != int64(os.Getuid()) {
		return fmt.Errorf(msg.AgentUntrustedDaemonFmt, uid)
	}
	c.Handle(ipc.MethodKeyPublic, a.handlePublic)
	c.Handle(ipc.MethodKeyX25519, func(ctx context.Context, _ uint32, params json.RawMessage) (any, error) {
		return a.handleX25519(ctx, c, params)
	})
	served := make(chan error, 1)
	go func() { served <- c.Serve(ctx) }()

	cur, err := a.serials()
	if err != nil {
		log.Printf("agent: listing cards: %v", err)
	}
	a.dropAbsent(cur)
	if err := a.call(ctx, c, ipc.MethodAgentRegister, ipc.AgentRegister{Serials: nonNil(cur)}); err != nil {
		return fmt.Errorf("agent.register: %w", err)
	}
	log.Printf("agent: registered with %d card(s)", len(cur))

	last := cur
	pollFailed := false
	tick := time.NewTicker(a.poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-served:
			return err
		case <-tick.C:
		}
		cur, err := a.serials()
		if err != nil {
			if !pollFailed {
				log.Printf("agent: listing cards: %v", err)
				pollFailed = true
			}
			continue
		}
		pollFailed = false
		removed, inserted := diff(last, cur)
		last = cur
		for _, s := range removed {
			a.dropSerial(s)
		}
		for _, s := range removed {
			log.Printf("agent: card %d removed", s)
			a.event(ctx, c, ipc.EventCardRemoved, s)
		}
		for _, s := range inserted {
			log.Printf("agent: card %d inserted", s)
			a.event(ctx, c, ipc.EventCardInserted, s)
		}
	}
}

func (a *Agent) call(ctx context.Context, c *ipc.Conn, method string, params any) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return c.Call(ctx, method, params, nil)
}

func (a *Agent) event(ctx context.Context, c *ipc.Conn, typ string, serial uint32) {
	if err := a.call(ctx, c, ipc.MethodAgentEvent, ipc.AgentEvent{Type: typ, Serial: serial}); err != nil {
		log.Printf("agent: agent.event %s %d: %v", typ, serial, err)
	}
}

// serials returns the present cards, sorted and without duplicates.
func (a *Agent) serials() ([]uint32, error) {
	s, err := a.b.Serials()
	if err != nil {
		return nil, err
	}
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s), nil
}

// diff compares two sorted serial lists.
func diff(old, cur []uint32) (removed, inserted []uint32) {
	for _, s := range old {
		if _, ok := slices.BinarySearch(cur, s); !ok {
			removed = append(removed, s)
		}
	}
	for _, s := range cur {
		if _, ok := slices.BinarySearch(old, s); !ok {
			inserted = append(inserted, s)
		}
	}
	return removed, inserted
}

func nonNil(s []uint32) []uint32 {
	if s == nil {
		return []uint32{}
	}
	return s
}

// ---- key requests ----

func (a *Agent) handlePublic(ctx context.Context, _ uint32, params json.RawMessage) (any, error) {
	ref, _, deadline, err := parseRequest(params, false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := withDeadline(ctx, deadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, userErr(err)
	}
	e, err := a.entry(ref)
	if err != nil {
		log.Printf("agent: key.public %s: %v", ref, err)
		return nil, userErr(err)
	}
	pub := e.prov.PublicKey()
	return ipc.KeyPublicResult{Public: base64.StdEncoding.EncodeToString(pub[:])}, nil
}

func (a *Agent) handleX25519(ctx context.Context, c *ipc.Conn, params json.RawMessage) (any, error) {
	ref, peer, deadline, err := parseRequest(params, true)
	if err != nil {
		return nil, err
	}
	rctx, cancel := withDeadline(ctx, deadline)
	defer cancel()
	ss, gotPIN, err := a.x25519(rctx, ref, peer)
	if err != nil {
		log.Printf("agent: key.x25519 %s: %v", ref, err)
		return nil, userErr(err)
	}
	defer clear(ss[:])
	if gotPIN {
		// The card is verified now: the daemon may retry what failed while
		// the user was typing (for example RecomputeStaticStatic).
		go a.event(ctx, c, ipc.EventPINReady, ref.Serial)
	}
	return ipc.KeyX25519Result{Shared: base64.StdEncoding.EncodeToString(ss[:])}, nil
}

func parseRequest(params json.RawMessage, withPeer bool) (ref keyref.Ref, peer [32]byte, deadline int64, err error) {
	var req ipc.KeyRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return ref, peer, 0, &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.AgentBadRequest}
	}
	ref, err = keyref.Parse(req.Ref)
	if err != nil {
		return ref, peer, 0, &ipc.Error{Code: ipc.CodeBadRequest, Message: err.Error()}
	}
	if withPeer {
		b, err := base64.StdEncoding.DecodeString(req.Peer)
		if err != nil || len(b) != len(peer) {
			return ref, peer, 0, &ipc.Error{Code: ipc.CodeBadRequest, Message: msg.AgentBadPeer}
		}
		copy(peer[:], b)
	}
	return ref, peer, req.Deadline, nil
}

// withDeadline applies a request's deadline (unix milliseconds, 0 = none).
// The handler's own ctx only ends with the connection.
func withDeadline(ctx context.Context, ms int64) (context.Context, context.CancelFunc) {
	if ms == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, time.UnixMilli(ms))
}

// x25519 runs one daemon request. gotPIN reports whether the user entered a
// PIN that the card accepted.
func (a *Agent) x25519(ctx context.Context, ref keyref.Ref, peer [32]byte) (ss [32]byte, gotPIN bool, err error) {
	cs := a.card(ref.Serial)
	start, _ := cs.last()
	req := &request{ctx: ctx, start: start}
	retriedUnavailable, retriedPIN := false, false
	for {
		e, err := a.entry(ref)
		if err != nil {
			return ss, false, err
		}
		ss, err = e.do(ctx, cs, req, peer)
		if err == nil {
			return ss, req.entered, nil
		}
		if errors.Is(err, keyprovider.ErrUnavailable) {
			a.drop(e)
		}
		var pe *keyprovider.PINError
		if req.typed && errors.As(err, &pe) {
			// Tell the user at the terminal, not only the daemon.
			a.warn(fmt.Sprintf(msg.AgentWrongPINFmt, pe.RetriesLeft))
		}
		// Retries never follow an attempt that called the prompt: after a
		// prompt the PIN and the operation went to the card together, so a
		// failure is the user's answer (or the card), not lost verification.
		retryable := !req.called && ctx.Err() == nil
		switch {
		case retryable && !retriedUnavailable && errors.Is(err, keyprovider.ErrUnavailable):
			// The connection may have died with a re-seat between two
			// polls; a fresh provider reopens the card.
			retriedUnavailable = true
		case retryable && !retriedPIN && pinLost(err):
			retriedPIN = true
		default:
			return ss, false, err
		}
	}
}

// pinLost reports a card answer of "PIN verification needed" that is not a
// wrong or blocked PIN.
func pinLost(err error) bool {
	var pe *keyprovider.PINError
	return errors.Is(err, keyprovider.ErrPINRequired) &&
		!errors.Is(err, keyprovider.ErrPINBlocked) && !errors.As(err, &pe)
}

// request is the per-request prompt state. It never holds the PIN.
type request struct {
	ctx     context.Context
	start   uint64 // card's prompt epoch when the request began
	called  bool   // prompt callback called in the current attempt
	typed   bool   // Prompter.PIN called in the current attempt
	asked   int    // Prompter.PIN calls in this request
	entered bool   // a PIN was entered and the operation then succeeded
}

// entry is a cached provider. Requests on one card run one at a time
// (cardState.sem), so the prompt callback (called synchronously from X25519)
// always belongs to the request in cur.
type entry struct {
	ref  keyref.Ref
	prov keyprovider.Provider
	desc keyprovider.Description
	cs   *cardState
	cur  atomic.Pointer[request]
}

func (e *entry) do(ctx context.Context, cs *cardState, req *request, peer [32]byte) ([32]byte, error) {
	if testHookWaiting != nil {
		testHookWaiting()
	}
	select {
	case cs.sem <- struct{}{}:
	case <-ctx.Done():
		return [32]byte{}, ctx.Err()
	}
	defer func() { <-cs.sem }()
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	req.called, req.typed = false, false
	e.cur.Store(req)
	defer e.cur.Store(nil)
	ss, err := e.prov.X25519(ctx, peer)
	if req.typed {
		// Recorded before the card is released, so every request still
		// waiting sees it.
		if err == nil {
			req.entered = true
			cs.record(nil)
		} else if isPINOutcome(err) {
			cs.record(err)
		}
	}
	return ss, err
}

// isPINOutcome reports errors that are the answer to a prompt: wrong PIN,
// blocked, or not entered (cancelled, empty, too long).
func isPINOutcome(err error) bool {
	var pe *keyprovider.PINError
	return errors.As(err, &pe) || errors.Is(err, keyprovider.ErrPINBlocked) ||
		errors.Is(err, keyprovider.ErrPINRequired)
}

func (a *Agent) warn(m string) {
	a.promptMu.Lock()
	defer a.promptMu.Unlock()
	a.p.Warn(m)
}

// prompt is the callback given to Backend.Provider for e.
func (a *Agent) prompt(e *entry, retriesLeft int) (string, error) {
	req := e.cur.Load()
	if req == nil {
		// Not serving a request: never ask.
		return "", keyprovider.ErrPINRequired
	}
	req.called = true
	if err := req.ctx.Err(); err != nil {
		// The daemon's deadline passed while this request waited.
		return "", fmt.Errorf("%w: %w", keyprovider.ErrPINRequired, err)
	}
	if epoch, outcome := e.cs.last(); epoch != req.start && outcome != nil {
		// A prompt for this card failed after this request began: answer
		// with that outcome instead of asking again.
		return "", outcome
	}
	a.promptMu.Lock()
	defer a.promptMu.Unlock()
	if retriesLeft <= 0 {
		a.p.Warn(msg.AgentPINBlocked)
		return "", keyprovider.ErrPINBlocked
	}
	if req.asked > 0 {
		return "", keyprovider.ErrPINRequired
	}
	req.asked++
	req.typed = true
	if retriesLeft == 1 {
		a.p.Warn(msg.LastPINRetry)
	}
	return a.p.PIN(e.desc, retriesLeft)
}

// entry returns the cached provider for ref, making one if needed.
func (a *Agent) entry(ref keyref.Ref) (*entry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.entries[ref]; e != nil {
		return e, nil
	}
	e := &entry{ref: ref, cs: a.cardLocked(ref.Serial)}
	prov, err := a.b.Provider(ref, func(retriesLeft int) (string, error) {
		return a.prompt(e, retriesLeft)
	})
	if err != nil {
		return nil, err
	}
	e.prov, e.desc = prov, prov.Describe()
	a.entries[ref] = e
	return e, nil
}

func (a *Agent) card(serial uint32) *cardState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cardLocked(serial)
}

func (a *Agent) cardLocked(serial uint32) *cardState {
	cs := a.cards[serial]
	if cs == nil {
		cs = &cardState{sem: make(chan struct{}, 1)}
		a.cards[serial] = cs
	}
	return cs
}

// drop forgets and closes e unless it was already replaced.
func (a *Agent) drop(e *entry) {
	a.mu.Lock()
	if a.entries[e.ref] != e {
		a.mu.Unlock()
		return
	}
	delete(a.entries, e.ref)
	a.mu.Unlock()
	closeProvider(e.prov)
}

func (a *Agent) dropSerial(serial uint32) {
	a.dropWhere(func(r keyref.Ref) bool { return r.Serial == serial })
}

func (a *Agent) dropAbsent(present []uint32) {
	a.dropWhere(func(r keyref.Ref) bool { return !slices.Contains(present, r.Serial) })
}

func (a *Agent) closeAll() {
	a.dropWhere(func(keyref.Ref) bool { return true })
}

func (a *Agent) dropWhere(match func(keyref.Ref) bool) {
	var gone []*entry
	a.mu.Lock()
	for r, e := range a.entries {
		if match(r) {
			gone = append(gone, e)
			delete(a.entries, r)
		}
	}
	a.mu.Unlock()
	for _, e := range gone {
		closeProvider(e.prov)
	}
}

func closeProvider(p keyprovider.Provider) {
	if c, ok := p.(io.Closer); ok {
		c.Close()
	}
}

// userErr turns provider errors into errors the daemon can act on and show.
func userErr(err error) error {
	var pe *keyprovider.PINError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return &ipc.Error{Code: ipc.CodeUnavailable, Message: msg.AgentRequestExpired}
	case errors.Is(err, keyprovider.ErrPINBlocked):
		return &ipc.Error{Code: ipc.CodePINBlocked, Message: msg.AgentPINBlocked}
	case errors.As(err, &pe):
		return &ipc.Error{Code: ipc.CodeWrongPIN, Message: fmt.Sprintf(msg.AgentWrongPINFmt, pe.RetriesLeft)}
	case errors.Is(err, keyprovider.ErrPINRequired):
		return &ipc.Error{Code: ipc.CodePINRequired, Message: msg.AgentPINRequired}
	case errors.Is(err, keyprovider.ErrLowOrderPoint):
		return &ipc.Error{Code: ipc.CodeLowOrderPoint, Message: msg.AgentLowOrderPeer}
	case errors.Is(err, keyprovider.ErrUnavailable):
		return &ipc.Error{Code: ipc.CodeUnavailable, Message: msg.AgentCardUnavailable}
	}
	// Backend errors (no such card, empty slot, ...) carry msg texts.
	return &ipc.Error{Code: ipc.CodeUnavailable, Message: err.Error()}
}
