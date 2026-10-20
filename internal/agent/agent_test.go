package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/softkey"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

const (
	serialA = 40727512
	serialB = 40727513

	testPIN  = "731905" // distinctive, so a leak is easy to find
	wrongPIN = "135799"

	poll = 20 * time.Millisecond
)

var refA = keyref.Ref{Serial: serialA, Slot: 0x82}

// ---- fake backend ----

// fakeCard is a card with one key. It follows the piv provider's contract:
// the prompt is called when the card holds no verified PIN; a wrong PIN is a
// *PINError; a prompt error comes back wrapped in ErrPINRequired; stale
// simulates verification lost after the card said it was verified (the
// card then answers "security status not satisfied" -> ErrPINRequired).
type fakeCard struct {
	mu       sync.Mutex
	key      *softkey.Key
	pin      string
	retries  int
	verified bool
	stale    bool
	// unavailable makes the next n operations fail as if the card had been
	// re-seated (the connection is dead).
	unavailable int
}

type fakeBackend struct {
	mu        sync.Mutex
	serials   []uint32
	cards     map[uint32]*fakeCard
	providers int // Provider calls
	closed    int // providers closed
}

func newFakeBackend(t *testing.T, serials ...uint32) *fakeBackend {
	b := &fakeBackend{serials: serials, cards: map[uint32]*fakeCard{}}
	for _, s := range serials {
		k, err := softkey.New()
		if err != nil {
			t.Fatal(err)
		}
		b.cards[s] = &fakeCard{key: k, pin: testPIN, retries: 3}
	}
	return b
}

func (b *fakeBackend) setSerials(s ...uint32) {
	b.mu.Lock()
	b.serials = s
	b.mu.Unlock()
}

func (b *fakeBackend) card(s uint32) *fakeCard {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cards[s]
}

func (b *fakeBackend) Serials() ([]uint32, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.serials), nil
}

func (b *fakeBackend) Provider(ref keyref.Ref, prompt func(int) (string, error)) (keyprovider.Provider, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.providers++
	c := b.cards[ref.Serial]
	if c == nil || !slices.Contains(b.serials, ref.Serial) {
		return nil, keyprovider.ErrUnavailable
	}
	return &fakeProvider{b: b, c: c, ref: ref, prompt: prompt}, nil
}

type fakeProvider struct {
	b      *fakeBackend
	c      *fakeCard
	ref    keyref.Ref
	prompt func(int) (string, error)
	dead   bool
}

func (p *fakeProvider) PublicKey() [32]byte { return p.c.key.PublicKey() }

func (p *fakeProvider) Describe() keyprovider.Description {
	return keyprovider.Description{Kind: "fake", Serial: p.ref.Serial, Slot: p.ref.Slot, Tier: keyprovider.Tier1}
}

func (p *fakeProvider) Close() error {
	p.b.mu.Lock()
	p.b.closed++
	p.b.mu.Unlock()
	return nil
}

func (p *fakeProvider) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	c := p.c
	c.mu.Lock()
	if p.dead {
		c.mu.Unlock()
		return [32]byte{}, keyprovider.ErrUnavailable
	}
	if c.unavailable > 0 {
		c.unavailable--
		p.dead = true
		c.verified = false // a re-seated card forgets the PIN
		c.mu.Unlock()
		return [32]byte{}, fmt.Errorf("%w: card removed", keyprovider.ErrUnavailable)
	}
	if !c.verified {
		retries := c.retries
		c.mu.Unlock()
		// Deliberately also called with 0 retries left: the agent itself
		// must refuse to prompt for a blocked PIN.
		pin, err := p.prompt(retries)
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: %w", keyprovider.ErrPINRequired, err)
		}
		c.mu.Lock()
		if pin != c.pin {
			c.retries--
			n := c.retries
			c.mu.Unlock()
			if n == 0 {
				return [32]byte{}, keyprovider.ErrPINBlocked
			}
			return [32]byte{}, &keyprovider.PINError{RetriesLeft: n}
		}
		c.retries = 3
		c.verified = true
	}
	if c.stale {
		c.stale = false
		c.verified = false
		c.mu.Unlock()
		return [32]byte{}, fmt.Errorf("%w: security status not satisfied", keyprovider.ErrPINRequired)
	}
	c.mu.Unlock()
	return c.key.X25519(ctx, peer)
}

// ---- fake prompter ----

type fakePrompter struct {
	mu      sync.Mutex
	pins    []string // answers, the last one repeats
	calls   []int    // retriesLeft of each PIN call
	journal []string // "warn:<msg>" and "pin" in call order
}

func (p *fakePrompter) PIN(d keyprovider.Description, retriesLeft int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, retriesLeft)
	p.journal = append(p.journal, "pin")
	if len(p.pins) == 0 {
		return "", errors.New("no PIN")
	}
	pin := p.pins[0]
	if len(p.pins) > 1 {
		p.pins = p.pins[1:]
	}
	return pin, nil
}

func (p *fakePrompter) Warn(m string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.journal = append(p.journal, "warn:"+m)
}

func (p *fakePrompter) pinCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *fakePrompter) log() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.journal)
}

// ---- fake daemon ----

type daemon struct {
	t        *testing.T
	l        net.Listener
	path     string
	conns    chan *ipc.Conn
	register chan ipc.AgentRegister
	events   chan ipc.AgentEvent
}

func sockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func newDaemon(t *testing.T) *daemon {
	t.Helper()
	d := &daemon{
		t:        t,
		path:     sockPath(t),
		conns:    make(chan *ipc.Conn, 4),
		register: make(chan ipc.AgentRegister, 16),
		events:   make(chan ipc.AgentEvent, 64),
	}
	d.listen()
	return d
}

func (d *daemon) listen() {
	l, err := ipc.Listen(d.path)
	if err != nil {
		d.t.Fatal(err)
	}
	d.l = l
	d.t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := ipc.Accept(l)
			if err != nil {
				return
			}
			c.Handle(ipc.MethodAgentRegister, func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
				var r ipc.AgentRegister
				if err := json.Unmarshal(p, &r); err != nil {
					return nil, err
				}
				d.register <- r
				return nil, nil
			})
			c.Handle(ipc.MethodAgentEvent, func(ctx context.Context, uid uint32, p json.RawMessage) (any, error) {
				var e ipc.AgentEvent
				if err := json.Unmarshal(p, &e); err != nil {
					return nil, err
				}
				d.events <- e
				return nil, nil
			})
			go c.Serve(context.Background())
			d.t.Cleanup(func() { c.Close() })
			d.conns <- c
		}
	}()
}

// conn waits for the agent's connection and its registration.
func (d *daemon) conn() (*ipc.Conn, ipc.AgentRegister) {
	d.t.Helper()
	var c *ipc.Conn
	select {
	case c = <-d.conns:
	case <-time.After(5 * time.Second):
		d.t.Fatal("agent did not connect")
	}
	select {
	case r := <-d.register:
		return c, r
	case <-time.After(5 * time.Second):
		d.t.Fatal("agent did not register")
	}
	return nil, ipc.AgentRegister{}
}

func (d *daemon) event() ipc.AgentEvent {
	d.t.Helper()
	select {
	case e := <-d.events:
		return e
	case <-time.After(5 * time.Second):
		d.t.Fatal("no agent.event")
	}
	return ipc.AgentEvent{}
}

func (d *daemon) noEvent(within time.Duration) {
	d.t.Helper()
	select {
	case e := <-d.events:
		d.t.Fatalf("unexpected event %+v", e)
	case <-time.After(within):
	}
}

func startAgent(t *testing.T, d *daemon, b Backend, p Prompter) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New(d.path, b, p, poll).Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func peerKey(t *testing.T) (*softkey.Key, string) {
	t.Helper()
	k, err := softkey.New()
	if err != nil {
		t.Fatal(err)
	}
	pk := k.PublicKey()
	return k, base64.StdEncoding.EncodeToString(pk[:])
}

func x25519(t *testing.T, c *ipc.Conn, ref keyref.Ref, peer string) (string, error) {
	t.Helper()
	var res ipc.KeyX25519Result
	err := c.Call(ctx5(t), ipc.MethodKeyX25519, ipc.KeyRequest{Ref: ref.String(), Peer: peer}, &res)
	return res.Shared, err
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var ie *ipc.Error
	if !errors.As(err, &ie) || ie.Code != code {
		t.Fatalf("err = %v, want ipc error code %q", err, code)
	}
}

// ---- tests ----

func TestRegistersAndReportsCards(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA, serialB)
	b.setSerials(serialA)
	startAgent(t, d, b, &fakePrompter{})

	_, reg := d.conn()
	if !slices.Equal(reg.Serials, []uint32{serialA}) {
		t.Fatalf("registered %v, want [A]", reg.Serials)
	}
	d.noEvent(5 * poll)

	b.setSerials(serialA, serialB)
	if e := d.event(); e != (ipc.AgentEvent{Type: ipc.EventCardInserted, Serial: serialB}) {
		t.Fatalf("event %+v, want card_inserted B", e)
	}
	b.setSerials(serialB)
	if e := d.event(); e != (ipc.AgentEvent{Type: ipc.EventCardRemoved, Serial: serialA}) {
		t.Fatalf("event %+v, want card_removed A", e)
	}
	d.noEvent(5 * poll)
}

func TestX25519ViaIPC(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	p := &fakePrompter{pins: []string{testPIN}}
	startAgent(t, d, b, p)
	c, _ := d.conn()

	var pub ipc.KeyPublicResult
	if err := c.Call(ctx5(t), ipc.MethodKeyPublic, ipc.KeyRequest{Ref: refA.String()}, &pub); err != nil {
		t.Fatal(err)
	}
	wantPub := b.card(serialA).key.PublicKey()
	if pub.Public != base64.StdEncoding.EncodeToString(wantPub[:]) {
		t.Fatalf("key.public = %s, want the card's key", pub.Public)
	}
	if p.pinCalls() != 0 {
		t.Fatal("key.public asked for the PIN")
	}

	peer, peerB64 := peerKey(t)
	shared, err := x25519(t, c, refA, peerB64)
	if err != nil {
		t.Fatal(err)
	}
	want, err := peer.X25519(context.Background(), wantPub)
	if err != nil {
		t.Fatal(err)
	}
	if shared != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatal("key.x25519 result differs from the software computation")
	}
	if e := d.event(); e != (ipc.AgentEvent{Type: ipc.EventPINReady, Serial: serialA}) {
		t.Fatalf("event %+v, want pin_ready A", e)
	}

	// Verified now: no new prompt, no new pin_ready.
	if _, err := x25519(t, c, refA, peerB64); err != nil {
		t.Fatal(err)
	}
	if p.pinCalls() != 1 {
		t.Fatalf("PIN asked %d times, want 1", p.pinCalls())
	}
	d.noEvent(5 * poll)

	// Bad requests are refused without touching the card.
	_, err = x25519(t, c, refA, "AAAA")
	wantCode(t, err, ipc.CodeBadRequest)
	err = c.Call(ctx5(t), ipc.MethodKeyPublic, ipc.KeyRequest{Ref: "piv://1/9a"}, nil)
	wantCode(t, err, ipc.CodeBadRequest)
}

func TestWrongPINDoesNotLoop(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	p := &fakePrompter{pins: []string{wrongPIN}}
	startAgent(t, d, b, p)
	c, _ := d.conn()
	_, peer := peerKey(t)

	_, err := x25519(t, c, refA, peer)
	wantCode(t, err, ipc.CodeWrongPIN)
	if n := p.pinCalls(); n != 1 {
		t.Fatalf("PIN asked %d times in one request, want 1", n)
	}
	// Asking again happens only with the next request.
	_, err = x25519(t, c, refA, peer)
	wantCode(t, err, ipc.CodeWrongPIN)
	if n := p.pinCalls(); n != 2 {
		t.Fatalf("PIN asked %d times after two requests, want 2", n)
	}
}

func TestLastRetryWarns(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	b.card(serialA).retries = 1
	p := &fakePrompter{pins: []string{testPIN}}
	startAgent(t, d, b, p)
	c, _ := d.conn()
	_, peer := peerKey(t)

	if _, err := x25519(t, c, refA, peer); err != nil {
		t.Fatal(err)
	}
	if got, want := p.log(), []string{"warn:" + msg.LastPINRetry, "pin"}; !slices.Equal(got, want) {
		t.Fatalf("prompter calls %q, want %q", got, want)
	}
	if !slices.Equal(p.calls, []int{1}) {
		t.Fatalf("PIN retriesLeft %v, want [1]", p.calls)
	}
}

func TestBlockedPINNeverPrompts(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	b.card(serialA).retries = 0
	p := &fakePrompter{pins: []string{testPIN}}
	startAgent(t, d, b, p)
	c, _ := d.conn()
	_, peer := peerKey(t)

	for i := 0; i < 2; i++ {
		_, err := x25519(t, c, refA, peer)
		wantCode(t, err, ipc.CodePINBlocked)
	}
	if n := p.pinCalls(); n != 0 {
		t.Fatalf("PIN asked %d times for a blocked PIN, want 0", n)
	}
}

func TestReverificationAfterExternalReset(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	p := &fakePrompter{pins: []string{testPIN}}
	startAgent(t, d, b, p)
	c, _ := d.conn()
	_, peer := peerKey(t)

	if _, err := x25519(t, c, refA, peer); err != nil {
		t.Fatal(err)
	}
	d.event() // pin_ready

	// Another program reset the card: it still looks verified, then the
	// operation answers "security status not satisfied".
	card := b.card(serialA)
	card.mu.Lock()
	card.stale = true
	card.mu.Unlock()

	if _, err := x25519(t, c, refA, peer); err != nil {
		t.Fatalf("request after external reset: %v", err)
	}
	if n := p.pinCalls(); n != 2 {
		t.Fatalf("PIN asked %d times, want once more within the request (2)", n)
	}
	if e := d.event(); e.Type != ipc.EventPINReady {
		t.Fatalf("event %+v, want pin_ready after re-verification", e)
	}

	// Lost again while the user gives a wrong PIN: no second prompt.
	card.mu.Lock()
	card.stale = true
	card.mu.Unlock()
	p.mu.Lock()
	p.pins = []string{wrongPIN}
	p.mu.Unlock()
	_, err := x25519(t, c, refA, peer)
	wantCode(t, err, ipc.CodeWrongPIN)
	if n := p.pinCalls(); n != 3 {
		t.Fatalf("PIN asked %d times, want exactly one more (3)", n)
	}
}

// A card re-seated between two polls kills the held connection. The request
// that notices drops the provider and makes a fresh one (asking the PIN
// again, since the card forgot it).
func TestReseatGetsFreshProvider(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	p := &fakePrompter{pins: []string{testPIN}}
	startAgent(t, d, b, p)
	c, _ := d.conn()
	_, peer := peerKey(t)

	if _, err := x25519(t, c, refA, peer); err != nil {
		t.Fatal(err)
	}
	card := b.card(serialA)
	card.mu.Lock()
	card.unavailable = 1
	card.mu.Unlock()
	if _, err := x25519(t, c, refA, peer); err != nil {
		t.Fatalf("request after re-seat: %v", err)
	}
	b.mu.Lock()
	providers, closed := b.providers, b.closed
	b.mu.Unlock()
	if providers != 2 || closed != 1 {
		t.Fatalf("providers made %d, closed %d; want 2 and 1", providers, closed)
	}
	if n := p.pinCalls(); n != 2 {
		t.Fatalf("PIN asked %d times, want 2", n)
	}

	// A card that is really gone fails as unavailable, without a loop.
	b.setSerials()
	card.mu.Lock()
	card.unavailable = 1
	card.mu.Unlock()
	_, err := x25519(t, c, refA, peer)
	wantCode(t, err, ipc.CodeUnavailable)
}

// When a card is removed its providers are closed.
func TestCardRemovalClosesProviders(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	startAgent(t, d, b, &fakePrompter{pins: []string{testPIN}})
	c, _ := d.conn()
	if err := c.Call(ctx5(t), ipc.MethodKeyPublic, ipc.KeyRequest{Ref: refA.String()}, nil); err != nil {
		t.Fatal(err)
	}
	b.setSerials()
	if e := d.event(); e.Type != ipc.EventCardRemoved {
		t.Fatalf("event %+v, want card_removed", e)
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed != 1 {
		t.Fatalf("closed %d providers after removal, want 1", closed)
	}
}

// The agent reconnects and registers again when the daemon goes away.
func TestRedialsAfterDaemonRestart(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	startAgent(t, d, b, &fakePrompter{})
	c, _ := d.conn()
	d.l.Close()
	c.Close()
	d.listen()
	_, reg := d.conn()
	if !slices.Equal(reg.Serials, []uint32{serialA}) {
		t.Fatalf("registered %v after restart, want [A]", reg.Serials)
	}
}

func TestPINNotLogged(t *testing.T) {
	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	p := &fakePrompter{pins: []string{wrongPIN, testPIN}}
	startAgent(t, d, b, p)
	c, _ := d.conn()
	_, peer := peerKey(t)

	if _, err := x25519(t, c, refA, peer); err == nil {
		t.Fatal("wrong PIN accepted")
	}
	if _, err := x25519(t, c, refA, peer); err != nil {
		t.Fatal(err)
	}
	card := b.card(serialA)
	card.mu.Lock()
	card.stale = true
	card.mu.Unlock()
	if _, err := x25519(t, c, refA, peer); err != nil {
		t.Fatal(err)
	}
	b.setSerials()
	d.event() // pin_ready
	d.event()
	d.event()

	out := buf.String()
	if out == "" {
		t.Fatal("agent logged nothing; the test would prove nothing")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, testPIN) || strings.Contains(line, wrongPIN) {
			t.Fatalf("PIN found in log line %q", line)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var _ io.Writer = (*syncBuffer)(nil)

// A cancelled prompt ends the request; it is not "verification lost".
func TestCancelledPromptNotRetried(t *testing.T) {
	d := newDaemon(t)
	b := newFakeBackend(t, serialA)
	p := &fakePrompter{} // every PIN call fails
	startAgent(t, d, b, p)
	c, _ := d.conn()
	_, peer := peerKey(t)

	_, err := x25519(t, c, refA, peer)
	wantCode(t, err, ipc.CodePINRequired)
	if n := p.pinCalls(); n != 1 {
		t.Fatalf("PIN asked %d times, want 1", n)
	}
}
