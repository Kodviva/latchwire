// Package ipc is the local transport between the Latchwire daemon, the
// per-user agent and the CLI. One unix socket carries newline-delimited JSON
// in both directions; every request is authorized by the peer's uid, which
// the kernel reports for the socket.
//
// The package is transport only. It never logs message bodies: params and
// results can carry X25519 output.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// MaxMessageSize is the largest message, excluding the trailing newline.
	// A longer incoming line closes the connection.
	MaxMessageSize = 64 * 1024

	// maxInflight bounds concurrently running Handle callbacks per Conn.
	maxInflight = 128

	writeTimeout = 10 * time.Second
	dialTimeout  = 2 * time.Second
)

var (
	// ErrClosed is returned by Call when the connection is, or becomes, closed.
	ErrClosed = errors.New("ipc: connection closed")
	// ErrMessageTooLarge is returned when a message exceeds MaxMessageSize.
	ErrMessageTooLarge = errors.New("ipc: message too large")
	// ErrAddrInUse is returned by Listen when a live server owns the socket.
	ErrAddrInUse = errors.New("ipc: socket already in use")

	errServeTwice = errors.New("ipc: Serve already called")
)

// Message is the wire format. A request has Method set; a response has
// Method empty and either Result or Error.
type Message struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error is a protocol-level error, see the Code* constants.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Handler serves one method. uid is the peer's uid from the socket's
// credentials. A returned *Error (also when wrapped) is sent as is; any other
// error becomes an opaque CodeInternal.
type Handler func(ctx context.Context, uid uint32, params json.RawMessage) (any, error)

// Conn is one end of a bidirectional connection. Call and Handle both work on
// either end. Call is safe for concurrent use.
type Conn struct {
	nc  net.Conn
	r   *bufio.Reader
	uid uint32

	wmu sync.Mutex // serialises writes

	mu       sync.Mutex
	pending  map[uint64]chan Message
	handlers map[string]Handler

	nextID    atomic.Uint64
	served    atomic.Bool
	inflight  chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newConn(uc *net.UnixConn) (*Conn, error) {
	uid, err := PeerUID(uc)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("ipc: peer credentials: %w", err)
	}
	return &Conn{
		nc:       uc,
		r:        bufio.NewReaderSize(uc, 4096),
		uid:      uid,
		pending:  make(map[uint64]chan Message),
		handlers: make(map[string]Handler),
		inflight: make(chan struct{}, maxInflight),
		done:     make(chan struct{}),
	}, nil
}

// Dial connects to the unix socket at path. PeerUID of the result is the
// server's uid, which lets a client check it is talking to root.
func Dial(path string) (*Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	nc, err := d.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return newConn(nc.(*net.UnixConn))
}

// Listen creates a unix socket listener at path with mode 0666; callers are
// told apart by peer credentials, not file permissions. A stale socket file
// (nothing accepts connections on it) is replaced. A live one, or a path that
// is not a socket, is left untouched and an error is returned.
func Listen(path string) (net.Listener, error) {
	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ipc: %s exists and is not a socket", path)
		}
		c, derr := net.DialTimeout("unix", path, dialTimeout)
		if derr == nil {
			c.Close()
			return nil, fmt.Errorf("%w: %s", ErrAddrInUse, path)
		}
		if !errors.Is(derr, syscall.ECONNREFUSED) && !errors.Is(derr, syscall.ENOENT) {
			return nil, fmt.Errorf("ipc: probing %s: %w", path, derr)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Accept accepts one connection from l, which must be a unix listener, and
// reads the peer's credentials.
func Accept(l net.Listener) (*Conn, error) {
	nc, err := l.Accept()
	if err != nil {
		return nil, err
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		nc.Close()
		return nil, errors.New("ipc: not a unix connection")
	}
	return newConn(uc)
}

// PeerUID returns the uid of the process at the other end of c, as reported
// by the kernel.
func (c *Conn) PeerUID() uint32 { return c.uid }

// Done is closed when the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Close closes the connection. Pending Calls fail with ErrClosed. Safe to call
// more than once.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.nc.Close()
	})
	return err
}

// Handle registers fn for method, replacing any previous handler. fn runs in
// its own goroutine; ctx is cancelled when the connection ends.
func (c *Conn) Handle(method string, fn Handler) {
	c.mu.Lock()
	c.handlers[method] = fn
	c.mu.Unlock()
}

// Call sends a request and waits for its response. params and result may be
// nil. A remote failure is returned as *Error. Call returns early with
// ctx.Err() on cancellation, and with ErrClosed if the connection closes; a
// response arriving later is discarded. Serve must be running to receive
// responses.
func (c *Conn) Call(ctx context.Context, method string, params, result any) error {
	msg := Message{Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("ipc: encode params: %w", err)
		}
		msg.Params = b
	}

	ch := make(chan Message, 1)
	msg.ID = c.nextID.Add(1)

	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return ErrClosed
	default:
	}
	c.pending[msg.ID] = ch
	c.mu.Unlock()
	forget := func() {
		c.mu.Lock()
		delete(c.pending, msg.ID)
		c.mu.Unlock()
	}

	if err := c.send(msg); err != nil {
		forget()
		return err
	}

	var resp Message
	select {
	case resp = <-ch:
	case <-ctx.Done():
		forget()
		return ctx.Err()
	case <-c.done:
		forget()
		select { // a response that raced the close still counts
		case resp = <-ch:
		default:
			return ErrClosed
		}
	}

	if resp.Error != nil {
		return resp.Error
	}
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("ipc: decode result: %w", err)
		}
	}
	return nil
}

// send writes one message. A failed or partial write leaves the stream in an
// unknown state, so it closes the connection.
func (c *Conn) send(m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("ipc: encode message: %w", err)
	}
	if len(b) > MaxMessageSize {
		return ErrMessageTooLarge
	}
	b = append(b, '\n')

	c.wmu.Lock()
	defer c.wmu.Unlock()
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := c.nc.Write(b); err != nil {
		c.Close()
		return fmt.Errorf("%w: %v", ErrClosed, err)
	}
	return nil
}

// Serve reads messages until the connection ends, dispatching requests to
// handlers and responses to waiting Calls. It closes the connection before
// returning. The result is nil for a normal end (peer hung up or Close),
// ctx.Err() on cancellation, or the protocol error that made it give up.
func (c *Conn) Serve(ctx context.Context) error {
	if !c.served.CompareAndSwap(false, true) {
		return errServeTwice
	}
	hctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer c.Close()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-stop:
		}
	}()

	for {
		m, err := c.readMessage()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
				return nil
			}
			return err
		}
		if m.Method != "" {
			c.dispatch(hctx, m)
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ok {
			ch <- m // buffered, never blocks
		}
	}
}

// readMessage reads one line, enforcing MaxMessageSize while reading so an
// endless line cannot exhaust memory.
func (c *Conn) readMessage() (Message, error) {
	for {
		var line []byte
		for {
			frag, err := c.r.ReadSlice('\n')
			line = append(line, frag...)
			if len(line) > MaxMessageSize+1 {
				return Message{}, ErrMessageTooLarge
			}
			if err == nil {
				break
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			return Message{}, err
		}
		line = line[:len(line)-1]
		if len(line) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return Message{}, errors.New("ipc: malformed message")
		}
		return m, nil
	}
}

func (c *Conn) dispatch(ctx context.Context, req Message) {
	c.mu.Lock()
	h := c.handlers[req.Method]
	c.mu.Unlock()
	if h == nil {
		c.reply(req.ID, nil, &Error{Code: CodeNotFound, Message: "unknown method"})
		return
	}
	select {
	case c.inflight <- struct{}{}:
	default:
		c.reply(req.ID, nil, &Error{Code: CodeUnavailable, Message: "too many requests in flight"})
		return
	}
	go func() {
		defer func() { <-c.inflight }()
		v, err := c.runHandler(ctx, h, req.Params)
		c.reply(req.ID, v, err)
	}()
}

func (c *Conn) runHandler(ctx context.Context, h Handler, params json.RawMessage) (v any, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, errors.New("handler panic") // value deliberately dropped
		}
	}()
	return h(ctx, c.uid, params)
}

func (c *Conn) reply(id uint64, v any, herr error) {
	resp := Message{ID: id}
	if herr != nil {
		var e *Error
		if !errors.As(herr, &e) {
			e = &Error{Code: CodeInternal, Message: "internal error"}
		}
		resp.Error = e
	} else if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			resp.Error = &Error{Code: CodeInternal, Message: "internal error"}
		} else {
			resp.Result = b
		}
	}
	if err := c.send(resp); errors.Is(err, ErrMessageTooLarge) {
		c.send(Message{ID: id, Error: &Error{Code: CodeInternal, Message: "response too large"}})
	}
}
