package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

const (
	// defaultKeyTimeout applies to a key call whose ctx has no deadline, so
	// every request carries one (ipc.KeyRequest.Deadline).
	defaultKeyTimeout = 3 * time.Second
	// publicKeyTimeout bounds key.public; no PIN is needed for it.
	publicKeyTimeout = 10 * time.Second
	// warmUpTimeout bounds the first X25519 at connect, which may wait for
	// the user to type the PIN.
	warmUpTimeout = 2 * time.Minute
)

// agentFinder returns the connection of a registered agent run by uid that
// reports serial, or nil.
type agentFinder func(serial, uid uint32) *ipc.Conn

// remoteKey is a keyprovider.Provider whose private key lives on a card
// owned by a user's agent. Each X25519 becomes a key.x25519 call to the
// agent of the same uid that served key.public at connect; the agent is
// looked up per call, so a restarted agent is used again.
type remoteKey struct {
	ref  keyref.Ref
	pub  [32]byte
	uid  uint32
	find agentFinder
	// life ends when the tunnel attempt that created the key ends; calls
	// still waiting on the agent then return at once.
	life context.Context
}

var _ keyprovider.Provider = (*remoteKey)(nil)

func (k *remoteKey) PublicKey() [32]byte { return k.pub }

func (k *remoteKey) Describe() keyprovider.Description {
	return keyprovider.Description{Kind: "remote", Serial: k.ref.Serial, Slot: k.ref.Slot, Tier: keyprovider.Tier1}
}

func (k *remoteKey) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	var out [32]byte
	c := k.find(k.ref.Serial, k.uid)
	if c == nil {
		return out, fmt.Errorf("%w: %s", keyprovider.ErrUnavailable, msg.DaemonAgentGone)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(k.life, cancel)
	defer stop()

	req, ctx, cancelT := keyRequest(ctx, k.ref)
	defer cancelT()
	req.Peer = base64.StdEncoding.EncodeToString(peer[:])
	var res ipc.KeyX25519Result
	if err := c.Call(ctx, ipc.MethodKeyX25519, req, &res); err != nil {
		return out, mapKeyErr(err)
	}
	b, err := base64.StdEncoding.DecodeString(res.Shared)
	defer clear(b)
	if err != nil || len(b) != len(out) {
		return out, fmt.Errorf("%w: %s", keyprovider.ErrUnavailable, msg.DaemonBadAgentReply)
	}
	copy(out[:], b)
	return out, nil
}

// fetchPublic asks c for the public key of ref.
func fetchPublic(ctx context.Context, c *ipc.Conn, ref keyref.Ref) ([32]byte, error) {
	var pub [32]byte
	ctx, cancel := context.WithTimeout(ctx, publicKeyTimeout)
	defer cancel()
	req, ctx, cancelT := keyRequest(ctx, ref)
	defer cancelT()
	var res ipc.KeyPublicResult
	if err := c.Call(ctx, ipc.MethodKeyPublic, req, &res); err != nil {
		return pub, mapKeyErr(err)
	}
	b, err := base64.StdEncoding.DecodeString(res.Public)
	if err != nil || len(b) != len(pub) {
		return pub, fmt.Errorf("%w: %s", keyprovider.ErrUnavailable, msg.DaemonBadAgentReply)
	}
	copy(pub[:], b)
	if pub == ([32]byte{}) {
		return pub, fmt.Errorf("%w: %s", keyprovider.ErrUnavailable, msg.DaemonBadAgentReply)
	}
	return pub, nil
}

// keyRequest builds a request whose Deadline is ctx's deadline, adding
// defaultKeyTimeout when ctx has none, so the agent never asks for a PIN
// after the daemon stopped waiting.
func keyRequest(ctx context.Context, ref keyref.Ref) (ipc.KeyRequest, context.Context, context.CancelFunc) {
	cancel := context.CancelFunc(func() {})
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, defaultKeyTimeout)
	}
	dl, _ := ctx.Deadline()
	return ipc.KeyRequest{Ref: ref.String(), Deadline: dl.UnixMilli()}, ctx, cancel
}

// keyError carries both the keyprovider error (for errors.Is/As in the
// device and adapter) and the agent's ipc.Error (for the user).
type keyError struct {
	kp error
	ie *ipc.Error
}

func (e *keyError) Error() string   { return e.kp.Error() + ": " + e.ie.Message }
func (e *keyError) Unwrap() []error { return []error{e.kp, e.ie} }

// mapKeyErr turns a key call failure into keyprovider errors. Context errors
// stay as they are; a lost connection and unknown codes are ErrUnavailable.
func mapKeyErr(err error) error {
	var ie *ipc.Error
	if errors.As(err, &ie) {
		var kp error
		switch ie.Code {
		case ipc.CodeWrongPIN:
			n := 0
			fmt.Sscanf(ie.Message, msg.AgentWrongPINFmt, &n)
			kp = &keyprovider.PINError{RetriesLeft: n}
		case ipc.CodePINBlocked:
			kp = keyprovider.ErrPINBlocked
		case ipc.CodePINRequired:
			kp = keyprovider.ErrPINRequired
		case ipc.CodeLowOrderPoint:
			kp = keyprovider.ErrLowOrderPoint
		default: // unavailable, bad_request, internal, anything new
			kp = keyprovider.ErrUnavailable
		}
		return &keyError{kp: kp, ie: ie}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ipc.ErrClosed) {
		return &keyError{kp: keyprovider.ErrUnavailable,
			ie: &ipc.Error{Code: ipc.CodeUnavailable, Message: msg.DaemonAgentGone}}
	}
	return fmt.Errorf("%w: %v", keyprovider.ErrUnavailable, err)
}
