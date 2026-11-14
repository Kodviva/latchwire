package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// approveTimeout is how long the approval window waits for the user; no
// answer is a refusal. A variable so tests can shorten it.
var approveTimeout = 2 * time.Minute

// noticeTimeout bounds an assist.notice call.
const noticeTimeout = 5 * time.Second

var (
	errNoApp     = &ipc.Error{Code: ipc.CodeNoApp, Message: msg.AssistNoApp}
	errDenied    = &ipc.Error{Code: ipc.CodeDenied, Message: msg.AssistDenied}
	errRevoked   = &ipc.Error{Code: ipc.CodeDenied, Message: msg.AssistCancelled}
	errCancelled = &ipc.Error{Code: ipc.CodeCancelled, Message: msg.AssistRequestCancelled}
)

// assistAgent returns the app that approvals and card operations of uid go
// to: the connection that opened uid's current grant, while it is still a
// registered agent of uid reporting CapAssist. Without a grant, or when its
// owner no longer qualifies, it returns nil. Another agent of the same user
// that merely reports CapAssist is never asked: the capability is the
// client's own claim, the grant is the user's act in the app.
func (m *Manager) assistAgent(uid uint32) *ipc.Conn {
	// Lock order: m.mu, then assist.mu.
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.assist.owner(uid)
	if c == nil || !m.assistAgentLocked(c, uid) {
		return nil
	}
	return c
}

// approve asks uid's app (the grant's owner) to show the approval window for
// r. It returns nil only when the user allowed it while access stayed open.
// A refusal, no answer within approveTimeout, access closing meanwhile
// (revoke, a new grant, the owner leaving) and losing the app's connection
// are CodeDenied; access that expired by time is CodeAccessOff; ctx ending
// is CodeCancelled; no grant owner is CodeNoApp, or CodeAccessOff when
// access is off. Callers still check access again before acting.
func (m *Manager) approve(ctx context.Context, uid uint32, r ipc.ApproveRequest) error {
	c := m.assistAgent(uid)
	if c == nil {
		return m.noApp(uid)
	}
	pctx, release := m.assist.pending(uid)
	defer release()
	if pctx.Err() != nil {
		// No open access: nobody is asked.
		if err := m.assist.allowed(uid, "", m.assist.now()); err != nil {
			return err
		}
		return errRevoked
	}
	cctx, cancel := context.WithTimeout(ctx, approveTimeout)
	defer cancel()
	// cancel takes no lock of the Manager or of assistState, so it may run
	// while pending's canceller holds the assist mutex.
	stop := context.AfterFunc(pctx, cancel)
	defer stop()
	r.ID = requestID()
	var res ipc.ApproveResult
	err := c.Call(cctx, ipc.MethodAssistApprove, r, &res)
	if err != nil && cctx.Err() != nil {
		// The daemon stopped waiting: the window must not stay open.
		m.abort(c, r.ID)
	}
	switch {
	case pctx.Err() != nil:
		// Checked first: an allow that raced a revoke is a refusal.
		return errRevoked
	case ctx.Err() != nil:
		return errCancelled
	case err != nil:
		log.Printf("daemon: assist.approve for uid %d: %v", uid, err)
		return errDenied
	case !res.Allow:
		return errDenied
	}
	// The grant may have run out by time while the window was open: that
	// does not cancel pending approvals, so check it here.
	return m.assist.allowed(uid, "", m.assist.now())
}

// requestID is a random name for one assist.approve or card.keygen.
func requestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// abort tells the app c that the daemon no longer waits for request id. It
// does not wait for the answer; errors are only logged.
func (m *Manager) abort(c *ipc.Conn, id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), noticeTimeout)
		defer cancel()
		if err := c.Call(ctx, ipc.MethodAssistAbort, ipc.AssistAbort{ID: id}, nil); err != nil {
			log.Printf("daemon: assist.abort %s: %v", id, err)
		}
	}()
}

// noApp is the error for uid when no app can be asked: access_off when
// access is off (a revoke closes the grant and with it its owner), else
// no_app.
func (m *Manager) noApp(uid uint32) error {
	if err := m.assist.allowed(uid, "", m.assist.now()); err != nil {
		return err
	}
	return errNoApp
}

// cardList returns the cards that uid's app (the grant's owner) sees.
func (m *Manager) cardList(ctx context.Context, uid uint32) ([]ipc.CardEntry, error) {
	c := m.assistAgent(uid)
	if c == nil {
		return nil, m.noApp(uid)
	}
	var res ipc.CardListResult
	if err := c.Call(ctx, ipc.MethodCardList, nil, &res); err != nil {
		return nil, err
	}
	return res.Cards, nil
}

// cardKeygen has uid's app make a new key in slot of the card serial.
func (m *Manager) cardKeygen(ctx context.Context, uid, serial uint32, slot uint8) (ipc.KeygenResult, error) {
	c := m.assistAgent(uid)
	if c == nil {
		return ipc.KeygenResult{}, m.noApp(uid)
	}
	id := requestID()
	var res ipc.KeygenResult
	err := c.Call(ctx, ipc.MethodCardKeygen, ipc.KeygenRequest{ID: id, Serial: serial, Slot: slot}, &res)
	if err != nil && ctx.Err() != nil {
		// The daemon stopped waiting: the app gives the key up.
		m.abort(c, id)
	}
	return res, err
}

// notify has uid's app show the guided step step. Failures are only logged:
// the notice is a convenience.
func (m *Manager) notify(uid uint32, step string) {
	c := m.assistAgent(uid)
	if c == nil {
		log.Printf("daemon: assist.notice %s for uid %d: no app", step, uid)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), noticeTimeout)
	defer cancel()
	if err := c.Call(ctx, ipc.MethodAssistNotice, ipc.AssistNotice{Step: step}, nil); err != nil {
		log.Printf("daemon: assist.notice %s for uid %d: %v", step, uid, err)
	}
}
