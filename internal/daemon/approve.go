package daemon

import (
	"context"
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
	errCancelled = &ipc.Error{Code: ipc.CodeCancelled, Message: msg.AssistDenied}
)

// assistAgent returns uid's earliest registered agent that reported
// CapAssist (the desktop app), or nil. Older agents and the CLI agent report
// no capabilities and are never chosen.
func (m *Manager) assistAgent(uid uint32) *ipc.Conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *ipc.Conn
	var seq uint64
	for c, a := range m.agents {
		if m.assistAgentLocked(c, uid) && (best == nil || a.seq < seq) {
			best, seq = c, a.seq
		}
	}
	return best
}

// approve asks uid's app to show the approval window for r. It returns nil
// only when the user allowed it while access stayed open. A refusal, no
// answer within approveTimeout, access closing meanwhile (revoke, a new
// grant, the owner leaving) and losing the app's connection are CodeDenied;
// ctx ending is CodeCancelled; no app is CodeNoApp. Callers still check
// access again before acting.
func (m *Manager) approve(ctx context.Context, uid uint32, r ipc.ApproveRequest) error {
	c := m.assistAgent(uid)
	if c == nil {
		return errNoApp
	}
	pctx, release := m.assist.pending(uid)
	defer release()
	if pctx.Err() != nil {
		// No open access: nobody is asked.
		return errRevoked
	}
	cctx, cancel := context.WithTimeout(ctx, approveTimeout)
	defer cancel()
	// cancel takes no lock of the Manager or of assistState, so it may run
	// while pending's canceller holds the assist mutex.
	stop := context.AfterFunc(pctx, cancel)
	defer stop()
	var res ipc.ApproveResult
	err := c.Call(cctx, ipc.MethodAssistApprove, r, &res)
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
	return nil
}

// cardList returns the cards that uid's app sees.
func (m *Manager) cardList(ctx context.Context, uid uint32) ([]ipc.CardEntry, error) {
	c := m.assistAgent(uid)
	if c == nil {
		return nil, errNoApp
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
		return ipc.KeygenResult{}, errNoApp
	}
	var res ipc.KeygenResult
	err := c.Call(ctx, ipc.MethodCardKeygen, ipc.KeygenRequest{Serial: serial, Slot: slot}, &res)
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
