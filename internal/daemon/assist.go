package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// assistKeep is how many activity entries the daemon keeps per user.
const assistKeep = 20

// assistState is the agent access of every user: whether a local agent (the
// MCP server) may drive setup, until when, for which permission groups, and
// the last assistKeep tool calls. It lives in memory only: a daemon restart
// closes access. The zero value is ready to use.
type assistState struct {
	mu    sync.Mutex
	users map[uint32]*assistUser
	// clock is time.Now unless a test injects another one.
	clock func() time.Time
}

type assistUser struct {
	grant   *assistGrant
	log     []ipc.ActivityEntry // newest first
	pending map[*struct{}]context.CancelFunc
}

// assistGrant is one open access. until is zero for "until the app closes";
// owner is the agent connection that opened it, and its loss closes access.
type assistGrant struct {
	until  time.Time
	groups map[string]bool
	owner  *ipc.Conn
}

func (a *assistState) now() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
}

// userLocked returns uid's state, creating it. Call with a.mu held.
func (a *assistState) userLocked(uid uint32) *assistUser {
	if a.users == nil {
		a.users = map[uint32]*assistUser{}
	}
	u := a.users[uid]
	if u == nil {
		u = &assistUser{pending: map[*struct{}]context.CancelFunc{}}
		a.users[uid] = u
	}
	return u
}

// cancelPendingLocked cancels the approvals waiting for u.
func (u *assistUser) cancelPendingLocked() {
	for _, cancel := range u.pending {
		cancel()
	}
}

// set opens access for uid, replacing an earlier grant: approvals waiting
// under the old one are cancelled. minutes is 15, 60 or 0 (until the owner
// connection closes); groups are the permission groups that are on.
func (a *assistState) set(uid uint32, owner *ipc.Conn, g ipc.AssistGrant, now time.Time) error {
	if g.Minutes != 0 && g.Minutes != 15 && g.Minutes != 60 {
		return errBadRequest
	}
	groups := map[string]bool{}
	for _, name := range g.Groups {
		switch name {
		case ipc.GroupKeys, ipc.GroupTunnels, ipc.GroupConnect:
			groups[name] = true
		default:
			return errBadRequest
		}
	}
	if owner != nil {
		select {
		case <-owner.Done():
			return &ipc.Error{Code: ipc.CodeAccessOff, Message: msg.AssistAccessOff}
		default:
		}
	}
	n := &assistGrant{groups: groups, owner: owner}
	if g.Minutes > 0 {
		n.until = now.Add(time.Duration(g.Minutes) * time.Minute)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.userLocked(uid)
	u.cancelPendingLocked()
	u.grant = n
	return nil
}

// revoke closes uid's access and cancels the approvals waiting for it.
func (a *assistState) revoke(uid uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.userLocked(uid)
	u.grant = nil
	u.cancelPendingLocked()
}

// dropOwner closes the access that c opened, if any.
func (a *assistState) dropOwner(c *ipc.Conn) {
	if c == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if u.grant != nil && u.grant.owner == c {
			u.grant = nil
			u.cancelPendingLocked()
		}
	}
}

// owner returns the connection that opened uid's current grant, or nil when
// uid has no grant. An expired grant still names its owner: callers check
// allowed for the time limit.
func (a *assistState) owner(uid uint32) *ipc.Conn {
	a.mu.Lock()
	defer a.mu.Unlock()
	if u := a.users[uid]; u != nil && u.grant != nil {
		return u.grant.owner
	}
	return nil
}

// allowed reports whether uid's agent may use a tool of group at now. An
// empty group is a read-only tool: it needs open access, no group.
func (a *assistState) allowed(uid uint32, group string, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var g *assistGrant
	if u := a.users[uid]; u != nil {
		g = u.grant
	}
	if g == nil || (!g.until.IsZero() && !now.Before(g.until)) {
		return &ipc.Error{Code: ipc.CodeAccessOff, Message: msg.AssistAccessOff}
	}
	if group != "" && !g.groups[group] {
		return &ipc.Error{Code: ipc.CodeAccessOff, Message: fmt.Sprintf(msg.AssistGroupOffFmt, group)}
	}
	return nil
}

// record adds e to uid's activity list and to the daemon log. Only what the
// caller put in e is written: callers pass summaries without secrets.
func (a *assistState) record(uid uint32, e ipc.ActivityEntry) {
	if e.Time.IsZero() {
		e.Time = a.now()
	}
	a.mu.Lock()
	u := a.userLocked(uid)
	u.log = slices.Insert(u.log, 0, e)
	if len(u.log) > assistKeep {
		u.log = u.log[:assistKeep]
	}
	a.mu.Unlock()
	log.Printf("daemon: assist: uid %d %s %s: %s (%s)", uid, e.Client, e.Tool, e.Result, e.Summary)
}

// activity returns uid's last tool calls, newest first.
func (a *assistState) activity(uid uint32) []ipc.ActivityEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if u := a.users[uid]; u != nil {
		return slices.Clone(u.log)
	}
	return nil
}

// pending returns a context for an approval of uid's that revoke, dropOwner
// of the owner connection and a new grant cancel. The caller must call the
// returned func when done: it frees the context.
func (a *assistState) pending(uid uint32) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	key := new(struct{})
	a.mu.Lock()
	u := a.userLocked(uid)
	if g := u.grant; g == nil || (!g.until.IsZero() && !a.now().Before(g.until)) {
		// No open access: nothing could cancel this later.
		a.mu.Unlock()
		cancel()
		return ctx, func() {}
	}
	u.pending[key] = cancel
	a.mu.Unlock()
	return ctx, func() {
		a.mu.Lock()
		delete(u.pending, key)
		a.mu.Unlock()
		cancel()
	}
}

// handleAssist registers the methods of the desktop agent that manage access.
func (m *Manager) handleAssist(c *ipc.Conn) {
	c.Handle(ipc.MethodAssistGrant, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		var g ipc.AssistGrant
		if err := decode(params, &g); err != nil {
			return nil, err
		}
		// Check and store under one m.mu section: dropAgent closes the
		// owner's access under the same lock, so a grant never outlives
		// its connection. Lock order: m.mu, then assist.mu.
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.assistAgentLocked(c, uid) {
			return nil, errForbidden
		}
		return nil, m.assist.set(uid, c, g, m.assist.now())
	})
	c.Handle(ipc.MethodAssistRevoke, func(_ context.Context, uid uint32, _ json.RawMessage) (any, error) {
		m.assist.revoke(uid)
		return nil, nil
	})
	c.Handle(ipc.MethodAssistActivity, func(_ context.Context, uid uint32, _ json.RawMessage) (any, error) {
		return ipc.AssistActivity{Entries: m.assist.activity(uid)}, nil
	})
}

// assistAgentLocked reports whether c is a registered agent of uid that
// reported CapAssist and never made an assist call. Call with m.mu held.
func (m *Manager) assistAgentLocked(c *ipc.Conn, uid uint32) bool {
	a := m.agents[c]
	return a != nil && a.seq != 0 && a.uid == uid && a.caps[ipc.CapAssist] && !m.assistCallers[c]
}

// markAssistCaller records that c made an assist.call: a connection that
// drives tools is never an access owner, so its grant is refused and any
// it holds is closed.
func (m *Manager) markAssistCaller(c *ipc.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.assistCallers == nil {
		m.assistCallers = map[*ipc.Conn]bool{}
	}
	m.assistCallers[c] = true
	m.assist.dropOwner(c)
}
