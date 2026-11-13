package daemon

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// agentView is what the connect log needs to know about one agent
// connection: who runs it, the cards it reports and whether the connection
// has closed without being dropped yet.
type agentView struct {
	seq     uint64
	uid     uint32
	serials []uint32
	closed  bool
}

// describeAgents says which registered agents of uid exist and which of
// them reports serial, so a "not connected" failure in the log tells an
// agent that never registered the card apart from one whose connection
// closed. Agents are listed in registration order; unregistered ones are
// left out.
func describeAgents(uid, serial uint32, views []agentView) string {
	var mine []agentView
	for _, v := range views {
		if v.uid == uid && v.seq != 0 {
			mine = append(mine, v)
		}
	}
	if len(mine) == 0 {
		return fmt.Sprintf("agents of uid %d: none", uid)
	}
	slices.SortFunc(mine, func(a, b agentView) int { return cmp.Compare(a.seq, b.seq) })
	var parts, holders []string
	for _, v := range mine {
		s := slices.Clone(v.serials)
		slices.Sort(s)
		p := fmt.Sprintf("#%d cards %v", v.seq, s)
		if v.closed {
			p += " closed"
		}
		parts = append(parts, p)
		if slices.Contains(s, serial) {
			holders = append(holders, fmt.Sprintf("#%d", v.seq))
		}
	}
	tail := fmt.Sprintf("no agent reports card %d", serial)
	if len(holders) > 0 {
		tail = fmt.Sprintf("card %d reported by %s", serial, strings.Join(holders, ", "))
	}
	return fmt.Sprintf("agents of uid %d: %s; %s", uid, strings.Join(parts, ", "), tail)
}

// agentsSummary describes the agents of uid for the log.
func (m *Manager) agentsSummary(uid, serial uint32) string {
	m.mu.Lock()
	views := make([]agentView, 0, len(m.agents))
	for c, a := range m.agents {
		v := agentView{seq: a.seq, uid: a.uid}
		for s := range a.serials {
			v.serials = append(v.serials, s)
		}
		select {
		case <-c.Done():
			v.closed = true
		default:
		}
		views = append(views, v)
	}
	m.mu.Unlock()
	return describeAgents(uid, serial, views)
}
