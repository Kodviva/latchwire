package daemon

import (
	"context"
	"encoding/json"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// addOwner is the user a tunnel is added for: the one the CLI names (it
// knows SUDO_UID), or the user behind an elevated Windows client, which the
// connection knows and the CLI does not.
func addOwner(named, elevated uint32) uint32 {
	if named != 0 {
		return named
	}
	return elevated
}

// handleUsers registers the methods that translate between Windows user
// names and uids: only the daemon holds the table. Unix has none and needs
// none.
func (m *Manager) handleUsers(c *ipc.Conn) {
	if m.users == nil {
		return
	}
	c.Handle(ipc.MethodUserID, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		if !m.admin(uid) {
			return nil, errAdminOnly
		}
		var p ipc.UserInfo
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		id, err := m.users.Assign(p.SID)
		if err != nil {
			return nil, &ipc.Error{Code: ipc.CodeBadRequest, Message: err.Error()}
		}
		return ipc.UserInfo{UID: id, SID: p.SID}, nil
	})
	c.Handle(ipc.MethodUserSID, func(_ context.Context, uid uint32, params json.RawMessage) (any, error) {
		if !m.user(uid) {
			return nil, errForbidden
		}
		var p ipc.UserInfo
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		sid, ok := m.users.SID(p.UID)
		if !ok {
			return nil, &ipc.Error{Code: ipc.CodeNotFound, Message: msg.PolicyNoSuchUser}
		}
		return ipc.UserInfo{UID: p.UID, SID: sid}, nil
	})
}
