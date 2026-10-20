package ipc

import (
	"errors"
	"os/user"
	"strconv"
)

// adminGroups are the groups whose members may manage tunnels, besides root.
var adminGroups = []string{"sudo", "wheel", "latchwire"}

// IsAdmin reports whether uid may manage tunnels: root, or a member of one of
// the sudo, wheel or latchwire groups. A uid without an account is not an
// admin.
func IsAdmin(uid uint32) (bool, error) {
	if uid == 0 {
		return true, nil
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		var unk user.UnknownUserIdError
		if errors.As(err, &unk) {
			return false, nil
		}
		return false, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	member := make(map[string]bool, len(gids))
	for _, g := range gids {
		member[g] = true
	}
	for _, name := range adminGroups {
		g, err := user.LookupGroup(name)
		if err != nil {
			var unk user.UnknownGroupError
			if errors.As(err, &unk) {
				continue
			}
			return false, err
		}
		if member[g.Gid] {
			return true, nil
		}
	}
	return false, nil
}
