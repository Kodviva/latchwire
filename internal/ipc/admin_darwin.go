package ipc

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// adminGID is the fixed gid of the macOS "admin" group.
const adminGID = "80"

// IsAdmin reports whether uid may manage tunnels: root, or a member of the
// macOS "admin" group. Membership is asked of the directory service, which
// also covers nested groups and network accounts.
func IsAdmin(uid uint32) (bool, error) {
	if uid == 0 {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/dsmemberutil",
		"checkmembership", "-u", strconv.FormatUint(uint64(uid), 10), "-g", adminGID).Output()
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(out)) {
	case "user is a member of the group":
		return true, nil
	case "user is not a member of the group":
		return false, nil
	}
	return false, errors.New("ipc: unexpected dsmemberutil output")
}
