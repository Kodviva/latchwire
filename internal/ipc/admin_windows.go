package ipc

// IsAdmin reports whether uid may manage tunnels. Only uid 0 may: classifyPeer
// gives it to LocalSystem and to tokens with BUILTIN\Administrators enabled,
// which is what UAC elevation means. A member of Administrators that is not
// elevated has a filtered token and is an ordinary user here, so a program
// running in that user's session cannot change tunnels without a prompt.
func IsAdmin(uid uint32) (bool, error) { return uid == 0, nil }
