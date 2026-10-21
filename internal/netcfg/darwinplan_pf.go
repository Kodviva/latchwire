package netcfg

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
)

// pfctlCmd is macOS's packet filter control command. Only the kill switch
// (package killswitch) journals pfctl steps; their undo is checked here
// because Cleanup runs them.
const pfctlCmd = "pfctl"

// pfctlUndone reports whether err from the pfctl undo step s says that
// there was nothing left to undo, which makes those steps idempotent:
//
//   - pfctl -a <anchor> -F all: an anchor that does not exist (never
//     loaded, flushed already, or gone with a reboot) makes pfctl report
//     "Anchor does not exist." (or "Table does not exist." for its tables);
//   - pfctl -X <token>: the kernel answers a token it does not hold with
//     EINVAL ("Invalid argument") and a stopped pf with ENOENT ("No such
//     file or directory"); a token is gone after its release, a reboot, or
//     pfctl -d, which drops every token.
//
// Without pfctl (exec.ErrNotFound) there is no pf to hold anything. The
// texts are the C-locale strerror texts the runner's LC_ALL=C gives, and
// pfctl's own wording (an assumption checked on a real Mac, see the
// manual checklist); anything else, such as a permission error, is a
// failure.
func pfctlUndone(s Step, err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return slices.Contains(s.Args, "-F") || slices.Contains(s.Args, "-X")
	}
	e := err.Error()
	switch {
	case slices.Contains(s.Args, "-F"):
		return strings.Contains(e, "does not exist")
	case slices.Contains(s.Args, "-X"):
		return strings.Contains(e, "Invalid argument") || strings.Contains(e, "No such file or directory") ||
			strings.Contains(e, "not enabled")
	}
	return false
}
