package netcfg

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

// The kill switch's pfctl undo steps are idempotent: an anchor that is not
// there (flushed already) or a token pf no longer knows (released, or
// invalidated by pfctl -d or a reboot) is undone.
func TestPfctlAlreadyUndone(t *testing.T) {
	flush := Step{Name: "pfctl", Args: []string{"-a", "com.apple/250.latchwire", "-F", "all"}, Persistent: true}
	release := Step{Name: "pfctl", Args: []string{"-X", "18446742523466346583"}, Persistent: true}
	for _, tc := range []struct {
		s    Step
		err  error
		want bool
	}{
		{flush, errors.New("exit status 1: pfctl: Anchor does not exist."), true},
		{flush, errors.New("exit status 1: pfctl: Table does not exist."), true},
		{flush, fmt.Errorf("pfctl: %w", exec.ErrNotFound), true},
		{flush, errors.New("exit status 1: pfctl: /dev/pf: Permission denied"), false},
		{release, errors.New("exit status 1: pfctl: DIOCSTOPREF: Invalid argument"), true},
		{release, errors.New("exit status 1: pfctl: DIOCSTOPREF: No such file or directory"), true},
		{release, errors.New("exit status 1: pf not enabled"), true},
		{release, errors.New("exit status 1: pfctl: /dev/pf: Permission denied"), false},
		{Step{Name: "pfctl", Args: []string{"-a", "x", "-f", "-"}}, errors.New("exit status 1: Anchor does not exist."), false},
	} {
		if got := AlreadyUndone(tc.s, tc.err); got != tc.want {
			t.Errorf("AlreadyUndone(%s, %q) = %v, want %v", tc.s, tc.err, got, tc.want)
		}
	}
}
