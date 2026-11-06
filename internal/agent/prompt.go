package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/ttyio"
)

// PIN prompts without a terminal. When the agent runs as a login item
// (launchd LaunchAgent, systemd user unit, a logon task) it has no terminal
// the user can see, so the PIN is asked with the desktop's own dialog
// program: osascript on macOS, pinentry on Linux, and on Windows a window of
// its own, since Windows has no such program (prompt_windows.go; of the
// rules below, the last two apply). Rules for these dialogs:
//   - The PIN never appears in a child's arguments or environment. The
//     osascript program comes on stdin and only non-secret display text is
//     passed as arguments; the PIN comes back on the child's stdout (or as
//     an Assuan D line from pinentry).
//   - Children are run by absolute path, never through PATH or a shell,
//     with a fixed environment, and are always killed and waited for.
//   - The PIN is read into fixed-size buffers that are wiped afterwards.
//   - Cancelling (or the dialog timing out) is keyprovider.ErrPINRequired,
//     which the agent treats like an unanswered prompt (Plan 1 PIN rules).

const (
	// dialogTimeout is how long a PIN dialog waits for the user before it
	// gives up by itself (counts as cancelled). Together with childGrace it
	// must stay below the daemon's warmUpTimeout (internal/daemon,
	// 2 minutes), the longest the daemon waits for a PIN: a PIN typed after
	// the daemon gave up would still reach the card for nothing.
	dialogTimeout = 100 * time.Second
	// childGrace is the extra time a dialog child gets beyond its own
	// timeout before it is killed.
	childGrace = 10 * time.Second
	// childWaitDelay bounds the wait for a killed child's output pipes.
	childWaitDelay = 2 * time.Second
	// maxChildOutput caps the stdout and the stderr kept from a child.
	maxChildOutput = 4 << 10
)

// NewPrompter returns the Prompter for the way the agent was started: the
// terminal when there is one (started from a shell), otherwise the system's
// PIN dialog (osascript on macOS, pinentry on Linux, a window on Windows).
func NewPrompter() Prompter { return choosePrompter(haveTTY, newGUIPrompter) }

func choosePrompter(tty func() bool, gui func() Prompter) Prompter {
	if tty() {
		return NewTTYPrompter()
	}
	return gui()
}

// haveTTY reports whether there is a terminal to ask on.
func haveTTY() bool { return ttyio.Interactive() }

// dialogText is the body of a PIN dialog. With one attempt left it carries
// the last-retry warning too, since a dialog user does not see the log.
func dialogText(d keyprovider.Description, retriesLeft int) string {
	s := fmt.Sprintf(msg.AgentPINDialogFmt, d.Serial, d.Slot, retriesLeft)
	if retriesLeft == 1 {
		s += "\n\n" + msg.LastPINRetry
	}
	return s
}

// noPrompter is used when there is neither a terminal nor a dialog program:
// every PIN request ends as "PIN required"; the agent logs the request's
// error, which carries the reason.
type noPrompter struct{ reason string }

func (p noPrompter) PIN(keyprovider.Description, int) (string, error) {
	return "", fmt.Errorf("%w: %s", keyprovider.ErrPINRequired, p.reason)
}

func (noPrompter) Warn(m string) { log.Print(m) }

// limitBuffer keeps the first cap(buf) bytes written (a child's error
// output) and drops the rest.
type limitBuffer struct{ buf []byte }

func newLimitBuffer(n int) *limitBuffer { return &limitBuffer{buf: make([]byte, 0, n)} }

func (l *limitBuffer) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p[:min(len(p), cap(l.buf)-len(l.buf))]...)
	// Everything counts as written so the child does not get a broken pipe.
	return len(p), nil
}

// childError is a dialog child that failed; stderr is its (capped) error
// output, which never carries the PIN.
type childError struct {
	err    error
	stderr string
}

func (e *childError) Error() string {
	if e.stderr == "" {
		return e.err.Error()
	}
	return e.err.Error() + ": " + e.stderr
}

func (e *childError) Unwrap() error { return e.err }

// childCommand returns the command for a dialog child: path with args and
// exactly the environment env, killed when ctx ends.
func childCommand(ctx context.Context, path string, args []string, env []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	// A nil Env would inherit the agent's environment.
	cmd.Env = append([]string{}, env...)
	cmd.WaitDelay = childWaitDelay
	return cmd
}

// runChild runs cmd (from childCommand with the same ctx) with stdin and
// returns its stdout. The caller wipes the returned bytes. Output beyond
// maxChildOutput is an error.
//
// stdout is read here from a pipe straight into one fixed buffer: with an
// io.Writer as Stdout, exec would copy the output (the PIN) through its own
// buffer, which cannot be wiped.
func runChild(ctx context.Context, cmd *exec.Cmd, stdin []byte) ([]byte, error) {
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer outR.Close()
	stderr := newLimitBuffer(maxChildOutput)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = outW, stderr
	err = cmd.Start()
	outW.Close()
	if err != nil {
		return nil, &childError{err: err}
	}
	if deadline, ok := ctx.Deadline(); ok {
		// A grandchild holding the pipe cannot block past ctx.
		_ = outR.SetReadDeadline(deadline)
	}
	buf := make([]byte, maxChildOutput)
	n, overflow := 0, false
	for {
		if n == len(buf) {
			overflow = true
			break
		}
		m, rerr := outR.Read(buf[n:])
		n += m
		if rerr != nil {
			break
		}
	}
	if overflow {
		cmd.Process.Kill()
	}
	err = cmd.Wait()
	switch {
	case overflow:
		clear(buf)
		return nil, errors.New(msg.AgentPINDialogLong)
	case err != nil:
		clear(buf)
		return nil, &childError{err: err, stderr: strings.TrimSpace(string(stderr.buf))}
	}
	return buf[:n], nil
}
