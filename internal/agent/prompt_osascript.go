package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
)

// osascript PIN dialog (macOS). This file has no build tag so that its tests
// run on every system; prompt_darwin.go selects it.

const osascriptPath = "/usr/bin/osascript"

// osascriptEnv is the whole environment of osascript.
var osascriptEnv = []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}

// osascriptPINScript is fed on stdin ("osascript -"). Its arguments are
// display texts only: the message, the title, the OK and Cancel button
// names and the seconds after which the dialog gives up. The answer is
// printed on stdout. Cancel raises error -128 ("User canceled."); giving
// up is turned into the same error.
const osascriptPINScript = `on run argv
	set {msgText, titleText, okText, cancelText, waitSecs} to argv
	activate
	set r to display dialog msgText with title titleText default answer "" with hidden answer buttons {cancelText, okText} default button okText cancel button cancelText with icon caution giving up after (waitSecs as integer)
	if gave up of r then error number -128
	return text returned of r
end run
`

// osascriptNotifyScript shows a warning as a notification (best effort).
// Arguments: the message and the title.
const osascriptNotifyScript = `on run argv
	display notification (item 1 of argv) with title (item 2 of argv)
end run
`

// osascriptCancelled is in osascript's error output when the user pressed
// Cancel (or the dialog gave up).
const osascriptCancelled = "(-128)"

// notifyTimeout bounds one notification.
const notifyTimeout = 10 * time.Second

type osascriptPrompter struct {
	// run runs osascript; runChild with osascriptEnv in production.
	run     func(ctx context.Context, path string, args []string, stdin []byte) ([]byte, error)
	timeout time.Duration
}

func newOsascriptPrompter() *osascriptPrompter {
	return &osascriptPrompter{
		run: func(ctx context.Context, path string, args []string, stdin []byte) ([]byte, error) {
			return runChild(ctx, path, args, stdin, osascriptEnv)
		},
		timeout: dialogTimeout,
	}
}

func (p *osascriptPrompter) PIN(d keyprovider.Description, retriesLeft int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout+childGrace)
	defer cancel()
	secs := max(1, int(p.timeout/time.Second))
	args := []string{"-", dialogText(d, retriesLeft), msg.AgentPINDialogTitle,
		msg.AgentPINDialogOK, msg.AgentPINDialogCancel, strconv.Itoa(secs)}
	out, err := p.run(ctx, osascriptPath, args, []byte(osascriptPINScript))
	defer clear(out)
	if err != nil {
		var ce *childError
		if errors.As(err, &ce) && strings.Contains(ce.stderr, osascriptCancelled) {
			return "", keyprovider.ErrPINRequired
		}
		if ctx.Err() != nil {
			// The dialog outlived its own timeout and was killed. Not
			// wrapped: the agent would report a context error as an
			// expired request.
			return "", fmt.Errorf("%w: the PIN dialog did not answer in time (%v)", keyprovider.ErrPINRequired, ctx.Err())
		}
		return "", fmt.Errorf("PIN dialog: %w", err)
	}
	// osascript ends its result with one newline; everything before it is
	// the answer as typed.
	pin, ok := bytes.CutSuffix(out, []byte("\n"))
	if !ok {
		return "", errors.New("PIN dialog: unexpected output from osascript")
	}
	return string(pin), nil
}

// Warn logs m and shows it as a notification, since a dialog user does
// not see the log.
func (p *osascriptPrompter) Warn(m string) {
	log.Print(m)
	ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
	defer cancel()
	out, err := p.run(ctx, osascriptPath, []string{"-", m, msg.AgentPINDialogTitle}, []byte(osascriptNotifyScript))
	clear(out)
	if err != nil {
		log.Printf("showing a notification: %v", err)
	}
}
