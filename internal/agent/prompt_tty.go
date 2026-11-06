package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/ttyio"
)

// ttyPrompter asks on the controlling terminal (/dev/tty) with echo off.
type ttyPrompter struct{}

// NewTTYPrompter returns a Prompter that reads the PIN from the controlling
// terminal without echo and writes warnings there (or to stderr when there
// is no terminal).
func NewTTYPrompter() Prompter { return ttyPrompter{} }

func (ttyPrompter) PIN(d keyprovider.Description, retriesLeft int) (string, error) {
	tty, err := ttyio.Open()
	if err != nil {
		return "", errors.New(msg.AgentNoTTY)
	}
	defer tty.Close()
	fmt.Fprintf(tty.Out, msg.AgentPINPromptFmt, d.Serial, d.Slot, retriesLeft)
	b, err := term.ReadPassword(int(tty.In.Fd()))
	fmt.Fprintln(tty.Out)
	defer clear(b)
	if err != nil {
		// The error is about the terminal; it never contains input.
		return "", fmt.Errorf("reading PIN: %w", err)
	}
	return string(bytes.TrimRight(b, "\r\n")), nil
}

func (ttyPrompter) Warn(m string) {
	var w io.Writer = os.Stderr
	if tty, err := ttyio.OpenOutput(); err == nil {
		defer tty.Close()
		w = tty
	}
	fmt.Fprintln(w, m)
}
