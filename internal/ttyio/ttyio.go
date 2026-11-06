// Package ttyio opens the terminal the user is at, for prompts that must
// not come from standard input: a pipe must never answer them.
package ttyio

import "os"

// Terminal is the open terminal. Unix has one file for both directions;
// Windows has an input and an output console.
type Terminal struct {
	In, Out *os.File
}

// Close closes the terminal.
func (t *Terminal) Close() {
	t.In.Close()
	if t.Out != t.In {
		t.Out.Close()
	}
}
