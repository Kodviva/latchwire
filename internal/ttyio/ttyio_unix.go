//go:build !windows

package ttyio

import "os"

// Open opens the controlling terminal.
func Open() (*Terminal, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Terminal{In: f, Out: f}, nil
}

// OpenOutput opens the controlling terminal for writing.
func OpenOutput() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_WRONLY, 0) }

// Interactive reports whether there is a terminal to ask on.
func Interactive() bool {
	t, err := Open()
	if err != nil {
		return false
	}
	t.Close()
	return true
}
