package ttyio

import (
	"os"

	"golang.org/x/sys/windows"
)

var (
	procGetConsoleWindow = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
	procIsWindowVisible  = windows.NewLazySystemDLL("user32.dll").NewProc("IsWindowVisible")
)

// Open opens the console.
func Open() (*Terminal, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	out, err := OpenOutput()
	if err != nil {
		in.Close()
		return nil, err
	}
	return &Terminal{In: in, Out: out}, nil
}

// OpenOutput opens the console for writing.
func OpenOutput() (*os.File, error) { return os.OpenFile("CONOUT$", os.O_RDWR, 0) }

// Interactive reports whether a person can see this process's console. A
// program started at logon has a console nobody sees, and a prompt there
// would wait for ever. (Windows Terminal hides the console too, so a prompt
// started there uses the dialog, which works just as well.)
func Interactive() bool {
	w, _, _ := procGetConsoleWindow.Call()
	if w == 0 {
		return false
	}
	if v, _, _ := procIsWindowVisible.Call(w); v == 0 {
		return false
	}
	t, err := Open()
	if err != nil {
		return false
	}
	t.Close()
	return true
}
