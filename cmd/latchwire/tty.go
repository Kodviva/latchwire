package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/Kodviva/latchwire/internal/msg"
)

// readSecretTTY asks on the controlling terminal with echo off. The error
// is about the terminal and never contains the input.
func readSecretTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New(msg.AgentNoTTY)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	defer clear(b)
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return string(bytes.TrimRight(b, "\r\n")), nil
}
