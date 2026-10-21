//go:build !darwin && !linux

package agent

import "github.com/Kodviva/latchwire/internal/msg"

// newGUIPrompter: this system has no supported PIN dialog.
func newGUIPrompter() Prompter { return noPrompter{reason: msg.AgentNoPINDialog} }
