//go:build !windows

package main

import (
	"os"

	"github.com/Kodviva/latchwire/internal/msg"
)

const (
	usage            = msg.CLIUsage
	daemonMustBeRoot = msg.DaemonMustBeRoot
	daemonNotRunning = msg.CLIDaemonNotRunning
)

// effectiveUID is env.geteuid in production.
func effectiveUID() int { return os.Geteuid() }

// runAsService: only Windows starts the daemon that way.
func runAsService() (code int, ok bool) { return 0, false }

func addPlatformCommands(map[string]command) {}
