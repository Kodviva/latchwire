//go:build !demo

package main

import (
	"context"
	"time"

	"github.com/Kodviva/latchwire/desktop/ui"
	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/keyprovider/piv"
)

// agentPoll is the same as the CLI's agent: card removal closes a tunnel
// within 2 seconds.
const agentPoll = time.Second

type backend struct {
	desktop.Cards
	*desktop.Client
}

func options() ui.Options {
	return ui.Options{Backend: backend{desktop.RealCards(), desktop.NewClient()}}
}

// runAgent is the same agent as latchwire agent; only the prompter differs.
func runAgent(ctx context.Context, u *ui.UI) {
	agent.New(daemon.DefaultSocket, piv.Backend{}, u.Prompter(), agentPoll).Run(ctx)
}
