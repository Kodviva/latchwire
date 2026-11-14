//go:build !demo

package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kodviva/latchwire/desktop/ui"
	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyprovider/piv"
	"github.com/Kodviva/latchwire/internal/msg"
)

// agentPoll is the same as the CLI's agent: card removal closes a tunnel
// within 2 seconds.
const agentPoll = time.Second

type backend struct {
	desktop.Cards
	*desktop.Client

	// agent is the app's agent once runAgent made it. Agent access is
	// opened and closed over its daemon connection: the daemon ties the
	// access to that connection.
	agent atomic.Pointer[agent.Agent]

	mu      sync.Mutex
	granted *ipc.Conn // the connection the last grant went over
}

var theBackend = &backend{Cards: desktop.RealCards(), Client: desktop.NewClient()}

func options() ui.Options {
	return ui.Options{Backend: theBackend}
}

// runAgent is the same agent as latchwire agent; only the prompter differs,
// and it offers the daemon the approval window and the card operations.
func runAgent(ctx context.Context, u *ui.UI) {
	a := agent.New(daemon.DefaultSocket, piv.Backend{}, u.Prompter(), agentPoll).WithAssistant(newAssistant(u))
	theBackend.agent.Store(a)
	a.Run(ctx)
}

var errNoAgent = errors.New(msg.AssistAppNotConnected)

// accessErr is the text to show for an error of the agent connection.
func accessErr(err error) error {
	var ie *ipc.Error
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ipc.ErrClosed):
		return errNoAgent
	case errors.As(err, &ie):
		return errors.New(ie.Message)
	}
	return err
}

// Grant implements ui.Backend.
func (b *backend) Grant(ctx context.Context, g ipc.AssistGrant) error {
	a := b.agent.Load()
	if a == nil {
		return errNoAgent
	}
	c := a.Connection()
	if c == nil {
		return errNoAgent
	}
	if err := c.Call(ctx, ipc.MethodAssistGrant, g, nil); err != nil {
		return accessErr(err)
	}
	b.mu.Lock()
	b.granted = c
	b.mu.Unlock()
	return nil
}

// Revoke implements ui.Backend. Without a connection there is no access to
// close: the daemon ended it with the connection that opened it.
func (b *backend) Revoke(ctx context.Context) error {
	if a := b.agent.Load(); a != nil {
		err := a.Call(ctx, ipc.MethodAssistRevoke, nil, nil)
		if err != nil && !errors.Is(err, ipc.ErrClosed) {
			return accessErr(err) // still held, and shown as on
		}
	}
	b.mu.Lock()
	b.granted = nil
	b.mu.Unlock()
	return nil
}

// GrantHeld implements ui.Backend.
func (b *backend) GrantHeld() bool {
	b.mu.Lock()
	c := b.granted
	b.mu.Unlock()
	if c == nil {
		return false
	}
	select {
	case <-c.Done():
		return false
	default:
		return true
	}
}

// Activity implements ui.Backend.
func (b *backend) Activity(ctx context.Context) ([]ipc.ActivityEntry, error) {
	a := b.agent.Load()
	if a == nil {
		return nil, errNoAgent
	}
	var res ipc.AssistActivity
	if err := a.Call(ctx, ipc.MethodAssistActivity, nil, &res); err != nil {
		return nil, accessErr(err)
	}
	return res.Entries, nil
}
