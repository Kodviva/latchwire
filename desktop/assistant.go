//go:build !demo

package main

import (
	"context"
	"errors"

	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// assistUI is what the assistant needs from the window (*ui.UI).
type assistUI interface {
	Approve(ctx context.Context, r ipc.ApproveRequest) (bool, error)
	CardList() ([]ipc.CardEntry, error)
	KeygenFor(ctx context.Context, serial uint32, slot uint8) (desktop.Key, error)
	Notice(step string)
}

// assistant is the app's agent.Assistant: the approval window and the card
// operations the daemon asks for on behalf of a local agent. The agent
// cancels a request's ctx on assist.abort, also for an abort that came
// first, and the window or forms close with it.
type assistant struct{ ui assistUI }

var _ agent.Assistant = assistant{}

func newAssistant(u assistUI) assistant { return assistant{u} }

func (s assistant) Approve(ctx context.Context, r ipc.ApproveRequest) (bool, error) {
	if ctx.Err() != nil {
		return false, nil
	}
	return s.ui.Approve(ctx, r)
}

func (s assistant) Cards() ([]ipc.CardEntry, error) { return s.ui.CardList() }

// errKeygenCancelled is what the daemon hears when the person closed a form
// or the request ended. Keygen's other errors are fixed texts and card
// errors: no form value reaches them.
var errKeygenCancelled = &ipc.Error{Code: ipc.CodeCancelled, Message: msg.AssistKeygenCancelled}

func (s assistant) Keygen(ctx context.Context, serial uint32, slot uint8) (string, [32]byte, error) {
	if ctx.Err() != nil {
		return "", [32]byte{}, errKeygenCancelled
	}
	k, err := s.ui.KeygenFor(ctx, serial, slot)
	switch {
	case errors.Is(err, desktop.ErrCancelled) || (err != nil && ctx.Err() != nil):
		return "", [32]byte{}, errKeygenCancelled
	case err != nil:
		return "", [32]byte{}, err
	}
	return k.Ref.String(), k.Public, nil
}

func (s assistant) Notice(step string) { s.ui.Notice(step) }

// Abort needs nothing more: the agent has cancelled the request's ctx.
func (assistant) Abort(string) {}
