//go:build !demo

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

func TestAccessErr(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{ipc.ErrClosed, msg.AssistAppNotConnected},
		// A daemon that predates agent access does not know the method.
		{&ipc.Error{Code: ipc.CodeNotFound, Message: ipc.UnknownMethod}, msg.AssistServiceTooOld},
		{fmt.Errorf("call: %w", &ipc.Error{Code: ipc.CodeNotFound, Message: ipc.UnknownMethod}), msg.AssistServiceTooOld},
		{&ipc.Error{Code: ipc.CodeNotFound, Message: "no such tunnel"}, "no such tunnel"},
		{&ipc.Error{Code: ipc.CodeForbidden, Message: "forbidden"}, "forbidden"},
	} {
		if got := accessErr(c.err); got == nil || got.Error() != c.want {
			t.Errorf("accessErr(%v) = %v, want %q", c.err, got, c.want)
		}
	}
	if accessErr(nil) != nil {
		t.Error("accessErr(nil) is not nil")
	}
	if err := errors.New("x"); accessErr(err) != err {
		t.Error("a plain error changed")
	}
}
