// Package mcpserver is the MCP server of latchwire mcp: the tools a local
// agent calls to set Latchwire up. It keeps no state and decides nothing:
// every tool goes to the daemon's assist.call, which checks access, asks
// the user for approval and records the call. The pure parts (the
// configuration text, the [Peer] block, the server guide) are computed
// here, peer_block and server_guide only after the daemon allowed them.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Version is the version the server reports to its clients.
var Version = "dev"

// progressInterval is how often a long call (create_key, add_tunnel,
// connect) tells a client that asked for progress that it is still
// waiting, so the client keeps the call alive. A variable for tests.
var progressInterval = 10 * time.Second

// Dialer opens a new connection to the daemon. The connection is not yet
// served: the server serves it for one tool call and closes it afterwards.
type Dialer func(ctx context.Context) (*ipc.Conn, error)

// New returns the MCP server with the Latchwire tools. Every tool call has
// a daemon connection of its own, opened with dial and closed when the call
// ends: when the client cancels the call, the daemon sees the connection
// close and cancels what it was doing.
func New(dial func(ctx context.Context) (*ipc.Conn, error)) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "latchwire", Title: "Latchwire", Version: Version}, nil)
	addTools(s, &daemon{dial: dial})
	return s
}

// daemon forwards tool calls to the daemon.
type daemon struct {
	dial Dialer
}

// clientName is the MCP client's name from its initialize request.
func clientName(req *mcp.CallToolRequest) string {
	if req != nil && req.Session != nil {
		if p := req.Session.InitializeParams(); p != nil && p.ClientInfo != nil && p.ClientInfo.Name != "" {
			return p.ClientInfo.Name
		}
	}
	return "unknown"
}

// call runs tool with args on the daemon over a connection of its own. With
// progress set and a progress token in the request, it notifies the client
// every progressInterval while it waits.
func (d *daemon) call(ctx context.Context, req *mcp.CallToolRequest, tool string, args any, progress bool) (ipc.AssistResult, error) {
	var res ipc.AssistResult
	p := ipc.AssistCall{Client: clientName(req), Tool: tool}
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return res, err
		}
		p.Args = b
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c, err := d.dial(ctx)
	if err != nil {
		return res, err
	}
	defer c.Close()
	// Serve closes c when ctx ends, which is how a cancelled call reaches
	// the daemon.
	go c.Serve(ctx)

	if progress {
		if stop := notifyProgress(ctx, req); stop != nil {
			defer stop()
		}
	}
	err = c.Call(ctx, ipc.MethodAssistCall, p, &res)
	return res, toolErr(err)
}

// notifyProgress sends a progress notification every progressInterval
// until the returned function is called, if the request carries a
// progress token; else it returns nil.
func notifyProgress(ctx context.Context, req *mcp.CallToolRequest) (stop func()) {
	if req == nil || req.Session == nil || req.Params == nil {
		return nil
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return nil
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(progressInterval)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				n++
				req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
					ProgressToken: token,
					Progress:      float64(n),
					Message:       progressMessage,
				})
			}
		}
	}()
	return func() { close(done); <-finished }
}

// progressMessage tells the agent what the call waits for.
const progressMessage = "waiting for the user in the Latchwire app"

// toolErr turns a failed daemon call into the error the agent sees: the
// daemon's message for its own errors, which say what to tell the user.
func toolErr(err error) error {
	var ie *ipc.Error
	switch {
	case errors.As(err, &ie) && ie.Code == ipc.CodeNotFound && ie.Message == ipc.UnknownMethod:
		return errors.New(msg.AssistDaemonTooOld)
	case errors.As(err, &ie):
		return errors.New(ie.Message)
	}
	return err
}
