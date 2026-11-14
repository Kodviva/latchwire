package main

import (
	"context"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/mcpserver"
	"github.com/Kodviva/latchwire/internal/msg"
)

// cmdMCP serves the agent tools over stdio to the MCP client that started
// it. Nothing else may write to stdout: it carries the protocol.
func cmdMCP(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("mcp", args, 0); err != nil {
		return err
	}
	return stopped(e.runMCP(ctx))
}

func runMCP(ctx context.Context) error {
	mcpserver.Version = version
	return mcpserver.New(dialMCP).Run(ctx, &mcp.StdioTransport{})
}

// dialMCP opens the connection of one tool call to the daemon, which only
// root (the daemon) or this user may serve. The server serves it.
func dialMCP(context.Context) (*ipc.Conn, error) {
	c, err := ipc.Dial(daemon.DefaultSocket)
	if err != nil {
		return nil, daemonErr(err)
	}
	if uid := c.PeerUID(); uid != 0 && int64(uid) != int64(os.Getuid()) {
		c.Close()
		return nil, fmt.Errorf(msg.CLIUntrustedDaemonFmt, uid)
	}
	return c, nil
}
