package main

import (
	"context"
	"fmt"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netmon"
)

// cmdNetwork prints the ID of the network the machine is on, as the daemon
// sees it: what --trust-network takes. "none" and "unknown" get a note on
// stderr, since they cannot be trusted.
func cmdNetwork(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("network", args, 0); err != nil {
		return err
	}
	return withDaemon(ctx, e, func(c rpcConn) error {
		id, err := currentNetwork(ctx, c)
		if err != nil {
			return err
		}
		fmt.Fprintln(e.stdout, id)
		if id == netmon.NoNetwork || id == netmon.UnknownNetwork {
			fmt.Fprintf(e.stderr, msg.NetworkUntrustableNoteFmt+"\n", id)
		}
		return nil
	})
}

// currentNetwork asks the daemon for the current network ID.
func currentNetwork(ctx context.Context, c rpcConn) (string, error) {
	var nc ipc.NetworkCurrent
	if err := c.Call(ctx, ipc.MethodNetworkCurrent, nil, &nc); err != nil {
		return "", err
	}
	return nc.ID, nil
}
