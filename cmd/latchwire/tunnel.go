package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// maxConfigBytes matches the limit the configuration parser applies.
const maxConfigBytes = 1 << 20

// withDaemon runs fn on a connection to the daemon.
func withDaemon(ctx context.Context, e *env, fn func(c rpcConn) error) error {
	c, err := e.dial(ctx)
	if err != nil {
		return daemonErr(err)
	}
	defer c.Close()
	return daemonErr(fn(c))
}

func cmdAdd(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("add <name> <file>", args, 2); err != nil {
		return err
	}
	name, file := args[0], args[1]
	text, err := readConfig(file)
	if err != nil {
		return err
	}
	return withDaemon(ctx, e, func(c rpcConn) error {
		if err := c.Call(ctx, ipc.MethodTunnelAdd, ipc.TunnelAdd{Name: name, Config: text}, nil); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, msg.AddedFmt+"\n", name)
		return nil
	})
}

func readConfig(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf(msg.AddReadFailedFmt, path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return "", fmt.Errorf(msg.AddReadFailedFmt, path, err)
	}
	if len(data) > maxConfigBytes {
		return "", fmt.Errorf(msg.ConfigTooLargeFmt, maxConfigBytes)
	}
	return string(data), nil
}

func cmdRemove(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("remove <name>", args, 1); err != nil {
		return err
	}
	name := args[0]
	return withDaemon(ctx, e, func(c rpcConn) error {
		if err := c.Call(ctx, ipc.MethodTunnelRemove, ipc.TunnelName{Name: name}, nil); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, msg.RemovedFmt+"\n", name)
		return nil
	})
}

func cmdUp(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("up <name>", args, 1); err != nil {
		return err
	}
	name := args[0]
	return withDaemon(ctx, e, func(c rpcConn) error {
		// The daemon answers when the tunnel is up, which can take as long
		// as the PIN prompt in the agent's terminal.
		fmt.Fprintf(e.stderr, msg.UpWaitingFmt+"\n", name)
		var st ipc.TunnelStatus
		if err := c.Call(ctx, ipc.MethodTunnelConnect, ipc.TunnelName{Name: name}, &st); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, msg.UpDoneFmt+"\n", name, st.State)
		return nil
	})
}

func cmdDown(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("down <name>", args, 1); err != nil {
		return err
	}
	name := args[0]
	return withDaemon(ctx, e, func(c rpcConn) error {
		// Ask first: for a tunnel that is not up, the daemon would tell a
		// non-administrator "not your tunnel", which is misleading.
		var sts []ipc.TunnelStatus
		if err := c.Call(ctx, ipc.MethodTunnelStatus, ipc.TunnelName{Name: name}, &sts); err != nil {
			return err
		}
		for _, st := range sts {
			if st.Name == name && (st.State == daemon.StateDisconnected || st.State == daemon.StateError) {
				fmt.Fprintf(e.stdout, msg.DownAlreadyFmt+"\n", name)
				return nil
			}
		}
		var st ipc.TunnelStatus
		if err := c.Call(ctx, ipc.MethodTunnelDisconnect, ipc.TunnelName{Name: name}, &st); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, msg.DownDoneFmt+"\n", name)
		return nil
	})
}

func cmdStatus(ctx context.Context, e *env, args []string) error {
	if len(args) > 1 {
		return wantArgs("status [name]", args, 1)
	}
	var params any
	if len(args) == 1 {
		params = ipc.TunnelName{Name: args[0]}
	}
	return withDaemon(ctx, e, func(c rpcConn) error {
		var sts []ipc.TunnelStatus
		if err := c.Call(ctx, ipc.MethodTunnelStatus, params, &sts); err != nil {
			return err
		}
		if len(sts) == 0 {
			fmt.Fprintln(e.stdout, msg.StatusNone)
			return nil
		}
		w := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, msg.StatusHeader)
		for _, st := range sts {
			id, hs := st.Identity, st.LastHandshake
			if id == "" {
				id = msg.StatusDash
			}
			if hs == "" {
				hs = msg.StatusDash
			}
			fmt.Fprintf(w, msg.StatusRowFmt+"\n", st.Name, st.State, id, hs)
		}
		return w.Flush()
	})
}
