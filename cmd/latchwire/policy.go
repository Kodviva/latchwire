package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

const policySynopsis = "policy <name> [--kill-switch auto|on|off] [--auto-connect=true|false] [--on-demand=true|false]" +
	" [--trust-network ID] [--trust-current-network] [--untrust-network ID] [--allow-user NAME] [--deny-user NAME]\n" +
	msg.PolicyTrustWarning

// listFlag collects the values of a flag that may be given several times.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// cmdPolicy prints a tunnel's policy, or changes it (administrators) when
// flags are given. User names are resolved here; the daemon gets uids.
// --trust-current-network trusts the network the daemon sees now (network
// current), which must be an identified one (P10).
func cmdPolicy(ctx context.Context, e *env, args []string) error {
	fs := newFlagSet("policy")
	killSwitch := fs.String("kill-switch", "", "")
	autoConnect := fs.Bool("auto-connect", false, "")
	onDemand := fs.Bool("on-demand", false, "")
	trustCurrent := fs.Bool("trust-current-network", false, "")
	var trust, untrust, allow, deny listFlag
	fs.Var(&trust, "trust-network", "")
	fs.Var(&untrust, "untrust-network", "")
	fs.Var(&allow, "allow-user", "")
	fs.Var(&deny, "deny-user", "")
	pos, err := parseInterleaved(fs, policySynopsis, args)
	if err != nil {
		return err
	}
	if err := wantArgs(policySynopsis, pos, 1); err != nil {
		return err
	}
	set := ipc.TunnelPolicySet{Name: pos[0]}
	changed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "trust-current-network" && !*trustCurrent {
			return // --trust-current-network=false changes nothing
		}
		changed = true
		switch f.Name {
		case "auto-connect":
			set.AutoConnect = autoConnect
		case "on-demand":
			set.OnDemand = onDemand
		}
	})
	if changed {
		switch *killSwitch {
		case "":
			if setFlag(fs, "kill-switch") {
				return usageErr(policySynopsis, msg.PolicyBadKillSwitchFmt, *killSwitch)
			}
		case daemon.KillSwitchAuto, daemon.KillSwitchOn, daemon.KillSwitchOff:
			set.KillSwitch = *killSwitch
		default:
			return usageErr(policySynopsis, msg.PolicyBadKillSwitchFmt, *killSwitch)
		}
		for _, id := range trust {
			if err := daemon.ValidTrustedNetwork(id); err != nil {
				return &usageError{err: err, synopsis: policySynopsis}
			}
		}
		set.Trust, set.Untrust = trust, untrust
		if set.Allow, err = e.uids(allow); err != nil {
			return err
		}
		if set.Deny, err = e.uids(deny); err != nil {
			return err
		}
	}
	return withDaemon(ctx, e, func(c rpcConn) error {
		var p ipc.TunnelPolicy
		var err error
		if *trustCurrent {
			id, err := currentNetwork(ctx, c)
			if err != nil {
				return err
			}
			if err := daemon.ValidTrustedNetwork(id); err != nil {
				return err
			}
			set.Trust = append(set.Trust, id)
		}
		if changed {
			err = c.Call(ctx, ipc.MethodTunnelPolicySet, set, &p)
		} else {
			err = c.Call(ctx, ipc.MethodTunnelPolicyGet, ipc.TunnelName{Name: set.Name}, &p)
		}
		if err != nil {
			return err
		}
		e.printPolicy(p)
		if len(set.Trust) > 0 {
			fmt.Fprintln(e.stderr, msg.PolicyTrustWarning)
		}
		return nil
	})
}

// parseInterleaved parses flags that may come before and after the
// positional arguments, which it returns. After "--" everything is
// positional.
func parseInterleaved(fs *flag.FlagSet, synopsis string, args []string) ([]string, error) {
	var pos []string
	for {
		rest, err := parseFlags(fs, synopsis, args)
		if err != nil {
			return nil, err
		}
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// setFlag reports whether the flag name was given.
func setFlag(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) { found = found || f.Name == name })
	return found
}

// uids resolves user names (or decimal uids of users that no longer
// exist) to uids. An unknown name is a usage error.
func (e *env) uids(names []string) ([]uint32, error) {
	var out []uint32
	for _, name := range names {
		uid, err := e.lookupUser(name)
		if err != nil {
			n, perr := strconv.ParseUint(name, 10, 32)
			if perr != nil {
				return nil, usageErr(policySynopsis, msg.PolicyUnknownUserFmt, name)
			}
			uid = uint32(n)
		}
		out = append(out, uid)
	}
	return out, nil
}

func (e *env) printPolicy(p ipc.TunnelPolicy) {
	onOff := func(b bool) string {
		if b {
			return msg.PolicyOn
		}
		return msg.PolicyOff
	}
	nets := msg.PolicyNone
	if len(p.TrustedNetworks) > 0 {
		nets = strings.Join(p.TrustedNetworks, ", ")
	}
	users := msg.PolicyAdminsOnly
	if len(p.AllowedUsers) > 0 {
		var us []string
		for _, uid := range p.AllowedUsers {
			if name := e.userName(uid); name != "" {
				us = append(us, fmt.Sprintf(msg.PolicyUserFmt, name, uid))
			} else {
				us = append(us, strconv.FormatUint(uint64(uid), 10))
			}
		}
		users = strings.Join(us, ", ")
	}
	fmt.Fprintf(e.stdout, msg.PolicyPrintFmt+"\n", p.Name, p.KillSwitch, onOff(p.AutoConnect), onOff(p.OnDemand), nets, users)
	if p.KillSwitchInEffect != "" {
		fmt.Fprintf(e.stdout, msg.PolicyKillSwitchPendingFmt+"\n", p.Name, p.KillSwitchInEffect, p.KillSwitch)
	}
	if p.RevokedBlocking {
		fmt.Fprintf(e.stdout, msg.PolicyRevokedBlockingFmt+"\n", p.Name)
	}
}

// sudoUID is the user who ran this command through sudo (SUDO_UID), or 0.
func sudoUID(e *env) uint32 {
	n, err := strconv.ParseUint(e.getenv("SUDO_UID"), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// lookupUserID is env.lookupUser in production.
func lookupUserID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, errors.New("not a numeric uid")
	}
	return uint32(n), nil
}

// lookupUserName is env.userName in production.
func lookupUserName(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return ""
	}
	return u.Username
}
