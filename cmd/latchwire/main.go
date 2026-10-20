// Command latchwire is the Latchwire command line: it generates keys on a
// YubiKey, runs the user agent and the root daemon, and drives tunnels
// through the daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/piv"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// agentPoll is how often the agent looks for card changes (card removal
// closes a tunnel within 2 seconds).
const agentPoll = time.Second

// cardOps is the part of *piv.Card the commands use. Tests replace it.
type cardOps interface {
	Generate(piv.GenerateOptions) (keyref.Ref, [32]byte, error)
	Provider(ref keyref.Ref, prompt func(retriesLeft int) (string, error)) (keyprovider.Provider, error)
	Occupied(slot uint8) (bool, error)
	Close() error
}

// rpcConn is a connection to the daemon; *ipc.Conn-backed in production.
type rpcConn interface {
	Call(ctx context.Context, method string, params, result any) error
	Close() error
}

// env is everything the commands touch outside the process, so tests can
// replace it.
type env struct {
	stdout, stderr io.Writer
	// readSecret asks for a PIN or PUK without echo. The answer is only
	// ever passed on to the card.
	readSecret func(prompt string) (string, error)
	// readLine asks on the terminal with echo, for confirmations. It never
	// reads stdin, so a pipe cannot confirm.
	readLine    func(prompt string) (string, error)
	listDevices func() ([]piv.Device, error)
	openCard    func(serial uint32) (cardOps, error)
	dial        func(ctx context.Context) (rpcConn, error)
	geteuid     func() int
	runAgent    func(ctx context.Context) error
	runDaemon   func(ctx context.Context) error
}

func defaultEnv() *env {
	return &env{
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		readSecret:  readSecretTTY,
		readLine:    readLineTTY,
		listDevices: piv.List,
		openCard: func(serial uint32) (cardOps, error) {
			c, err := piv.Open(serial)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		dial:    dialDaemon,
		geteuid: os.Geteuid,
		runAgent: func(ctx context.Context) error {
			return agent.New(daemon.DefaultSocket, piv.Backend{}, agent.NewTTYPrompter(), agentPoll).Run(ctx)
		},
		runDaemon: func(ctx context.Context) error {
			return daemon.NewManager(daemon.Options{}).Serve(ctx)
		},
	}
}

// dialDaemon connects to the daemon socket. Only root (the daemon) or this
// user may serve it: configuration texts go over this connection.
func dialDaemon(ctx context.Context) (rpcConn, error) {
	c, err := ipc.Dial(daemon.DefaultSocket)
	if err != nil {
		return nil, err
	}
	if uid := c.PeerUID(); uid != 0 && int64(uid) != int64(os.Getuid()) {
		c.Close()
		return nil, fmt.Errorf(msg.CLIUntrustedDaemonFmt, uid)
	}
	go c.Serve(ctx)
	return c, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, defaultEnv(), os.Args[1:])
	stop()
	os.Exit(code)
}

// usageError is a mistake in the command line: exit code 2.
type usageError struct {
	err      error  // what is wrong; nil for "no command"
	synopsis string // usage line of the command; "" for the full usage
}

func (u *usageError) Error() string {
	if u.err == nil {
		return "usage"
	}
	return u.err.Error()
}

func usageErr(synopsis, format string, args ...any) *usageError {
	return &usageError{err: fmt.Errorf(format, args...), synopsis: synopsis}
}

type command struct {
	synopsis string // arguments after the command name
	run      func(ctx context.Context, e *env, args []string) error
}

func commands() map[string]command {
	return map[string]command{
		"devices": {"devices", cmdDevices},
		"keygen":  {keygenSynopsis, cmdKeygen},
		"pubkey":  {"pubkey <keyref>", cmdPubkey},
		"agent":   {"agent", cmdAgent},
		"daemon":  {"daemon", cmdDaemon},
		"add":     {"add <name> <file>", cmdAdd},
		"remove":  {"remove <name>", cmdRemove},
		"up":      {"up <name>", cmdUp},
		"down":    {"down <name>", cmdDown},
		"status":  {"status [name]", cmdStatus},
	}
}

// run executes one command line and returns the process exit code.
func run(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, msg.CLIUsage)
		return exitUsage
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "--help":
		fmt.Fprintln(e.stdout, msg.CLIUsage)
		return exitOK
	}
	cmd, ok := commands()[name]
	if !ok {
		fmt.Fprintf(e.stderr, "latchwire: %s\n%s\n", fmt.Sprintf(msg.CLIUnknownCommandFmt, name), msg.CLIUsage)
		return exitUsage
	}

	err := cmd.run(ctx, e, rest)
	var ue *usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(e.stdout, msg.CLIUsageErrorFmt+"\n", cmd.synopsis)
		}
		return exitOK
	case errors.As(err, &ue):
		fmt.Fprintf(e.stderr, msg.CLIErrorFmt+"\n", ue.err)
		fmt.Fprintf(e.stderr, msg.CLIUsageErrorFmt+"\n", cmd.synopsis)
		return exitUsage
	default:
		fmt.Fprintf(e.stderr, msg.CLIErrorFmt+"\n", err)
		return exitError
	}
}

// newFlagSet returns a FlagSet whose errors come back as values.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses args and returns the positional arguments.
func parseFlags(fs *flag.FlagSet, synopsis string, args []string) ([]string, error) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, &usageError{err: err, synopsis: synopsis}
	}
	return fs.Args(), nil
}

// wantArgs checks the number of positional arguments.
func wantArgs(synopsis string, args []string, n int) error {
	if len(args) != n {
		return &usageError{err: fmt.Errorf("expected %d argument(s), got %d", n, len(args)), synopsis: synopsis}
	}
	return nil
}

func cmdAgent(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("agent", args, 0); err != nil {
		return err
	}
	fmt.Fprintf(e.stderr, msg.AgentStartedFmt+"\n", daemon.DefaultSocket)
	return stopped(e.runAgent(ctx))
}

func cmdDaemon(ctx context.Context, e *env, args []string) error {
	if err := wantArgs("daemon", args, 0); err != nil {
		return err
	}
	if e.geteuid() != 0 {
		return errors.New(msg.DaemonMustBeRoot)
	}
	fmt.Fprintf(e.stderr, msg.DaemonStartedFmt+"\n", daemon.DefaultSocket)
	return stopped(e.runDaemon(ctx))
}

// stopped turns the cancellation that ends a long-running command into
// success.
func stopped(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// daemonErr turns a failed daemon call into the text the user should see.
func daemonErr(err error) error {
	var ie *ipc.Error
	switch {
	case errors.As(err, &ie):
		return errors.New(ie.Message)
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
		return errors.New(msg.CLIDaemonNotRunning)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New(msg.CLIDaemonNotRunning)
	}
	return err
}
