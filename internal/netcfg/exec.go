//go:build darwin || linux

package netcfg

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// execTimeout bounds one network command.
	execTimeout = 10 * time.Second
	// execWaitDelay bounds the wait for a killed command's output pipes.
	execWaitDelay = 2 * time.Second
	// maxStderr caps the command output kept for an error message.
	maxStderr = 4 << 10
)

// capBuffer keeps the first max bytes written and discards the rest.
type capBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

type execRunner struct {
	dirs []string
}

// ExecRunner runs network commands by name from a fixed list of system
// directories, never through PATH and never through a shell. Each call is
// bounded by a timeout. It returns stdout; stderr is appended to the error.
// The command gets a minimal environment (LC_ALL=C, PATH = the fixed
// directories). Arguments carry only addresses and names: anything secret goes through
// stdin.
func ExecRunner() Runner { return execRunner{dirs: commandDirs} }

func (e execRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if name == "" || strings.ContainsRune(name, filepath.Separator) {
		return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
	}
	path := ""
	for _, d := range e.dirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			path = p
			break
		}
	}
	if path == "" {
		return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	var stdout bytes.Buffer
	stderr := &capBuffer{max: maxStderr}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = &stdout, stderr
	// A minimal environment: no inherited variables, a fixed locale and the
	// fixed directories as PATH (for tools that run other tools).
	cmd.Env = []string{"LC_ALL=C", "PATH=" + strings.Join(e.dirs, ":")}
	cmd.WaitDelay = execWaitDelay
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		if s := strings.TrimSpace(stderr.buf.String()); s != "" {
			return stdout.Bytes(), fmt.Errorf("%w: %s", err, s)
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}
