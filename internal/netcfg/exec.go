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

// execTimeout bounds one network command.
const execTimeout = 10 * time.Second

type execRunner struct {
	dirs []string
}

// ExecRunner runs network commands by name from a fixed list of system
// directories, never through PATH and never through a shell. Each call is
// bounded by a timeout. It returns stdout; stderr is appended to the error.
// Arguments carry only addresses and names: anything secret goes through
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
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		if s := strings.TrimSpace(stderr.String()); s != "" {
			return stdout.Bytes(), fmt.Errorf("%w: %s", err, s)
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}
