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

// Exec runs a network command by name from a fixed list of system
// directories, never through PATH. Its combined output is included in the
// error; the commands carry only addresses and interface names.
func Exec(name string, args ...string) error {
	path := ""
	for _, d := range commandDirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			path = p
			break
		}
	}
	if path == "" {
		return fmt.Errorf("%s: %w", name, exec.ErrNotFound)
	}
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if s := strings.TrimSpace(out.String()); s != "" {
			return fmt.Errorf("%w: %s", err, s)
		}
		return err
	}
	return nil
}
