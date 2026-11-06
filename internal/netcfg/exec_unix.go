//go:build !windows

package netcfg

import (
	"context"
	"strings"
)

// failureOnStdout says that a failing command explains itself on stdout.
const failureOnStdout = false

func builtin(string) func(context.Context, []string) ([]byte, error) { return nil }

func exeFile(name string) string { return name }

func execEnv(dirs []string) []string {
	return []string{"LC_ALL=C", "PATH=" + strings.Join(dirs, ":")}
}
