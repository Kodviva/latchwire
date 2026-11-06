package netcfg

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// failureOnStdout: netsh writes its errors to stdout.
const failureOnStdout = true

var builtins sync.Map // name to func(context.Context, []string) ([]byte, error)

// RegisterBuiltin makes name a command the runner answers itself. Some
// undo steps are API calls rather than programs (the WFP filters), and the
// journal holds steps: a builtin lets it replay them like any other.
func RegisterBuiltin(name string, fn func(ctx context.Context, args []string) ([]byte, error)) {
	builtins.Store(name, fn)
}

func builtin(name string) func(context.Context, []string) ([]byte, error) {
	if v, ok := builtins.Load(name); ok {
		return v.(func(context.Context, []string) ([]byte, error))
	}
	return nil
}

func exeFile(name string) string { return name + ".exe" }

// execEnv: System32 tools need SystemRoot. There is no LC_ALL: Windows tools
// follow the system's language, which is why the parsers read only numbers
// and addresses.
func execEnv(dirs []string) []string {
	return []string{"SystemRoot=" + filepath.Dir(systemDir()), "PATH=" + strings.Join(dirs, ";")}
}

// systemDir is System32, from the system rather than the environment.
var systemDir = sync.OnceValue(func() string {
	d, err := windows.GetSystemDirectory()
	if err != nil {
		return `C:\Windows\System32`
	}
	return d
})
