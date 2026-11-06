//go:build !windows

package ipctest

import (
	"os"
	"path/filepath"
	"testing"
)

// path is short: a socket path has a low length limit, and t.TempDir can
// pass it.
func path(t testing.TB) string {
	dir, err := os.MkdirTemp("", "lw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}
