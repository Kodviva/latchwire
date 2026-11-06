// Package ipctest gives a test a transport address of its own.
package ipctest

import "testing"

// Path returns an address nothing else uses, for ipc.Listen.
func Path(t testing.TB) string {
	t.Helper()
	return path(t)
}
