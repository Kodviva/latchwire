//go:build !windows

package datadir

// Dir is the service's data directory; Unix has none.
func Dir() string { return "" }

// Secure does nothing on Unix.
func Secure() error { return nil }
