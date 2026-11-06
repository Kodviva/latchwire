//go:build unix

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// singleInstance takes a per-user lock: a second app would be a second agent
// answering for the same card. The kernel drops the lock if the app dies.
func singleInstance() (release func(), ok bool) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return func() {}, true
	}
	dir = filepath.Join(dir, "Latchwire")
	if os.MkdirAll(dir, 0o700) != nil {
		return func() {}, true
	}
	f, err := os.OpenFile(filepath.Join(dir, "app.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, true
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, false
	}
	return func() { f.Close() }, true
}
