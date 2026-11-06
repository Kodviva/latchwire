//go:build !windows

package daemon

import (
	"runtime"

	"golang.zx2c4.com/wireguard/tun"
)

func createTUN(name string, mtu int) (tun.Device, error) {
	if runtime.GOOS == "darwin" {
		name = "utun"
	}
	return tun.CreateTUN(name, mtu)
}
