package daemon

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Kodviva/latchwire/internal/msg"
	"github.com/Kodviva/latchwire/internal/netcfg"
)

func init() { tun.WintunTunnelType = "Latchwire" }

// createTUN creates the tunnel's Wintun adapter. The GUID comes from the
// name: netcfg names the adapter's registry keys with it, and a stable GUID
// keeps Windows from adding a network profile per connect.
func createTUN(name string, mtu int) (tun.Device, error) {
	guid, err := windows.GUIDFromString(netcfg.WindowsInterfaceGUID(name))
	if err != nil {
		return nil, err
	}
	d, err := tun.CreateTUNWithRequestedGUID(name, &guid, mtu)
	if errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		return nil, fmt.Errorf(msg.WintunMissingFmt, err)
	}
	return d, err
}
