package main

import (
	"context"
	"fmt"

	"github.com/Kodviva/latchwire/internal/msg"
)

func cmdDevices(_ context.Context, e *env, args []string) error {
	if err := wantArgs("devices", args, 0); err != nil {
		return err
	}
	devs, err := e.listDevices()
	if err != nil {
		return err
	}
	if len(devs) == 0 {
		fmt.Fprintln(e.stdout, msg.DevicesNone)
		return nil
	}
	for i, d := range devs {
		if i > 0 {
			fmt.Fprintln(e.stdout)
		}
		supported := msg.DevicesYes
		if !d.Supported {
			supported = msg.DevicesNo
		}
		fmt.Fprintf(e.stdout, msg.DevicesHeaderFmt+"\n", d.Serial)
		fmt.Fprintf(e.stdout, msg.DevicesFirmware+"\n", d.Firmware)
		fmt.Fprintf(e.stdout, msg.DevicesSupported+"\n", supported)
		fmt.Fprintf(e.stdout, msg.DevicesReader+"\n", d.Reader)
	}
	return nil
}
