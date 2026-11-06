// Command latchwire-desktop is the Latchwire menu bar and tray app. It hosts
// the per-user key agent and talks to the tunnel daemon over the same IPC as
// the latchwire command.
package main

import (
	"context"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/Kodviva/latchwire/desktop/assets"
	"github.com/Kodviva/latchwire/desktop/ui"
)

const appID = "com.latchwire.desktop"

func main() {
	release, ok := singleInstance()
	if !ok {
		log.Print("latchwire-desktop is already running")
		return
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := app.NewWithID(appID)
	a.SetIcon(fyne.NewStaticResource("icon.svg", assets.AppIcon))
	u := ui.New(a, options())
	go runAgent(ctx, u)
	u.Run(ctx)
}
