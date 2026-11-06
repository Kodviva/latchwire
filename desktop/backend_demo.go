//go:build demo

package main

import (
	"context"
	"os"
	"time"

	"github.com/Kodviva/latchwire/desktop/demo"
	"github.com/Kodviva/latchwire/desktop/ui"
)

var cards = demo.New()

func options() ui.Options {
	in := true
	return ui.Options{Backend: cards, Demo: true, Actions: []ui.DemoAction{{
		Label: "Toggle card (demo)",
		Run: func() {
			in = !in
			cards.SetCard(demo.CardA, in)
		},
	}}}
}

// runAgent has no agent to run. With LATCHWIRE_DEMO_TOUR set to a directory
// it walks the screens and writes them there.
func runAgent(_ context.Context, u *ui.UI) {
	if dir := os.Getenv("LATCHWIRE_DEMO_TOUR"); dir != "" {
		time.Sleep(2 * time.Second)
		u.Tour(dir, func(in bool) { cards.SetCard(demo.CardA, in) })
	}
}
