// Command gen writes internal/msg/en.go from internal/msg/locales/en.arb.
// Run it with go generate ./internal/msg.
package main

import (
	"log"
	"os"

	"github.com/Kodviva/latchwire/internal/msg/icu"
)

func main() {
	data, err := os.ReadFile("locales/en.arb")
	if err != nil {
		log.Fatal(err)
	}
	f, err := icu.ParseARB(data)
	if err != nil {
		log.Fatal(err)
	}
	src, err := icu.GenerateGo(f)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("en.go", src, 0o644); err != nil {
		log.Fatal(err)
	}
}
