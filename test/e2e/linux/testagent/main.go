//go:build e2e && linux

// Command testagent is the Latchwire user agent with software keys instead
// of a YubiKey. It exists only for the Linux end-to-end test
// (test/e2e/linux): the production command (cmd/latchwire) never links the
// software key (Plan 1 rule, checked by cmd/latchwire/deps_test.go).
//
// The "card" is present while the file given by -card exists: deleting it is
// the test's card removal, creating it again the insertion. Keys are read
// from <keys>/<slot>.key (base64 of a 32-byte X25519 private scalar), for
// example 82.key for piv://<serial>/82.
//
//	testagent -pub FILE          print the public key of a key file
//	testagent -serial N -card F -keys DIR [-socket S] [-poll D]
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Kodviva/latchwire/internal/agent"
	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/softkey"
	"github.com/Kodviva/latchwire/internal/keyref"
)

func main() {
	pub := flag.String("pub", "", "print the public key of this key file and exit")
	socket := flag.String("socket", daemon.DefaultSocket, "daemon socket")
	serial := flag.Uint("serial", 0, "serial number of the simulated card")
	card := flag.String("card", "", "the card is present while this file exists")
	keys := flag.String("keys", "", "directory holding <slot>.key files")
	poll := flag.Duration("poll", 200*time.Millisecond, "card presence poll interval")
	flag.Parse()

	if *pub != "" {
		k, err := readKey(*pub)
		if err != nil {
			log.Fatal(err)
		}
		p := k.PublicKey()
		fmt.Println(base64.StdEncoding.EncodeToString(p[:]))
		return
	}
	if *serial == 0 || *card == "" || *keys == "" {
		log.Fatal("testagent: -serial, -card and -keys are required")
	}
	b := &backend{serial: uint32(*serial), card: *card, keys: *keys}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := agent.New(*socket, b, prompter{}, *poll).Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func readKey(path string) (*softkey.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("testagent: %s: not a base64 32-byte key", path)
	}
	var sk [32]byte
	copy(sk[:], raw)
	return softkey.FromPrivate(sk), nil
}

// backend is one simulated card holding software keys.
type backend struct {
	serial uint32
	card   string
	keys   string
}

func (b *backend) present() bool {
	_, err := os.Stat(b.card)
	return err == nil
}

func (b *backend) Serials() ([]uint32, error) {
	if !b.present() {
		return nil, nil
	}
	return []uint32{b.serial}, nil
}

func (b *backend) Provider(ref keyref.Ref, _ func(int) (string, error)) (keyprovider.Provider, error) {
	if ref.Serial != b.serial || !b.present() {
		return nil, keyprovider.ErrUnavailable
	}
	k, err := readKey(filepath.Join(b.keys, fmt.Sprintf("%02x.key", ref.Slot)))
	if err != nil {
		return nil, err
	}
	return &cardKey{Key: k, b: b}, nil
}

// cardKey fails like a pulled token once the card file is gone.
type cardKey struct {
	*softkey.Key
	b *backend
}

func (k *cardKey) X25519(ctx context.Context, peer [32]byte) ([32]byte, error) {
	if !k.b.present() {
		return [32]byte{}, keyprovider.ErrUnavailable
	}
	return k.Key.X25519(ctx, peer)
}

// prompter never has a PIN to give: software keys need none.
type prompter struct{}

func (prompter) PIN(keyprovider.Description, int) (string, error) {
	return "", keyprovider.ErrPINRequired
}

func (prompter) Warn(m string) { log.Printf("testagent: %s", m) }
