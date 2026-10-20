package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/piv"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

const keygenSynopsis = "keygen --serial N [--slot 82] [--force] [--address IP]"

// newSecretTries is how often the new PIN or PUK is asked for when the two
// entries differ or have the wrong length.
const newSecretTries = 3

func cmdKeygen(_ context.Context, e *env, args []string) error {
	fs := newFlagSet("keygen")
	serial := fs.Uint64("serial", 0, "serial number of the YubiKey")
	slotStr := fs.String("slot", "", "retired slot 82-95 (hex); default: the first empty one")
	force := fs.Bool("force", false, "replace a key already in the slot")
	addrStr := fs.String("address", "", "tunnel IP address of this client, for the server's [Peer] block")
	rest, err := parseFlags(fs, keygenSynopsis, args)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return usageErr(keygenSynopsis, "unexpected argument %q", rest[0])
	}
	if *serial == 0 || *serial > 1<<32-1 {
		return usageErr(keygenSynopsis, "%s", msg.KeygenSerialRequired)
	}
	slot, err := parseSlot(*slotStr)
	if err != nil {
		return &usageError{err: err, synopsis: keygenSynopsis}
	}
	var addr netip.Addr
	if *addrStr != "" {
		addr, err = netip.ParseAddr(*addrStr)
		if err != nil {
			return usageErr(keygenSynopsis, msg.KeygenBadAddressFmt, *addrStr)
		}
	}

	card, err := e.openCard(uint32(*serial))
	if err != nil {
		return err
	}
	defer card.Close()

	pin, err := e.readSecret(fmt.Sprintf(msg.KeygenPINPromptFmt, *serial))
	if err != nil {
		return err
	}
	if pin == "" {
		return errors.New(msg.PIVEmptyPIN)
	}

	opts := piv.GenerateOptions{Slot: slot, PIN: pin, Force: *force}
	ref, pub, err := card.Generate(opts)
	if errors.Is(err, piv.ErrFreshCard) {
		if err := askFreshCardSecrets(e, &opts); err != nil {
			return err
		}
		ref, pub, err = card.Generate(opts)
		if errors.Is(err, piv.ErrFreshCard) {
			return errors.New(msg.KeygenFreshRejected)
		}
	}
	if err != nil {
		return keygenFailure(e, card, uint32(*serial), slot, err)
	}

	printNewKey(e.stdout, ref, pub, addr)
	return nil
}

// parseSlot reads a retired slot number in hex ("" = 0 = first empty slot).
func parseSlot(s string) (uint8, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 8)
	if err != nil || n < keyref.MinSlot || n > keyref.MaxSlot {
		return 0, fmt.Errorf(msg.KeygenBadSlotFmt, s)
	}
	return uint8(n), nil
}

// askFreshCardSecrets explains why a factory-fresh card has to be secured
// and asks for the current PUK and a new PIN and PUK, each new one twice.
func askFreshCardSecrets(e *env, o *piv.GenerateOptions) error {
	fmt.Fprintln(e.stderr, msg.FreshCardExplain)
	puk, err := e.readSecret(msg.KeygenPUKPrompt)
	if err != nil {
		return err
	}
	newPIN, err := askNewSecret(e, msg.KeygenNewPINPrompt, msg.KeygenNewPINAgain)
	if err != nil {
		return err
	}
	newPUK, err := askNewSecret(e, msg.KeygenNewPUKPrompt, msg.KeygenNewPUKAgain)
	if err != nil {
		return err
	}
	o.CurrentPUK, o.NewPIN, o.NewPUK = puk, newPIN, newPUK
	return nil
}

func askNewSecret(e *env, first, again string) (string, error) {
	for range newSecretTries {
		a, err := e.readSecret(first)
		if err != nil {
			return "", err
		}
		b, err := e.readSecret(again)
		if err != nil {
			return "", err
		}
		switch {
		case a != b:
			fmt.Fprintln(e.stderr, msg.KeygenSecretMismatch)
		case len(a) < 6 || len(a) > 8:
			fmt.Fprintln(e.stderr, msg.KeygenSecretRules)
		default:
			return a, nil
		}
	}
	return "", errors.New(msg.KeygenSecretGaveUp)
}

// keygenFailure turns a Generate error into what the user sees.
func keygenFailure(e *env, card cardOps, serial uint32, slot uint8, err error) error {
	var pe *keyprovider.PINError
	switch {
	case errors.As(err, &pe):
		if pe.RetriesLeft == 1 {
			fmt.Fprintln(e.stderr, msg.LastPINRetry)
		}
		return fmt.Errorf(msg.KeygenWrongPINFmt, pe.RetriesLeft)
	case errors.Is(err, keyprovider.ErrPINBlocked):
		return errors.New(msg.AgentPINBlocked)
	case errors.Is(err, piv.ErrSlotOccupied):
		return slotOccupied(card, serial, slot)
	}
	return err
}

// slotOccupied describes what the slot holds and says how to replace it.
func slotOccupied(card cardOps, serial uint32, slot uint8) error {
	var what string
	p, err := card.Provider(keyref.Ref{Serial: serial, Slot: slot}, func(int) (string, error) {
		return "", keyprovider.ErrPINRequired
	})
	if err != nil {
		what = fmt.Sprintf(msg.KeygenSlotOccupiedOther, slot, serial, err)
	} else {
		pub := p.PublicKey()
		what = fmt.Sprintf(msg.KeygenSlotOccupiedFmt, slot, serial, base64.StdEncoding.EncodeToString(pub[:]))
		if c, ok := p.(io.Closer); ok {
			c.Close()
		}
	}
	return errors.New(what + "\n" + msg.KeygenSlotOccupiedStop)
}

// printNewKey writes the result: the KeyRef, the lines for the tunnel
// configuration and the [Peer] block for the server. addr is the client's
// tunnel address; invalid means "not given".
func printNewKey(w io.Writer, ref keyref.Ref, pub [32]byte, addr netip.Addr) {
	b64 := base64.StdEncoding.EncodeToString(pub[:])
	ip, bits := msg.KeygenTunnelIP, 32
	if addr.IsValid() {
		ip, bits = addr.String(), addr.BitLen()
	}
	fmt.Fprintf(w, msg.KeygenDoneFmt+"\n\n", ref.Serial, ref.Slot)
	fmt.Fprintf(w, msg.KeygenKeyRefFmt+"\n\n", ref)
	fmt.Fprintln(w, msg.KeygenIdentityHeader)
	fmt.Fprintf(w, msg.KeygenIdentityLinesFmt+"\n\n", ref, b64)
	fmt.Fprintln(w, msg.KeygenPeerHeader)
	fmt.Fprintf(w, msg.KeygenPeerBlockFmt+"\n", b64, ip, bits)
	if !addr.IsValid() {
		fmt.Fprintf(w, "\n%s\n", msg.KeygenAddressHint)
	}
}

func cmdPubkey(_ context.Context, e *env, args []string) error {
	const synopsis = "pubkey <keyref>"
	if err := wantArgs(synopsis, args, 1); err != nil {
		return err
	}
	ref, err := keyref.Parse(args[0])
	if err != nil {
		return &usageError{err: err, synopsis: synopsis}
	}
	card, err := e.openCard(ref.Serial)
	if err != nil {
		return err
	}
	defer card.Close()
	// Reading a public key never needs the PIN.
	p, err := card.Provider(ref, func(int) (string, error) { return "", keyprovider.ErrPINRequired })
	if err != nil {
		return err
	}
	if c, ok := p.(io.Closer); ok {
		defer c.Close()
	}
	pub := p.PublicKey()
	fmt.Fprintln(e.stdout, base64.StdEncoding.EncodeToString(pub[:]))
	return nil
}
