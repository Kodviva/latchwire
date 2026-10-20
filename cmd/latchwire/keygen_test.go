package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/keyprovider/piv"
	"github.com/Kodviva/latchwire/internal/keyref"
	"github.com/Kodviva/latchwire/internal/msg"
)

// fakeCard stands in for *piv.Card.
type fakeCard struct {
	serial uint32
	pub    [32]byte

	// genErrs are returned by successive Generate calls before it succeeds.
	genErrs []error
	gens    []piv.GenerateOptions
	// mgmtKeys holds a copy of each call's ManagementKey (gens shares the
	// caller's buffer, which is cleared after use).
	mgmtKeys [][]byte

	// slotPub, if set, is what Provider reports for an occupied slot.
	slotPub *[32]byte
	closed  bool
}

func (f *fakeCard) Generate(o piv.GenerateOptions) (keyref.Ref, [32]byte, error) {
	f.gens = append(f.gens, o)
	f.mgmtKeys = append(f.mgmtKeys, bytes.Clone(o.ManagementKey))
	if len(f.genErrs) > 0 {
		err := f.genErrs[0]
		f.genErrs = f.genErrs[1:]
		return keyref.Ref{}, [32]byte{}, err
	}
	slot := o.Slot
	if slot == 0 {
		slot = 0x82
	}
	return keyref.Ref{Serial: f.serial, Slot: slot}, f.pub, nil
}

type fakeProvider struct{ pub [32]byte }

func (p fakeProvider) PublicKey() [32]byte { return p.pub }
func (p fakeProvider) X25519(context.Context, [32]byte) ([32]byte, error) {
	return [32]byte{}, errors.New("not used")
}
func (p fakeProvider) Describe() keyprovider.Description { return keyprovider.Description{} }

func (f *fakeCard) Provider(ref keyref.Ref, _ func(int) (string, error)) (keyprovider.Provider, error) {
	if f.slotPub == nil {
		return nil, piv.ErrImportedKey
	}
	return fakeProvider{*f.slotPub}, nil
}

func (f *fakeCard) Close() error { f.closed = true; return nil }

// secretQueue answers readSecret in order and records the prompts.
type secretQueue struct {
	answers []string
	prompts []string
}

func (q *secretQueue) read(prompt string) (string, error) {
	q.prompts = append(q.prompts, prompt)
	if len(q.answers) == 0 {
		return "", errors.New("unexpected prompt: " + prompt)
	}
	a := q.answers[0]
	q.answers = q.answers[1:]
	return a, nil
}

type testEnv struct {
	*env
	out, errOut *bytes.Buffer
	card        *fakeCard
	secrets     *secretQueue
}

func newTestEnv(card *fakeCard, answers ...string) *testEnv {
	te := &testEnv{out: &bytes.Buffer{}, errOut: &bytes.Buffer{}, card: card, secrets: &secretQueue{answers: answers}}
	te.env = &env{
		stdout:     te.out,
		stderr:     te.errOut,
		readSecret: te.secrets.read,
		openCard: func(serial uint32) (cardOps, error) {
			if card == nil || serial != card.serial {
				return nil, piv.ErrNotFound
			}
			return card, nil
		},
		geteuid: func() int { return 1000 },
	}
	return te
}

func testPub() [32]byte {
	var p [32]byte
	for i := range p {
		p[i] = byte(i + 1)
	}
	return p
}

func b64(p [32]byte) string { return base64.StdEncoding.EncodeToString(p[:]) }

func TestKeygenPrintsPeerBlock(t *testing.T) {
	pub := testPub()
	te := newTestEnv(&fakeCard{serial: 40727512, pub: pub}, "654321")

	code := run(context.Background(), te.env, []string{"keygen", "--serial", "40727512", "--address", "10.8.0.2"})
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, te.errOut)
	}
	out := te.out.String()
	for _, want := range []string{
		"[Peer]\nPublicKey = " + b64(pub) + "\nAllowedIPs = 10.8.0.2/32",
		"KeyRef = piv://40727512/82\nPublicKey = " + b64(pub),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if got := te.card.gens[0]; got.PIN != "654321" || got.Slot != 0 || got.Force {
		t.Errorf("Generate options = %+v", got)
	}
	if !te.card.closed {
		t.Error("card not closed")
	}
	if strings.Contains(out+te.errOut.String(), "654321") {
		t.Error("PIN was printed")
	}
}

func TestKeygenPeerBlockPlaceholderAndIPv6(t *testing.T) {
	pub := testPub()
	te := newTestEnv(&fakeCard{serial: 7, pub: pub}, "654321")
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if want := "[Peer]\nPublicKey = " + b64(pub) + "\nAllowedIPs = " + msg.KeygenTunnelIP + "/32"; !strings.Contains(te.out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, te.out)
	}

	te = newTestEnv(&fakeCard{serial: 7, pub: pub}, "654321")
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7", "--address", "fd00::2"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if want := "AllowedIPs = fd00::2/128"; !strings.Contains(te.out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, te.out)
	}
}

func TestKeygenSlotFlag(t *testing.T) {
	te := newTestEnv(&fakeCard{serial: 7, pub: testPub()}, "654321")
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7", "--slot", "8a", "--force"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if got := te.card.gens[0]; got.Slot != 0x8a || !got.Force {
		t.Errorf("Generate options = %+v", got)
	}
	if !strings.Contains(te.out.String(), "piv://7/8a") {
		t.Errorf("output: %s", te.out)
	}
	for _, bad := range []string{"81", "96", "zz", "9a"} {
		te := newTestEnv(&fakeCard{serial: 7}, "654321")
		if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7", "--slot", bad}); code != 2 {
			t.Errorf("--slot %s: exit %d, want 2", bad, code)
		}
		if len(te.secrets.prompts) != 0 || te.card.gens != nil {
			t.Errorf("--slot %s: touched the card or asked for a PIN", bad)
		}
	}
}

func TestKeygenFreshCard(t *testing.T) {
	pub := testPub()
	card := &fakeCard{serial: 7, pub: pub, genErrs: []error{piv.ErrFreshCard}}
	// PIN, then PUK, new PIN twice, new PUK twice.
	te := newTestEnv(card, "123456", "12345678", "246810", "246810", "13579024", "13579024")

	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, te.errOut)
	}
	if !strings.Contains(te.errOut.String(), msg.FreshCardExplain) {
		t.Errorf("fresh-card explanation missing from stderr:\n%s", te.errOut)
	}
	if len(card.gens) != 2 {
		t.Fatalf("Generate called %d times", len(card.gens))
	}
	if g := card.gens[0]; g.NewPIN != "" || g.NewPUK != "" || g.CurrentPUK != "" {
		t.Errorf("first call carried secrets that were not asked for yet: %+v", g)
	}
	g := card.gens[1]
	if g.PIN != "123456" || g.CurrentPUK != "12345678" || g.NewPIN != "246810" || g.NewPUK != "13579024" {
		t.Errorf("second call = %+v", g)
	}
	if len(te.secrets.prompts) != 6 {
		t.Errorf("prompts = %q", te.secrets.prompts)
	}
	all := te.out.String() + te.errOut.String()
	for _, s := range []string{"123456", "12345678", "246810", "13579024"} {
		if strings.Contains(all, s) {
			t.Errorf("secret %q was printed", s)
		}
	}
}

func TestKeygenFreshCardMismatchAsksAgain(t *testing.T) {
	card := &fakeCard{serial: 7, pub: testPub(), genErrs: []error{piv.ErrFreshCard}}
	te := newTestEnv(card, "123456", "12345678",
		"246810", "246811", // mismatch
		"246810", "246810",
		"13579024", "13579024")
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, te.errOut)
	}
	if !strings.Contains(te.errOut.String(), msg.KeygenSecretMismatch) {
		t.Errorf("no mismatch message:\n%s", te.errOut)
	}
	if card.gens[1].NewPIN != "246810" {
		t.Errorf("NewPIN = %q", card.gens[1].NewPIN)
	}
}

func TestKeygenFreshCardNewSecretsRejectedStops(t *testing.T) {
	card := &fakeCard{serial: 7, pub: testPub(), genErrs: []error{piv.ErrFreshCard, piv.ErrFreshCard}}
	te := newTestEnv(card, "123456", "12345678", "246810", "246810", "13579024", "13579024")
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if len(card.gens) != 2 {
		t.Errorf("Generate called %d times, want 2", len(card.gens))
	}
	if !strings.Contains(te.errOut.String(), msg.KeygenFreshRejected) {
		t.Errorf("stderr: %s", te.errOut)
	}
}

func TestKeygenSlotOccupiedShowsContent(t *testing.T) {
	pub := testPub()
	card := &fakeCard{serial: 7, genErrs: []error{piv.ErrSlotOccupied}, slotPub: &pub}
	te := newTestEnv(card, "654321")
	code := run(context.Background(), te.env, []string{"keygen", "--serial", "7", "--slot", "82"})
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if card.gens[0].Force {
		t.Error("Force set without --force")
	}
	e := te.errOut.String()
	for _, want := range []string{b64(pub), "--force", "slot 82"} {
		if !strings.Contains(e, want) {
			t.Errorf("stderr lacks %q:\n%s", want, e)
		}
	}
	if te.out.Len() != 0 {
		t.Errorf("stdout not empty: %s", te.out)
	}
}

func TestKeygenSlotOccupiedUnusableKey(t *testing.T) {
	card := &fakeCard{serial: 7, genErrs: []error{piv.ErrSlotOccupied}} // Provider -> ErrImportedKey
	te := newTestEnv(card, "654321")
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7", "--slot", "83"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errOut.String(), piv.ErrImportedKey.Error()) {
		t.Errorf("stderr: %s", te.errOut)
	}
}

func TestKeygenPromptsForManagementKey(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		mk := make([]byte, n)
		for i := range mk {
			mk[i] = byte(0xa0 + i)
		}
		mkHex := hex.EncodeToString(mk)
		card := &fakeCard{serial: 7, pub: testPub(), genErrs: []error{piv.ErrManagementKeyRequired}}
		te := newTestEnv(card, "654321", mkHex)
		if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 0 {
			t.Fatalf("%d-byte key: exit %d, stderr: %s", n, code, te.errOut)
		}
		if len(card.gens) != 2 {
			t.Fatalf("%d-byte key: Generate called %d times, want 2", n, len(card.gens))
		}
		if card.mgmtKeys[0] != nil {
			t.Errorf("first call already carried a management key")
		}
		if !bytes.Equal(card.mgmtKeys[1], mk) {
			t.Errorf("%d-byte key: retry used management key %x, want %x", n, card.mgmtKeys[1], mk)
		}
		if g := card.gens[1]; g.PIN != "654321" {
			t.Errorf("retry options = %+v", g)
		}
		if !bytes.Equal(card.gens[1].ManagementKey, make([]byte, n)) {
			t.Errorf("%d-byte key: management key buffer not cleared after use", n)
		}
		if want := []string{fmt.Sprintf(msg.KeygenPINPromptFmt, 7), msg.KeygenManagementKeyPrompt}; !slices.Equal(te.secrets.prompts, want) {
			t.Errorf("prompts = %q, want %q", te.secrets.prompts, want)
		}
		if strings.Contains(strings.ToLower(te.out.String()+te.errOut.String()), mkHex) {
			t.Error("management key was printed")
		}
	}
}

func TestKeygenRejectsBadManagementKeyHex(t *testing.T) {
	for _, bad := range []string{
		"",
		"0011",
		strings.Repeat("ab", 20), // 20 bytes: not an AES/3DES key length
		strings.Repeat("zz", 24), // not hex
		strings.Repeat("ab", 24) + "a",
	} {
		card := &fakeCard{serial: 7, pub: testPub(), genErrs: []error{piv.ErrManagementKeyRequired}}
		te := newTestEnv(card, "654321", bad)
		if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 1 {
			t.Errorf("%q: exit %d, want 1", bad, code)
		}
		if len(card.gens) != 1 {
			t.Errorf("%q: Generate called %d times, want 1 (no retry with a bad key)", bad, len(card.gens))
		}
		if !strings.Contains(te.errOut.String(), msg.KeygenBadManagementKey) {
			t.Errorf("%q: stderr: %s", bad, te.errOut)
		}
		if bad != "" && strings.Contains(te.errOut.String(), bad) {
			t.Errorf("%q: input was echoed", bad)
		}
	}
}

func TestKeygenWrongManagementKeyRetriedOnce(t *testing.T) {
	card := &fakeCard{serial: 7, pub: testPub(),
		genErrs: []error{piv.ErrManagementKeyRequired, piv.ErrManagementKeyRequired, piv.ErrManagementKeyRequired}}
	te := newTestEnv(card, "654321", strings.Repeat("01", 24))
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if len(card.gens) != 2 || len(te.secrets.prompts) != 2 {
		t.Errorf("gens=%d prompts=%d, want 2 and 2", len(card.gens), len(te.secrets.prompts))
	}
	if !strings.Contains(te.errOut.String(), msg.KeygenManagementKeyRejected) {
		t.Errorf("stderr: %s", te.errOut)
	}
}

func TestKeygenWrongPINDoesNotRetry(t *testing.T) {
	card := &fakeCard{serial: 7, genErrs: []error{&keyprovider.PINError{RetriesLeft: 2}}}
	te := newTestEnv(card, "000000")
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "7"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if len(card.gens) != 1 || len(te.secrets.prompts) != 1 {
		t.Errorf("gens=%d prompts=%d", len(card.gens), len(te.secrets.prompts))
	}
	if want := fmt.Sprintf(msg.KeygenWrongPINFmt, 2); !strings.Contains(te.errOut.String(), want) {
		t.Errorf("stderr: %s", te.errOut)
	}
	if strings.Contains(te.errOut.String(), "000000") {
		t.Error("PIN was printed")
	}
}

func TestKeygenWrongPINLastRetryWarns(t *testing.T) {
	card := &fakeCard{serial: 7, genErrs: []error{&keyprovider.PINError{RetriesLeft: 1}}}
	te := newTestEnv(card, "000000")
	run(context.Background(), te.env, []string{"keygen", "--serial", "7"})
	if !strings.Contains(te.errOut.String(), msg.LastPINRetry) {
		t.Errorf("stderr: %s", te.errOut)
	}
}

func TestKeygenCardNotFound(t *testing.T) {
	te := newTestEnv(nil)
	if code := run(context.Background(), te.env, []string{"keygen", "--serial", "9"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(te.errOut.String(), msg.PIVCardNotFound) {
		t.Errorf("stderr: %s", te.errOut)
	}
	if len(te.secrets.prompts) != 0 {
		t.Error("asked for a PIN although no card was found")
	}
}

func TestKeygenUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"keygen"},
		{"keygen", "--serial", "x"},
		{"keygen", "--serial", "7", "--address", "not-an-ip"},
		{"keygen", "--serial", "7", "stray"},
		{"keygen", "--bogus"},
	} {
		te := newTestEnv(&fakeCard{serial: 7})
		if code := run(context.Background(), te.env, args); code != 2 {
			t.Errorf("%v: exit %d, want 2 (stderr: %s)", args, code, te.errOut)
		}
		if len(te.secrets.prompts) != 0 {
			t.Errorf("%v: asked for a secret", args)
		}
	}
}

func TestPubkey(t *testing.T) {
	pub := testPub()
	te := newTestEnv(&fakeCard{serial: 40727512, slotPub: &pub})
	if code := run(context.Background(), te.env, []string{"pubkey", "piv://40727512/82"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if got := strings.TrimSpace(te.out.String()); got != b64(pub) {
		t.Errorf("stdout = %q", got)
	}
	if code := run(context.Background(), te.env, []string{"pubkey", "piv://0/82"}); code != 2 {
		t.Errorf("bad keyref: exit %d, want 2", code)
	}
	if code := run(context.Background(), te.env, []string{"pubkey"}); code != 2 {
		t.Errorf("no keyref: exit %d, want 2", code)
	}
}
